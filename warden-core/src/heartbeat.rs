#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

use crate::approval::{ApprovalWorkflow, WorkflowStatus, WorkflowStore};
use crate::Result;

const MAX_CURRENT_STAGE_LEN: usize = 256;
const DEFAULT_MAX_TRACKED_WORKFLOWS: usize = 10_000;
const MIN_HEARTBEAT_INTERVAL_SECS: i64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub max_missed: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(120),
            max_missed: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatDetails {
    pub progress_percent: u8,
    pub current_stage: String,
    pub approvals_collected: u32,
    pub approvals_required: u32,
}

impl HeartbeatDetails {
    pub fn new(
        progress_percent: u8,
        current_stage: impl Into<String>,
        approvals_collected: u32,
        approvals_required: u32,
    ) -> Self {
        let mut stage: String = current_stage.into();
        if stage.len() > MAX_CURRENT_STAGE_LEN {
            stage.truncate(MAX_CURRENT_STAGE_LEN);
        }
        Self {
            progress_percent: progress_percent.min(100),
            current_stage: stage,
            approvals_collected,
            approvals_required,
        }
    }

    pub fn from_workflow(workflow: &ApprovalWorkflow) -> Self {
        let required = workflow.requirement.minimum_approvals();
        let collected = workflow.approval_count();
        let progress = match required {
            0 => 0,
            r => (collected.saturating_mul(100) / r).min(100) as u8,
        };

        Self {
            progress_percent: progress,
            current_stage: format!("{:?}", workflow.status),
            approvals_collected: collected,
            approvals_required: required,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowHeartbeat {
    pub workflow_id: Uuid,
    pub last_heartbeat: DateTime<Utc>,
    pub missed_count: u32,
    pub details: Option<HeartbeatDetails>,
    pub config: HeartbeatConfig,
}

impl WorkflowHeartbeat {
    pub fn new(workflow_id: Uuid, config: HeartbeatConfig) -> Self {
        Self {
            workflow_id,
            last_heartbeat: Utc::now(),
            missed_count: 0,
            details: None,
            config,
        }
    }

    pub fn record(&mut self, details: Option<HeartbeatDetails>) {
        self.last_heartbeat = Utc::now();
        self.missed_count = 0;
        self.details = details;
    }

    pub fn is_stale(&self) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.last_heartbeat)
            .to_std()
            .unwrap_or(Duration::ZERO);
        elapsed > self.config.timeout
    }

    pub fn check_missed(&mut self) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.last_heartbeat)
            .to_std()
            .unwrap_or(Duration::ZERO);

        let interval_secs = self.config.interval.as_secs().max(1);
        self.missed_count = (elapsed.as_secs() / interval_secs) as u32;
        self.missed_count >= self.config.max_missed
    }

    pub fn seconds_until_timeout(&self) -> i64 {
        let elapsed = Utc::now()
            .signed_duration_since(self.last_heartbeat)
            .num_seconds();
        self.config.timeout.as_secs() as i64 - elapsed
    }
}

pub struct HeartbeatTracker {
    heartbeats: RwLock<HashMap<Uuid, WorkflowHeartbeat>>,
    default_config: HeartbeatConfig,
    max_capacity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatError {
    CapacityExceeded { current: usize, max: usize },
    RateLimited,
    NotRegistered,
}

impl HeartbeatTracker {
    pub fn new(default_config: HeartbeatConfig) -> Self {
        Self {
            heartbeats: RwLock::new(HashMap::new()),
            default_config,
            max_capacity: DEFAULT_MAX_TRACKED_WORKFLOWS,
        }
    }

    pub fn with_max_capacity(mut self, max_capacity: usize) -> Self {
        self.max_capacity = max_capacity;
        self
    }

    pub fn register(&self, workflow_id: Uuid) -> std::result::Result<(), HeartbeatError> {
        self.register_with_config(workflow_id, self.default_config.clone())
    }

    pub fn register_with_config(
        &self,
        workflow_id: Uuid,
        config: HeartbeatConfig,
    ) -> std::result::Result<(), HeartbeatError> {
        let mut heartbeats = self.heartbeats.write();
        if heartbeats.contains_key(&workflow_id) {
            return Ok(());
        }
        if heartbeats.len() >= self.max_capacity {
            return Err(HeartbeatError::CapacityExceeded {
                current: heartbeats.len(),
                max: self.max_capacity,
            });
        }
        heartbeats.insert(workflow_id, WorkflowHeartbeat::new(workflow_id, config));
        Ok(())
    }

    pub fn record(
        &self,
        workflow_id: Uuid,
        details: Option<HeartbeatDetails>,
    ) -> std::result::Result<(), HeartbeatError> {
        let mut heartbeats = self.heartbeats.write();
        if let Some(hb) = heartbeats.get_mut(&workflow_id) {
            let now = Utc::now();
            let elapsed = now.signed_duration_since(hb.last_heartbeat).num_seconds();
            if elapsed < MIN_HEARTBEAT_INTERVAL_SECS {
                return Err(HeartbeatError::RateLimited);
            }
            hb.record(details);
            Ok(())
        } else {
            Err(HeartbeatError::NotRegistered)
        }
    }

    pub fn unregister(&self, workflow_id: Uuid) {
        let mut heartbeats = self.heartbeats.write();
        heartbeats.remove(&workflow_id);
    }

    pub fn get(&self, workflow_id: Uuid) -> Option<WorkflowHeartbeat> {
        let heartbeats = self.heartbeats.read();
        heartbeats.get(&workflow_id).cloned()
    }

    pub fn find_stale(&self) -> Vec<Uuid> {
        let heartbeats = self.heartbeats.read();
        heartbeats
            .values()
            .filter(|hb| hb.is_stale())
            .map(|hb| hb.workflow_id)
            .collect()
    }

    pub fn check_all_missed(&self) -> Vec<Uuid> {
        self.heartbeats
            .write()
            .values_mut()
            .filter_map(|hb| hb.check_missed().then_some(hb.workflow_id))
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.heartbeats.read().len()
    }
}

impl Default for HeartbeatTracker {
    fn default() -> Self {
        Self::new(HeartbeatConfig::default())
    }
}

impl std::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityExceeded { current, max } => {
                write!(f, "capacity exceeded: {} of {} slots used", current, max)
            }
            Self::RateLimited => write!(f, "heartbeat rate limited"),
            Self::NotRegistered => write!(f, "workflow not registered"),
        }
    }
}

impl std::error::Error for HeartbeatError {}

pub struct HeartbeatChecker {
    tracker: Arc<HeartbeatTracker>,
    workflow_store: Arc<dyn WorkflowStore>,
    check_interval: Duration,
}

impl HeartbeatChecker {
    pub fn new(tracker: Arc<HeartbeatTracker>, workflow_store: Arc<dyn WorkflowStore>) -> Self {
        Self {
            tracker,
            workflow_store,
            check_interval: Duration::from_secs(30),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    pub async fn check_once(&self) -> Result<Vec<Uuid>> {
        let stale = self.tracker.find_stale();
        let mut timed_out = Vec::new();

        for workflow_id in stale {
            if let Some(mut workflow) = self.workflow_store.get_workflow(&workflow_id).await? {
                if workflow.status != WorkflowStatus::Pending {
                    info!(
                        workflow_id = %workflow_id,
                        status = ?workflow.status,
                        "Skipping stale workflow already transitioned"
                    );
                } else {
                    workflow.status = WorkflowStatus::TimedOut;
                    workflow.rejection_reason = Some("Heartbeat timeout".into());
                    workflow.completed_at = Some(Utc::now());
                    self.workflow_store.update_workflow(workflow).await?;

                    if let Some(updated) = self.workflow_store.get_workflow(&workflow_id).await? {
                        if updated.status == WorkflowStatus::TimedOut {
                            timed_out.push(workflow_id);
                            info!(workflow_id = %workflow_id, "Workflow timed out due to missed heartbeat");
                        } else {
                            warn!(
                                workflow_id = %workflow_id,
                                expected = "TimedOut",
                                actual = ?updated.status,
                                "Workflow status changed after update (possible race)"
                            );
                        }
                    }
                }
            }
            self.tracker.unregister(workflow_id);
        }

        Ok(timed_out)
    }

    pub fn spawn(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            info!("HeartbeatChecker shutting down");
                            break;
                        }
                    }
                    _ = tokio::time::sleep(self.check_interval) => {
                        match self.check_once().await {
                            Ok(timed_out) if !timed_out.is_empty() => {
                                info!(count = timed_out.len(), "Timed out {} workflows due to heartbeat", timed_out.len());
                            }
                            Err(e) => {
                                warn!(error = %e, "Heartbeat check failed");
                            }
                            _ => {}
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{InMemoryWorkflowStore, TransactionDetails};
    use crate::quorum::RequirementNode;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn test_heartbeat_config_default() {
        let config = HeartbeatConfig::default();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert_eq!(config.max_missed, 3);
    }

    #[test]
    fn test_heartbeat_details_clamps_progress() {
        let details = HeartbeatDetails::new(150, "test", 5, 3);
        assert_eq!(details.progress_percent, 100);
    }

    #[test]
    fn test_workflow_heartbeat_record() {
        let config = HeartbeatConfig::default();
        let mut hb = WorkflowHeartbeat::new(Uuid::new_v4(), config);
        hb.missed_count = 2;

        let details = HeartbeatDetails::new(50, "processing", 1, 2);
        hb.record(Some(details.clone()));

        assert_eq!(hb.missed_count, 0);
        assert!(hb.details.is_some());
    }

    #[test]
    fn test_heartbeat_tracker_register_and_record() {
        let tracker = HeartbeatTracker::default();
        let workflow_id = Uuid::new_v4();

        tracker.register(workflow_id).unwrap();
        assert_eq!(tracker.active_count(), 1);

        std::thread::sleep(Duration::from_secs(2));
        let recorded = tracker.record(workflow_id, None);
        assert!(recorded.is_ok());

        let unregistered_id = Uuid::new_v4();
        let not_recorded = tracker.record(unregistered_id, None);
        assert!(matches!(not_recorded, Err(HeartbeatError::NotRegistered)));

        tracker.unregister(workflow_id);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_heartbeat_tracker_find_stale() {
        let config = HeartbeatConfig {
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(20),
            max_missed: 2,
        };
        let tracker = HeartbeatTracker::new(config);
        let workflow_id = Uuid::new_v4();

        tracker.register(workflow_id).unwrap();
        assert!(tracker.find_stale().is_empty());

        std::thread::sleep(Duration::from_millis(50));
        let stale = tracker.find_stale();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], workflow_id);
    }

    #[tokio::test]
    async fn test_heartbeat_checker_times_out_stale_workflow() {
        let workflow_store = Arc::new(InMemoryWorkflowStore::new());
        let config = HeartbeatConfig {
            interval: Duration::from_millis(5),
            timeout: Duration::from_millis(10),
            max_missed: 2,
        };
        let tracker = Arc::new(HeartbeatTracker::new(config));

        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "dest".into(), 1000);
        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            ChronoDuration::hours(24),
        );
        let workflow_id = workflow.id;
        workflow_store.create_workflow(workflow).await.unwrap();

        tracker.register(workflow_id).unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let checker = HeartbeatChecker::new(Arc::clone(&tracker), workflow_store.clone());
        let timed_out = checker.check_once().await.unwrap();

        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], workflow_id);

        let workflow = workflow_store
            .get_workflow(&workflow_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(workflow.status, WorkflowStatus::TimedOut);
        assert_eq!(workflow.rejection_reason, Some("Heartbeat timeout".into()));
    }

    #[test]
    fn test_heartbeat_details_from_workflow() {
        let requirement = RequirementNode::threshold(3, "treasury");
        let tx_details = TransactionDetails::new("wallet1".into(), "dest".into(), 1000);
        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            tx_details,
            ChronoDuration::hours(24),
        );

        workflow.add_approval(crate::approval::Approval::new(
            "alice".into(),
            "treasury".into(),
            crate::approval::ApprovalDecision::Approve,
            0,
        ));

        let details = HeartbeatDetails::from_workflow(&workflow);
        assert_eq!(details.approvals_collected, 1);
        assert_eq!(details.approvals_required, 3);
        assert_eq!(details.progress_percent, 33);
    }

    #[test]
    fn test_heartbeat_details_truncates_long_stage() {
        let long_stage = "x".repeat(500);
        let details = HeartbeatDetails::new(50, long_stage, 1, 2);
        assert_eq!(details.current_stage.len(), MAX_CURRENT_STAGE_LEN);
    }

    #[test]
    fn test_heartbeat_tracker_capacity_limit() {
        let tracker = HeartbeatTracker::new(HeartbeatConfig::default()).with_max_capacity(2);

        tracker.register(Uuid::new_v4()).unwrap();
        tracker.register(Uuid::new_v4()).unwrap();

        let result = tracker.register(Uuid::new_v4());
        assert!(matches!(
            result,
            Err(HeartbeatError::CapacityExceeded { current: 2, max: 2 })
        ));
    }

    #[test]
    fn test_heartbeat_tracker_rate_limiting() {
        let tracker = HeartbeatTracker::default();
        let workflow_id = Uuid::new_v4();

        tracker.register(workflow_id).unwrap();

        let result = tracker.record(workflow_id, None);
        assert!(matches!(result, Err(HeartbeatError::RateLimited)));
    }

    #[test]
    fn test_heartbeat_tracker_allows_reregistration() {
        let tracker = HeartbeatTracker::new(HeartbeatConfig::default()).with_max_capacity(1);
        let workflow_id = Uuid::new_v4();

        tracker.register(workflow_id).unwrap();
        let result = tracker.register(workflow_id);
        assert!(result.is_ok());
        assert_eq!(tracker.active_count(), 1);
    }
}
