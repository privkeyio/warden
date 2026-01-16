#![forbid(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::policy::ApprovalConfig;
use crate::quorum::{GroupId, QuorumEvaluator, QuorumStatus, RequirementNode};
use crate::risk::RiskLevel;
use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirements {
    pub initial: ApprovalStage,
    pub degradation: Vec<DegradationStage>,
}

impl ApprovalRequirements {
    pub fn simple(quorum: u32, roles: Vec<String>) -> Self {
        Self {
            initial: ApprovalStage {
                roles,
                required: quorum,
            },
            degradation: vec![],
        }
    }

    pub fn with_degradation(
        initial_quorum: u32,
        initial_roles: Vec<String>,
        degradation: Vec<DegradationStage>,
    ) -> Self {
        Self {
            initial: ApprovalStage {
                roles: initial_roles,
                required: initial_quorum,
            },
            degradation,
        }
    }

    pub fn for_risk_level(level: RiskLevel) -> Option<Self> {
        match level {
            RiskLevel::Low => None,
            RiskLevel::Medium => Some(Self {
                initial: ApprovalStage {
                    roles: vec!["treasury".into(), "cfo".into()],
                    required: 2,
                },
                degradation: vec![DegradationStage {
                    after: Duration::hours(4),
                    roles: vec!["cfo".into()],
                    required: 1,
                }],
            }),
            RiskLevel::High | RiskLevel::Critical => Some(Self {
                initial: ApprovalStage {
                    roles: vec!["treasury".into(), "cfo".into(), "ceo".into()],
                    required: 3,
                },
                degradation: vec![
                    DegradationStage {
                        after: Duration::hours(4),
                        roles: vec!["cfo".into(), "ceo".into()],
                        required: 2,
                    },
                    DegradationStage {
                        after: Duration::hours(24),
                        roles: vec!["ceo".into()],
                        required: 1,
                    },
                ],
            }),
        }
    }

    pub fn current_stage(&self, created_at: DateTime<Utc>) -> CurrentStage {
        let elapsed = Utc::now() - created_at;

        for (i, stage) in self.degradation.iter().enumerate() {
            if elapsed < stage.after {
                if i == 0 {
                    return CurrentStage {
                        index: 0,
                        roles: self.initial.roles.clone(),
                        required: self.initial.required,
                        is_degraded: false,
                    };
                } else {
                    let prev = &self.degradation[i - 1];
                    return CurrentStage {
                        index: i as u32,
                        roles: prev.roles.clone(),
                        required: prev.required,
                        is_degraded: true,
                    };
                }
            }
        }

        if let Some(last) = self.degradation.last() {
            CurrentStage {
                index: self.degradation.len() as u32,
                roles: last.roles.clone(),
                required: last.required,
                is_degraded: true,
            }
        } else {
            CurrentStage {
                index: 0,
                roles: self.initial.roles.clone(),
                required: self.initial.required,
                is_degraded: false,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStage {
    pub roles: Vec<String>,
    pub required: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationStage {
    #[serde(with = "duration_serde")]
    pub after: Duration,
    pub roles: Vec<String>,
    pub required: u32,
}

#[derive(Debug, Clone)]
pub struct CurrentStage {
    pub index: u32,
    pub roles: Vec<String>,
    pub required: u32,
    pub is_degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub policy_id: Uuid,
    pub status: ApprovalStatus,
    pub requirements: ApprovalRequirements,
    pub approvals: Vec<Approval>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ApprovalRequest {
    pub fn new(
        transaction_id: Uuid,
        policy_id: Uuid,
        requirements: ApprovalRequirements,
        expires_in: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            transaction_id,
            policy_id,
            status: ApprovalStatus::Pending,
            requirements,
            approvals: vec![],
            created_at: now,
            expires_at: now + expires_in,
        }
    }

    pub fn current_stage(&self) -> CurrentStage {
        self.requirements.current_stage(self.created_at)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn approval_count(&self) -> u32 {
        self.approvals
            .iter()
            .filter(|a| a.decision == ApprovalDecision::Approve)
            .count() as u32
    }

    pub fn can_approve(&self, user_id: &str, user_roles: &[String]) -> bool {
        if self.status != ApprovalStatus::Pending {
            return false;
        }

        if self.is_expired() {
            return false;
        }

        if self.approvals.iter().any(|a| a.approver_id == user_id) {
            return false;
        }

        let stage = self.current_stage();
        user_roles.iter().any(|r| stage.roles.contains(r))
    }

    pub fn add_approval(&mut self, approval: Approval) -> ApprovalStatus {
        self.approvals.push(approval.clone());

        if approval.decision == ApprovalDecision::Reject {
            self.status = ApprovalStatus::Rejected;
            return self.status.clone();
        }

        let stage = self.current_stage();
        if self.approval_count() >= stage.required {
            self.status = ApprovalStatus::Approved;
        }

        self.status.clone()
    }

    pub fn check_expiration(&mut self) -> bool {
        if self.is_expired() && self.status == ApprovalStatus::Pending {
            self.status = ApprovalStatus::Expired;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: Uuid,
    pub approver_id: String,
    pub approver_role: String,
    pub decision: ApprovalDecision,
    pub comment: Option<String>,
    pub signature: Option<String>,
    pub degradation_stage: u32,
    pub created_at: DateTime<Utc>,
}

impl Approval {
    pub fn new(
        approver_id: String,
        approver_role: String,
        decision: ApprovalDecision,
        stage: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            approver_id,
            approver_role,
            decision,
            comment: None,
            signature: None,
            degradation_stage: stage,
            created_at: Utc::now(),
        }
    }

    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn with_signature(mut self, signature: String) -> Self {
        self.signature = Some(signature);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowStatus {
    Pending,
    Approved,
    Rejected,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWorkflow {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub policy_id: Uuid,
    pub rule_id: String,
    pub requester_id: Option<String>,
    pub status: WorkflowStatus,
    pub requirement: RequirementNode,
    pub approvals: Vec<Approval>,
    pub rejected_by: Option<String>,
    pub rejection_reason: Option<String>,
    pub transaction_details: TransactionDetails,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl ApprovalWorkflow {
    pub fn new(
        transaction_id: Uuid,
        policy_id: Uuid,
        rule_id: String,
        requester_id: Option<String>,
        requirement: RequirementNode,
        transaction_details: TransactionDetails,
        timeout: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            transaction_id,
            policy_id,
            rule_id,
            requester_id,
            status: WorkflowStatus::Pending,
            requirement,
            approvals: Vec::new(),
            rejected_by: None,
            rejection_reason: None,
            transaction_details,
            created_at: now,
            expires_at: now + timeout,
            completed_at: None,
        }
    }

    pub fn from_config(
        transaction_id: Uuid,
        policy_id: Uuid,
        rule_id: String,
        requester_id: Option<String>,
        config: &ApprovalConfig,
        transaction_details: TransactionDetails,
    ) -> Self {
        let requirement = if config.from_groups.len() == 1 {
            RequirementNode::threshold(config.quorum, config.from_groups[0].clone())
        } else {
            let group_requirements: Vec<RequirementNode> = config
                .from_groups
                .iter()
                .map(|g| RequirementNode::threshold(config.quorum, g.clone()))
                .collect();
            RequirementNode::any(group_requirements)
        };
        let timeout = Duration::hours(config.timeout_hours as i64);
        Self::new(
            transaction_id,
            policy_id,
            rule_id,
            requester_id,
            requirement,
            transaction_details,
            timeout,
        )
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_pending(&self) -> bool {
        self.status == WorkflowStatus::Pending
    }

    pub fn can_approve(&self, approver_id: &str, approver_groups: &[GroupId]) -> bool {
        if !self.is_pending() || self.is_expired() {
            return false;
        }
        if let Some(ref requester) = self.requester_id {
            if requester == approver_id {
                return false;
            }
        }
        if self.approvals.iter().any(|a| a.approver_id == approver_id) {
            return false;
        }
        let required_groups = self.requirement.all_groups();
        approver_groups.iter().any(|g| required_groups.contains(g))
    }

    pub fn add_approval(&mut self, approval: Approval) -> WorkflowStatus {
        if !self.is_pending() {
            return self.status;
        }

        if self
            .approvals
            .iter()
            .any(|a| a.approver_id == approval.approver_id)
        {
            return self.status;
        }

        if let Some(ref requester) = self.requester_id {
            if requester == &approval.approver_id {
                return self.status;
            }
        }

        if approval.decision == ApprovalDecision::Reject {
            self.status = WorkflowStatus::Rejected;
            self.rejected_by = Some(approval.approver_id.clone());
            self.rejection_reason = approval.comment.clone();
            self.completed_at = Some(Utc::now());
            self.approvals.push(approval);
            return self.status;
        }

        self.approvals.push(approval);

        let evaluator = QuorumEvaluator::new();
        if evaluator
            .evaluate(&self.requirement, &self.approvals)
            .is_satisfied()
        {
            self.status = WorkflowStatus::Approved;
            self.completed_at = Some(Utc::now());
        }

        self.status
    }

    pub fn check_expiration(&mut self) -> bool {
        if self.is_expired() && self.is_pending() {
            self.status = WorkflowStatus::TimedOut;
            self.rejection_reason = Some("Approval timeout".into());
            self.completed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    pub fn cancel(&mut self, reason: Option<String>) {
        if self.is_pending() {
            self.status = WorkflowStatus::Cancelled;
            self.rejection_reason = reason;
            self.completed_at = Some(Utc::now());
        }
    }

    pub fn quorum_status(&self) -> QuorumStatus {
        QuorumEvaluator::new().evaluate(&self.requirement, &self.approvals)
    }

    pub fn approval_count(&self) -> u32 {
        self.approvals
            .iter()
            .filter(|a| a.decision == ApprovalDecision::Approve)
            .count() as u32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetails {
    pub source_wallet: String,
    pub destination: String,
    pub amount_sats: u64,
    pub memo: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TransactionDetails {
    pub fn new(source_wallet: String, destination: String, amount_sats: u64) -> Self {
        Self {
            source_wallet,
            destination,
            amount_sats,
            memo: None,
            metadata: HashMap::new(),
        }
    }

    pub fn amount_btc(&self) -> f64 {
        self.amount_sats as f64 / 100_000_000.0
    }
}

#[async_trait]
pub trait ApprovalStore: Send + Sync {
    async fn create(&self, request: ApprovalRequest) -> Result<ApprovalRequest>;
    async fn get(&self, id: &Uuid) -> Result<Option<ApprovalRequest>>;
    async fn get_by_transaction(&self, transaction_id: &Uuid) -> Result<Option<ApprovalRequest>>;
    async fn update(&self, request: ApprovalRequest) -> Result<ApprovalRequest>;
    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>>;
}

#[async_trait]
pub trait WorkflowStore: Send + Sync {
    async fn create_workflow(&self, workflow: ApprovalWorkflow) -> Result<ApprovalWorkflow>;
    async fn get_workflow(&self, id: &Uuid) -> Result<Option<ApprovalWorkflow>>;
    async fn get_workflow_by_transaction(
        &self,
        transaction_id: &Uuid,
    ) -> Result<Option<ApprovalWorkflow>>;
    async fn update_workflow(&self, workflow: ApprovalWorkflow) -> Result<ApprovalWorkflow>;
    async fn list_pending_workflows(&self) -> Result<Vec<ApprovalWorkflow>>;
    async fn list_pending_for_approver(
        &self,
        approver_id: &str,
        groups: &[GroupId],
    ) -> Result<Vec<ApprovalWorkflow>>;
    async fn add_approval_to_workflow(
        &self,
        workflow_id: &Uuid,
        approval: Approval,
    ) -> Result<ApprovalWorkflow>;
}

pub struct InMemoryApprovalStore {
    requests: RwLock<HashMap<Uuid, ApprovalRequest>>,
}

impl InMemoryApprovalStore {
    pub fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryApprovalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalStore for InMemoryApprovalStore {
    async fn create(&self, request: ApprovalRequest) -> Result<ApprovalRequest> {
        let mut requests = self.requests.write();
        requests.insert(request.id, request.clone());
        Ok(request)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<ApprovalRequest>> {
        let requests = self.requests.read();
        Ok(requests.get(id).cloned())
    }

    async fn get_by_transaction(&self, transaction_id: &Uuid) -> Result<Option<ApprovalRequest>> {
        let requests = self.requests.read();
        Ok(requests
            .values()
            .find(|r| &r.transaction_id == transaction_id)
            .cloned())
    }

    async fn update(&self, request: ApprovalRequest) -> Result<ApprovalRequest> {
        let mut requests = self.requests.write();
        requests.insert(request.id, request.clone());
        Ok(request)
    }

    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>> {
        let requests = self.requests.read();
        Ok(requests
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .cloned()
            .collect())
    }
}

pub struct InMemoryWorkflowStore {
    workflows: RwLock<HashMap<Uuid, ApprovalWorkflow>>,
}

impl InMemoryWorkflowStore {
    pub fn new() -> Self {
        Self {
            workflows: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWorkflowStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WorkflowStore for InMemoryWorkflowStore {
    async fn create_workflow(&self, workflow: ApprovalWorkflow) -> Result<ApprovalWorkflow> {
        let mut workflows = self.workflows.write();
        workflows.insert(workflow.id, workflow.clone());
        Ok(workflow)
    }

    async fn get_workflow(&self, id: &Uuid) -> Result<Option<ApprovalWorkflow>> {
        let workflows = self.workflows.read();
        Ok(workflows.get(id).cloned())
    }

    async fn get_workflow_by_transaction(
        &self,
        transaction_id: &Uuid,
    ) -> Result<Option<ApprovalWorkflow>> {
        let workflows = self.workflows.read();
        Ok(workflows
            .values()
            .find(|w| &w.transaction_id == transaction_id)
            .cloned())
    }

    async fn update_workflow(&self, workflow: ApprovalWorkflow) -> Result<ApprovalWorkflow> {
        let mut workflows = self.workflows.write();
        workflows.insert(workflow.id, workflow.clone());
        Ok(workflow)
    }

    async fn list_pending_workflows(&self) -> Result<Vec<ApprovalWorkflow>> {
        let workflows = self.workflows.read();
        Ok(workflows
            .values()
            .filter(|w| w.status == WorkflowStatus::Pending)
            .cloned()
            .collect())
    }

    async fn list_pending_for_approver(
        &self,
        approver_id: &str,
        groups: &[GroupId],
    ) -> Result<Vec<ApprovalWorkflow>> {
        let workflows = self.workflows.read();
        Ok(workflows
            .values()
            .filter(|w| w.can_approve(approver_id, groups))
            .cloned()
            .collect())
    }

    async fn add_approval_to_workflow(
        &self,
        workflow_id: &Uuid,
        approval: Approval,
    ) -> Result<ApprovalWorkflow> {
        let mut workflows = self.workflows.write();
        if let Some(workflow) = workflows.get_mut(workflow_id) {
            workflow.add_approval(approval);
            Ok(workflow.clone())
        } else {
            Err(crate::Error::Storage(format!(
                "workflow not found: {}",
                workflow_id
            )))
        }
    }
}

mod duration_serde {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.num_seconds().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = i64::deserialize(deserializer)?;
        Ok(Duration::seconds(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_approval() {
        let reqs = ApprovalRequirements::simple(2, vec!["admin".into()]);
        let mut request =
            ApprovalRequest::new(Uuid::new_v4(), Uuid::new_v4(), reqs, Duration::hours(24));

        assert!(request.can_approve("user1", &["admin".into()]));
        assert!(!request.can_approve("user1", &["viewer".into()]));

        let approval1 = Approval::new("user1".into(), "admin".into(), ApprovalDecision::Approve, 0);
        request.add_approval(approval1);
        assert_eq!(request.status, ApprovalStatus::Pending);

        let approval2 = Approval::new("user2".into(), "admin".into(), ApprovalDecision::Approve, 0);
        request.add_approval(approval2);
        assert_eq!(request.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_degradation() {
        let reqs = ApprovalRequirements {
            initial: ApprovalStage {
                roles: vec!["treasury".into(), "cfo".into(), "ceo".into()],
                required: 3,
            },
            degradation: vec![
                DegradationStage {
                    after: Duration::hours(4),
                    roles: vec!["cfo".into(), "ceo".into()],
                    required: 2,
                },
                DegradationStage {
                    after: Duration::hours(24),
                    roles: vec!["ceo".into()],
                    required: 1,
                },
            ],
        };

        let stage = reqs.current_stage(Utc::now());
        assert_eq!(stage.required, 3);
        assert!(!stage.is_degraded);

        let five_hours_ago = Utc::now() - Duration::hours(5);
        let stage = reqs.current_stage(five_hours_ago);
        assert_eq!(stage.required, 2);
        assert!(stage.is_degraded);

        let two_days_ago = Utc::now() - Duration::days(2);
        let stage = reqs.current_stage(two_days_ago);
        assert_eq!(stage.required, 1);
        assert!(stage.is_degraded);
    }

    #[test]
    fn test_rejection() {
        let reqs = ApprovalRequirements::simple(2, vec!["admin".into()]);
        let mut request =
            ApprovalRequest::new(Uuid::new_v4(), Uuid::new_v4(), reqs, Duration::hours(24));

        let rejection = Approval::new("user1".into(), "admin".into(), ApprovalDecision::Reject, 0);
        request.add_approval(rejection);
        assert_eq!(request.status, ApprovalStatus::Rejected);
    }

    #[test]
    fn test_no_self_approve() {
        let reqs = ApprovalRequirements::simple(2, vec!["admin".into()]);
        let mut request =
            ApprovalRequest::new(Uuid::new_v4(), Uuid::new_v4(), reqs, Duration::hours(24));

        let approval1 = Approval::new("user1".into(), "admin".into(), ApprovalDecision::Approve, 0);
        request.add_approval(approval1);

        assert!(!request.can_approve("user1", &["admin".into()]));
        assert!(request.can_approve("user2", &["admin".into()]));
    }

    #[test]
    fn test_workflow_requester_cannot_approve() {
        use crate::quorum::RequirementNode;

        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1destination".into(), 1_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            Some("alice".into()),
            requirement,
            details,
            Duration::hours(24),
        );

        assert!(!workflow.can_approve("alice", &["treasury".into()]));
        assert!(workflow.can_approve("bob", &["treasury".into()]));
        assert!(!workflow.can_approve("bob", &["finance".into()]));
    }

    #[test]
    fn test_workflow_no_requester_allows_anyone() {
        use crate::quorum::RequirementNode;

        let requirement = RequirementNode::threshold(1, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1destination".into(), 1_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        assert!(workflow.can_approve("alice", &["treasury".into()]));
        assert!(workflow.can_approve("bob", &["treasury".into()]));
    }

    #[test]
    fn test_multi_group_quorum_met_in_single_group() {
        use crate::policy::ApprovalConfig;

        let config = ApprovalConfig {
            quorum: 2,
            from_groups: vec!["treasury".into(), "executives".into()],
            timeout_hours: 24,
        };
        let details = TransactionDetails::new("wallet1".into(), "dest".into(), 1_000_000);

        let mut workflow = ApprovalWorkflow::from_config(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            &config,
            details,
        );

        workflow.add_approval(Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        ));
        assert_eq!(workflow.status, WorkflowStatus::Pending);

        workflow.add_approval(Approval::new(
            "bob".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        ));
        assert_eq!(workflow.status, WorkflowStatus::Approved);
    }

    #[test]
    fn test_multi_group_mixed_approvals_not_satisfied() {
        use crate::policy::ApprovalConfig;

        let config = ApprovalConfig {
            quorum: 2,
            from_groups: vec!["treasury".into(), "executives".into()],
            timeout_hours: 24,
        };
        let details = TransactionDetails::new("wallet1".into(), "dest".into(), 1_000_000);

        let mut workflow = ApprovalWorkflow::from_config(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            &config,
            details,
        );

        workflow.add_approval(Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        ));
        workflow.add_approval(Approval::new(
            "charlie".into(),
            "executives".into(),
            ApprovalDecision::Approve,
            0,
        ));

        assert_eq!(workflow.status, WorkflowStatus::Pending);
    }

    #[test]
    fn test_multi_group_second_group_satisfies() {
        use crate::policy::ApprovalConfig;

        let config = ApprovalConfig {
            quorum: 2,
            from_groups: vec!["treasury".into(), "executives".into()],
            timeout_hours: 24,
        };
        let details = TransactionDetails::new("wallet1".into(), "dest".into(), 1_000_000);

        let mut workflow = ApprovalWorkflow::from_config(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            &config,
            details,
        );

        workflow.add_approval(Approval::new(
            "charlie".into(),
            "executives".into(),
            ApprovalDecision::Approve,
            0,
        ));
        workflow.add_approval(Approval::new(
            "diana".into(),
            "executives".into(),
            ApprovalDecision::Approve,
            0,
        ));

        assert_eq!(workflow.status, WorkflowStatus::Approved);
    }
}
