#![forbid(unsafe_code)]

use crate::error::Result;
use crate::notification::NotificationSender;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub name: String,
    pub stages: Vec<EscalationStage>,
    pub final_action: FinalAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStage {
    pub stage: u32,
    pub duration_hours: u32,
    pub actions: Vec<EscalationAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EscalationAction {
    Reminder {
        channels: Vec<String>,
        message: String,
    },
    Escalate {
        to_groups: Vec<String>,
        add_to_approvers: bool,
    },
    Alert {
        channels: Vec<String>,
        severity: AlertSeverity,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FinalAction {
    AutoReject {
        reason: String,
    },
    AutoApprove {
        reason: String,
    },
    Notify {
        channels: Vec<String>,
        message: String,
    },
}

impl Default for EscalationPolicy {
    fn default() -> Self {
        Self {
            name: "default-escalation".into(),
            stages: vec![
                EscalationStage {
                    stage: 1,
                    duration_hours: 4,
                    actions: vec![EscalationAction::Reminder {
                        channels: vec!["email".into(), "slack".into()],
                        message: "Approval pending for {transaction_id}".into(),
                    }],
                },
                EscalationStage {
                    stage: 2,
                    duration_hours: 8,
                    actions: vec![
                        EscalationAction::Reminder {
                            channels: vec!["email".into(), "slack".into(), "sms".into()],
                            message: "URGENT: Approval needed for {transaction_id}".into(),
                        },
                        EscalationAction::Escalate {
                            to_groups: vec!["managers".into()],
                            add_to_approvers: true,
                        },
                    ],
                },
                EscalationStage {
                    stage: 3,
                    duration_hours: 24,
                    actions: vec![
                        EscalationAction::Escalate {
                            to_groups: vec!["executives".into()],
                            add_to_approvers: true,
                        },
                        EscalationAction::Alert {
                            channels: vec!["pagerduty".into()],
                            severity: AlertSeverity::High,
                        },
                    ],
                },
            ],
            final_action: FinalAction::AutoReject {
                reason: "Approval timeout after escalation".into(),
            },
        }
    }
}

#[async_trait::async_trait]
pub trait EscalationPolicyStore: Send + Sync {
    async fn get(&self, policy_id: &str) -> Result<EscalationPolicy>;
    async fn list(&self) -> Result<Vec<EscalationPolicy>>;
    async fn create(&self, policy: EscalationPolicy) -> Result<()>;
    async fn update(&self, policy: EscalationPolicy) -> Result<()>;
    async fn delete(&self, policy_id: &str) -> Result<()>;
}

#[async_trait::async_trait]
pub trait WorkflowClient: Send + Sync {
    async fn list_pending_workflows(&self) -> Result<Vec<PendingWorkflow>>;
    async fn add_approver_groups(&self, workflow_id: &str, groups: &[String]) -> Result<()>;
    async fn update_escalation_stage(&self, workflow_id: &str, stage: u32) -> Result<()>;
    async fn reject_workflow(&self, workflow_id: &str, reason: &str) -> Result<()>;
    async fn approve_workflow(&self, workflow_id: &str, reason: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct PendingWorkflow {
    pub id: String,
    pub transaction_id: String,
    pub created_at: DateTime<Utc>,
    pub escalation_policy_id: String,
    pub escalation_stage: u32,
    pub approvers: Vec<String>,
}

pub struct EscalationManager<P: EscalationPolicyStore, W: WorkflowClient, N: NotificationSender> {
    policy_store: P,
    workflow_client: W,
    _notification_sender: std::marker::PhantomData<N>,
}

impl<P: EscalationPolicyStore, W: WorkflowClient, N: NotificationSender>
    EscalationManager<P, W, N>
{
    pub fn new(policy_store: P, workflow_client: W) -> Self {
        Self {
            policy_store,
            workflow_client,
            _notification_sender: std::marker::PhantomData,
        }
    }

    pub async fn process_escalations(&self) -> Result<EscalationResults> {
        let pending = self.workflow_client.list_pending_workflows().await?;
        let mut results = EscalationResults::default();

        for workflow in pending {
            match self.process_workflow(&workflow).await {
                Ok(action) => {
                    if action != EscalationOutcome::NoAction {
                        results.processed += 1;
                    }
                    match action {
                        EscalationOutcome::Escalated { stage } => {
                            results.escalated.push((workflow.id.clone(), stage));
                        }
                        EscalationOutcome::FinalActionTaken => {
                            results.finalized.push(workflow.id.clone());
                        }
                        EscalationOutcome::NoAction => {}
                    }
                }
                Err(e) => {
                    results.errors.push((workflow.id.clone(), e.to_string()));
                }
            }
        }

        Ok(results)
    }

    async fn process_workflow(&self, workflow: &PendingWorkflow) -> Result<EscalationOutcome> {
        let policy = self
            .policy_store
            .get(&workflow.escalation_policy_id)
            .await?;
        let elapsed = Utc::now() - workflow.created_at;

        let current_stage = self.determine_stage(&policy, elapsed);

        if current_stage > workflow.escalation_stage {
            self.execute_escalation(workflow, &policy, current_stage)
                .await?;
            return Ok(EscalationOutcome::Escalated {
                stage: current_stage,
            });
        }

        let total_hours: u32 = policy.stages.iter().map(|s| s.duration_hours).sum();
        if elapsed > Duration::hours(total_hours as i64) {
            self.execute_final_action(workflow, &policy).await?;
            return Ok(EscalationOutcome::FinalActionTaken);
        }

        Ok(EscalationOutcome::NoAction)
    }

    fn determine_stage(&self, policy: &EscalationPolicy, elapsed: Duration) -> u32 {
        let mut total_hours = 0;
        for stage in &policy.stages {
            total_hours += stage.duration_hours;
            if elapsed <= Duration::hours(total_hours as i64) {
                return stage.stage;
            }
        }
        policy.stages.last().map(|s| s.stage).unwrap_or(0) + 1
    }

    async fn execute_escalation(
        &self,
        workflow: &PendingWorkflow,
        policy: &EscalationPolicy,
        stage: u32,
    ) -> Result<()> {
        let stage_config = policy
            .stages
            .iter()
            .find(|s| s.stage == stage)
            .ok_or_else(|| crate::error::Error::NotFound(format!("Stage {} not found", stage)))?;

        for action in &stage_config.actions {
            match action {
                EscalationAction::Reminder { channels, message } => {
                    let formatted_message =
                        message.replace("{transaction_id}", &workflow.transaction_id);
                    tracing::warn!(
                        workflow_id = %workflow.id,
                        channels = ?channels,
                        message = %formatted_message,
                        "TODO: Reminder notification not yet implemented - message logged for debugging"
                    );
                }
                EscalationAction::Escalate {
                    to_groups,
                    add_to_approvers,
                } => {
                    if *add_to_approvers {
                        self.workflow_client
                            .add_approver_groups(&workflow.id, to_groups)
                            .await?;
                    }
                    tracing::info!(
                        workflow_id = %workflow.id,
                        groups = ?to_groups,
                        "Escalating to additional groups"
                    );
                }
                EscalationAction::Alert { channels, severity } => {
                    tracing::warn!(
                        workflow_id = %workflow.id,
                        channels = ?channels,
                        severity = ?severity,
                        "Sending escalation alert"
                    );
                }
            }
        }

        self.workflow_client
            .update_escalation_stage(&workflow.id, stage)
            .await?;

        Ok(())
    }

    async fn execute_final_action(
        &self,
        workflow: &PendingWorkflow,
        policy: &EscalationPolicy,
    ) -> Result<()> {
        match &policy.final_action {
            FinalAction::AutoReject { reason } => {
                self.workflow_client
                    .reject_workflow(&workflow.id, reason)
                    .await?;
                tracing::info!(
                    workflow_id = %workflow.id,
                    reason = %reason,
                    "Auto-rejected workflow due to escalation timeout"
                );
            }
            FinalAction::AutoApprove { reason } => {
                self.workflow_client
                    .approve_workflow(&workflow.id, reason)
                    .await?;
                tracing::info!(
                    workflow_id = %workflow.id,
                    reason = %reason,
                    "Auto-approved workflow due to escalation timeout"
                );
            }
            FinalAction::Notify { channels, message } => {
                let formatted_message =
                    message.replace("{transaction_id}", &workflow.transaction_id);
                tracing::info!(
                    workflow_id = %workflow.id,
                    channels = ?channels,
                    message = %formatted_message,
                    "Sending final escalation notification"
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationOutcome {
    NoAction,
    Escalated { stage: u32 },
    FinalActionTaken,
}

#[derive(Debug, Clone, Default)]
pub struct EscalationResults {
    pub processed: usize,
    pub escalated: Vec<(String, u32)>,
    pub finalized: Vec<String>,
    pub errors: Vec<(String, String)>,
}

pub struct InMemoryEscalationPolicyStore {
    policies: tokio::sync::RwLock<std::collections::HashMap<String, EscalationPolicy>>,
}

impl InMemoryEscalationPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InMemoryEscalationPolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_policy(policy: &EscalationPolicy) -> Result<()> {
    if policy.stages.is_empty() {
        return Err(crate::error::Error::InvalidInput(
            "Escalation policy must have at least one stage".into(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl EscalationPolicyStore for InMemoryEscalationPolicyStore {
    async fn get(&self, policy_id: &str) -> Result<EscalationPolicy> {
        self.policies
            .read()
            .await
            .get(policy_id)
            .cloned()
            .ok_or_else(|| crate::error::Error::NotFound(format!("Policy {} not found", policy_id)))
    }

    async fn list(&self) -> Result<Vec<EscalationPolicy>> {
        Ok(self.policies.read().await.values().cloned().collect())
    }

    async fn create(&self, policy: EscalationPolicy) -> Result<()> {
        validate_policy(&policy)?;
        self.policies
            .write()
            .await
            .insert(policy.name.clone(), policy);
        Ok(())
    }

    async fn update(&self, policy: EscalationPolicy) -> Result<()> {
        validate_policy(&policy)?;
        self.policies
            .write()
            .await
            .insert(policy.name.clone(), policy);
        Ok(())
    }

    async fn delete(&self, policy_id: &str) -> Result<()> {
        self.policies.write().await.remove(policy_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_escalation_policy() {
        let policy = EscalationPolicy::default();
        assert_eq!(policy.stages.len(), 3);
        assert_eq!(policy.stages[0].duration_hours, 4);
        assert_eq!(policy.stages[1].duration_hours, 8);
        assert_eq!(policy.stages[2].duration_hours, 24);
    }

    #[test]
    fn test_escalation_policy_serialization() {
        let policy = EscalationPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: EscalationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, policy.name);
        assert_eq!(parsed.stages.len(), policy.stages.len());
    }

    #[test]
    fn test_alert_severity_serialization() {
        let high = AlertSeverity::High;
        let json = serde_json::to_string(&high).unwrap();
        assert_eq!(json, "\"high\"");
    }
}
