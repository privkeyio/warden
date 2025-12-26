#![forbid(unsafe_code)]

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::approval::{ApprovalWorkflow, TransactionDetails, WorkflowStatus, WorkflowStore};
use crate::backend::{
    BackendRegistry, SigningMetadata, SigningPayload, SigningRequest, SigningSession,
};
use crate::notification::{
    ApprovalSummary, Notification, NotificationService, WorkflowCompleteNotification,
};
use crate::{Error, Result};

#[async_trait]
pub trait CompletionCallback: Send + Sync {
    async fn on_workflow_approved(&self, workflow: &ApprovalWorkflow) -> Result<()>;
    async fn on_workflow_rejected(&self, workflow: &ApprovalWorkflow) -> Result<()>;
    async fn on_signing_initiated(&self, workflow_id: Uuid, session: &SigningSession)
        -> Result<()>;
    async fn on_signing_completed(&self, workflow_id: Uuid, session: &SigningSession)
        -> Result<()>;
    async fn on_signing_failed(&self, workflow_id: Uuid, reason: &str) -> Result<()>;
}

pub struct WorkflowCompletionHandler {
    workflow_store: Arc<dyn WorkflowStore>,
    backend_registry: Arc<BackendRegistry>,
    notification_service: Option<Arc<NotificationService>>,
    callbacks: Vec<Arc<dyn CompletionCallback>>,
}

impl WorkflowCompletionHandler {
    pub fn new(
        workflow_store: Arc<dyn WorkflowStore>,
        backend_registry: Arc<BackendRegistry>,
    ) -> Self {
        Self {
            workflow_store,
            backend_registry,
            notification_service: None,
            callbacks: Vec::new(),
        }
    }

    pub fn with_notification_service(mut self, service: Arc<NotificationService>) -> Self {
        self.notification_service = Some(service);
        self
    }

    pub fn add_callback(&mut self, callback: Arc<dyn CompletionCallback>) {
        self.callbacks.push(callback);
    }

    pub async fn process_workflow_completion(
        &self,
        workflow_id: Uuid,
    ) -> Result<Option<SigningSession>> {
        let workflow = self
            .workflow_store
            .get_workflow(&workflow_id)
            .await?
            .ok_or_else(|| Error::WorkflowNotFound(workflow_id.to_string()))?;

        match workflow.status {
            WorkflowStatus::Approved => {
                info!(
                    workflow_id = %workflow_id,
                    transaction_id = %workflow.transaction_id,
                    "Processing approved workflow, initiating signing"
                );

                for callback in &self.callbacks {
                    if let Err(e) = callback.on_workflow_approved(&workflow).await {
                        warn!(error = %e, "Callback failed on workflow_approved");
                    }
                }

                let signing_result = self.initiate_signing(&workflow).await;

                match &signing_result {
                    Ok(session) => {
                        info!(
                            session_id = %session.session_id,
                            "Signing session initiated"
                        );
                        for callback in &self.callbacks {
                            if let Err(e) =
                                callback.on_signing_initiated(workflow_id, session).await
                            {
                                warn!(error = %e, "Callback failed on signing_initiated");
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to initiate signing");
                        for callback in &self.callbacks {
                            if let Err(ce) = callback
                                .on_signing_failed(workflow_id, &e.to_string())
                                .await
                            {
                                warn!(error = %ce, "Callback failed on signing_failed");
                            }
                        }
                    }
                }

                self.send_completion_notification(&workflow).await;
                signing_result.map(Some)
            }
            WorkflowStatus::Rejected => {
                info!(
                    workflow_id = %workflow_id,
                    rejected_by = ?workflow.rejected_by,
                    reason = ?workflow.rejection_reason,
                    "Processing rejected workflow"
                );

                for callback in &self.callbacks {
                    if let Err(e) = callback.on_workflow_rejected(&workflow).await {
                        warn!(error = %e, "Callback failed on workflow_rejected");
                    }
                }

                self.send_completion_notification(&workflow).await;
                Ok(None)
            }
            WorkflowStatus::TimedOut => {
                info!(
                    workflow_id = %workflow_id,
                    "Workflow timed out"
                );
                self.send_completion_notification(&workflow).await;
                Ok(None)
            }
            WorkflowStatus::Cancelled => {
                info!(
                    workflow_id = %workflow_id,
                    "Workflow was cancelled"
                );
                Ok(None)
            }
            WorkflowStatus::Pending => {
                warn!(
                    workflow_id = %workflow_id,
                    "Attempted to process pending workflow"
                );
                Ok(None)
            }
        }
    }

    async fn initiate_signing(&self, workflow: &ApprovalWorkflow) -> Result<SigningSession> {
        let backend = self.backend_registry.get_default()?;

        let payload = self.build_signing_payload(&workflow.transaction_details)?;

        let required_signers = workflow
            .transaction_details
            .metadata
            .get("signers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let request = SigningRequest {
            transaction_id: workflow.transaction_id,
            wallet_id: workflow.transaction_details.source_wallet.clone(),
            payload,
            required_signers,
            timeout: std::time::Duration::from_secs(300),
            metadata: SigningMetadata::default(),
        };

        backend.initiate_signing(request).await
    }

    fn build_signing_payload(&self, details: &TransactionDetails) -> Result<SigningPayload> {
        if let Some(psbt_hex) = details.metadata.get("psbt").and_then(|v| v.as_str()) {
            let psbt_bytes = hex::decode(psbt_hex)
                .map_err(|e| Error::InvalidInput(format!("Invalid PSBT hex: {}", e)))?;
            return Ok(SigningPayload::Psbt(psbt_bytes));
        }

        if let Some(message) = details.metadata.get("message").and_then(|v| v.as_str()) {
            return Ok(SigningPayload::RawMessage(message.as_bytes().to_vec()));
        }

        Err(Error::InvalidInput(
            "Missing signing payload: transaction must include 'psbt' or 'message' in metadata"
                .into(),
        ))
    }

    fn build_completion_notification(
        &self,
        workflow: &ApprovalWorkflow,
    ) -> WorkflowCompleteNotification {
        let status = match workflow.status {
            WorkflowStatus::Approved => "approved",
            WorkflowStatus::Rejected => "rejected",
            WorkflowStatus::TimedOut => "timed_out",
            WorkflowStatus::Cancelled => "cancelled",
            WorkflowStatus::Pending => "pending",
        };

        let approvals = workflow
            .approvals
            .iter()
            .map(|a| ApprovalSummary {
                approver_id: a.approver_id.clone(),
                group: a.approver_role.clone(),
                decision: format!("{:?}", a.decision).to_lowercase(),
                timestamp: a.created_at,
            })
            .collect();

        WorkflowCompleteNotification {
            workflow_id: workflow.id,
            transaction_id: workflow.transaction_id,
            status: status.into(),
            approvals,
            rejected_by: workflow.rejected_by.clone(),
            rejection_reason: workflow.rejection_reason.clone(),
            completed_at: workflow.completed_at.unwrap_or_else(Utc::now),
        }
    }

    async fn send_completion_notification(&self, workflow: &ApprovalWorkflow) {
        let notification_data = self.build_completion_notification(workflow);
        let notification = Notification::WorkflowComplete(notification_data);

        if let Some(ref service) = self.notification_service {
            if let Some(webhook_url) = workflow
                .transaction_details
                .metadata
                .get("webhook_url")
                .and_then(|v| v.as_str())
            {
                match service
                    .send("webhook", &notification, webhook_url, workflow.id)
                    .await
                {
                    Ok(_) => {
                        info!(workflow_id = %workflow.id, "Completion notification sent");
                    }
                    Err(e) => {
                        warn!(workflow_id = %workflow.id, error = %e, "Failed to send completion notification");
                    }
                }
            }
        }
    }

    pub async fn poll_signing_status(
        &self,
        workflow_id: Uuid,
        session_id: Uuid,
    ) -> Result<SigningSession> {
        let backend = self.backend_registry.get_default()?;
        let mut session = backend.get_session(&session_id).await?;

        use crate::backend::SessionStatus;

        match &session.status {
            SessionStatus::Completed => {
                if session.signature.is_none() {
                    session.signature = Some(backend.get_signature(&session_id).await?);
                }

                for callback in &self.callbacks {
                    if let Err(e) = callback.on_signing_completed(workflow_id, &session).await {
                        warn!(error = %e, "Callback failed on signing_completed");
                    }
                }

                Ok(session)
            }
            SessionStatus::Failed { reason } => {
                for callback in &self.callbacks {
                    if let Err(e) = callback.on_signing_failed(workflow_id, reason).await {
                        warn!(error = %e, "Callback failed on signing_failed");
                    }
                }
                Err(Error::SigningFailed(reason.clone()))
            }
            _ => Ok(session),
        }
    }
}

pub struct TimeoutChecker {
    workflow_store: Arc<dyn WorkflowStore>,
    notification_service: Option<Arc<NotificationService>>,
    check_interval: std::time::Duration,
}

impl TimeoutChecker {
    pub fn new(workflow_store: Arc<dyn WorkflowStore>) -> Self {
        Self {
            workflow_store,
            notification_service: None,
            check_interval: std::time::Duration::from_secs(60),
        }
    }

    pub fn with_notification_service(mut self, service: Arc<NotificationService>) -> Self {
        self.notification_service = Some(service);
        self
    }

    pub fn with_interval(mut self, interval: std::time::Duration) -> Self {
        self.check_interval = interval;
        self
    }

    pub async fn check_once(&self) -> Result<Vec<Uuid>> {
        let pending = self.workflow_store.list_pending_workflows().await?;
        let mut expired = Vec::new();

        for mut workflow in pending {
            if workflow.is_expired() {
                workflow.check_expiration();
                self.workflow_store
                    .update_workflow(workflow.clone())
                    .await?;
                expired.push(workflow.id);

                if let Some(ref service) = self.notification_service {
                    let notification =
                        Notification::Timeout(crate::notification::TimeoutNotification {
                            workflow_id: workflow.id,
                            transaction_id: workflow.transaction_id,
                            transaction_details: workflow.transaction_details.clone(),
                            approvals_collected: workflow
                                .approvals
                                .iter()
                                .map(|a| ApprovalSummary {
                                    approver_id: a.approver_id.clone(),
                                    group: a.approver_role.clone(),
                                    decision: format!("{:?}", a.decision).to_lowercase(),
                                    timestamp: a.created_at,
                                })
                                .collect(),
                            expired_at: workflow.expires_at,
                        });

                    if let Some(webhook_url) = workflow
                        .transaction_details
                        .metadata
                        .get("webhook_url")
                        .and_then(|v| v.as_str())
                    {
                        if let Err(e) = service
                            .send("webhook", &notification, webhook_url, workflow.id)
                            .await
                        {
                            warn!(workflow_id = %workflow.id, error = %e, "Failed to send timeout notification");
                        }
                    }
                }

                info!(workflow_id = %workflow.id, "Workflow expired and marked as timed out");
            }
        }

        Ok(expired)
    }

    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let checker = self;
        tokio::spawn(async move {
            loop {
                match checker.check_once().await {
                    Ok(expired) if !expired.is_empty() => {
                        info!(count = expired.len(), "Expired {} workflows", expired.len());
                    }
                    Err(e) => {
                        error!(error = %e, "Timeout check failed");
                    }
                    _ => {}
                }
                tokio::time::sleep(checker.check_interval).await;
            }
        })
    }
}

pub struct LoggingCallback;

#[async_trait]
impl CompletionCallback for LoggingCallback {
    async fn on_workflow_approved(&self, workflow: &ApprovalWorkflow) -> Result<()> {
        info!(
            workflow_id = %workflow.id,
            transaction_id = %workflow.transaction_id,
            approvals = workflow.approvals.len(),
            "Workflow approved"
        );
        Ok(())
    }

    async fn on_workflow_rejected(&self, workflow: &ApprovalWorkflow) -> Result<()> {
        info!(
            workflow_id = %workflow.id,
            transaction_id = %workflow.transaction_id,
            rejected_by = ?workflow.rejected_by,
            reason = ?workflow.rejection_reason,
            "Workflow rejected"
        );
        Ok(())
    }

    async fn on_signing_initiated(
        &self,
        workflow_id: Uuid,
        session: &SigningSession,
    ) -> Result<()> {
        info!(
            workflow_id = %workflow_id,
            session_id = %session.session_id,
            "Signing session initiated"
        );
        Ok(())
    }

    async fn on_signing_completed(
        &self,
        workflow_id: Uuid,
        session: &SigningSession,
    ) -> Result<()> {
        info!(
            workflow_id = %workflow_id,
            session_id = %session.session_id,
            "Signing completed successfully"
        );
        Ok(())
    }

    async fn on_signing_failed(&self, workflow_id: Uuid, reason: &str) -> Result<()> {
        error!(
            workflow_id = %workflow_id,
            reason = %reason,
            "Signing failed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{InMemoryWorkflowStore, TransactionDetails};
    use crate::backend::MockSigningBackend;
    use crate::quorum::RequirementNode;
    use chrono::Duration;

    async fn setup_handler() -> (WorkflowCompletionHandler, Arc<InMemoryWorkflowStore>) {
        let workflow_store = Arc::new(InMemoryWorkflowStore::new());
        let backend_registry = Arc::new(BackendRegistry::new());
        backend_registry.register(Arc::new(MockSigningBackend::new()));

        let handler = WorkflowCompletionHandler::new(workflow_store.clone(), backend_registry);

        (handler, workflow_store)
    }

    #[tokio::test]
    async fn test_process_approved_workflow() {
        let (handler, workflow_store) = setup_handler().await;

        let requirement = RequirementNode::threshold(1, "treasury");
        let mut details = TransactionDetails::new("wallet1".into(), "dest".into(), 1000);
        details
            .metadata
            .insert("message".into(), serde_json::json!("test signing message"));

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let approval = crate::approval::Approval::new(
            "alice".into(),
            "treasury".into(),
            crate::approval::ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval);

        assert_eq!(workflow.status, WorkflowStatus::Approved);

        let workflow_id = workflow.id;
        workflow_store.create_workflow(workflow).await.unwrap();

        let result = handler.process_workflow_completion(workflow_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_process_rejected_workflow() {
        let (handler, workflow_store) = setup_handler().await;

        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "dest".into(), 1000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let rejection = crate::approval::Approval::new(
            "bob".into(),
            "treasury".into(),
            crate::approval::ApprovalDecision::Reject,
            0,
        )
        .with_comment("Too risky".into());
        workflow.add_approval(rejection);

        assert_eq!(workflow.status, WorkflowStatus::Rejected);

        let workflow_id = workflow.id;
        workflow_store.create_workflow(workflow).await.unwrap();

        let result = handler.process_workflow_completion(workflow_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_pending_workflow_not_processed() {
        let (handler, workflow_store) = setup_handler().await;

        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "dest".into(), 1000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        assert_eq!(workflow.status, WorkflowStatus::Pending);

        let workflow_id = workflow.id;
        workflow_store.create_workflow(workflow).await.unwrap();

        let result = handler.process_workflow_completion(workflow_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
