//! Notification type definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::approval::{ApprovalWorkflow, TransactionDetails};
use crate::quorum::PendingGroupInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Notification {
    ApprovalRequest(ApprovalRequestNotification),
    ApprovalProgress(ApprovalProgressNotification),
    WorkflowComplete(WorkflowCompleteNotification),
    Timeout(TimeoutNotification),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestNotification {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub transaction_details: TransactionDetails,
    pub pending_groups: Vec<PendingGroupInfo>,
    pub expires_at: DateTime<Utc>,
    pub approval_url: Option<String>,
}

impl ApprovalRequestNotification {
    pub fn from_workflow(workflow: &ApprovalWorkflow, approval_url: Option<String>) -> Self {
        Self {
            workflow_id: workflow.id,
            transaction_id: workflow.transaction_id,
            transaction_details: workflow.transaction_details.clone(),
            pending_groups: crate::quorum::QuorumEvaluator::new()
                .pending_groups(&workflow.requirement, &workflow.approvals),
            expires_at: workflow.expires_at,
            approval_url,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalProgressNotification {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub approver_id: String,
    pub approver_group: String,
    pub decision: String,
    pub pending_groups: Vec<PendingGroupInfo>,
    pub is_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompleteNotification {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub status: String,
    pub approvals: Vec<ApprovalSummary>,
    pub rejected_by: Option<String>,
    pub rejection_reason: Option<String>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub approver_id: String,
    pub group: String,
    pub decision: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutNotification {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub transaction_details: TransactionDetails,
    pub approvals_collected: Vec<ApprovalSummary>,
    pub expired_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub recipient_id: String,
    pub channel: String,
    pub notification_type: String,
    pub status: NotificationStatus,
    pub sent_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub retry_count: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationStatus {
    Pending,
    Sent,
    Delivered,
    Failed,
}

pub fn notification_type_name(notification: &Notification) -> String {
    match notification {
        Notification::ApprovalRequest(_) => "approval_request".into(),
        Notification::ApprovalProgress(_) => "approval_progress".into(),
        Notification::WorkflowComplete(_) => "workflow_complete".into(),
        Notification::Timeout(_) => "timeout".into(),
    }
}
