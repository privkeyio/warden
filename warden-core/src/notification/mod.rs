//! Notification system for approval workflows.

#![forbid(unsafe_code)]

pub mod senders;
mod service;
mod store;
mod types;

pub use senders::{
    EmailConfig, EmailSender, LoggingSender, NostrConfig, NostrSender, SlackConfig, SlackSender,
    WebhookSender,
};
pub use service::{NotificationError, NotificationSender, NotificationService, RetryPolicy};
pub use store::{InMemoryNotificationStore, NotificationStore};
pub use types::{
    notification_type_name, ApprovalProgressNotification, ApprovalRequestNotification,
    ApprovalSummary, Notification, NotificationRecord, NotificationStatus, TimeoutNotification,
    WorkflowCompleteNotification,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::TransactionDetails;
    use chrono::Utc;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    struct MockSender {
        fail_count: std::sync::atomic::AtomicU32,
    }

    impl MockSender {
        fn new() -> Self {
            Self {
                fail_count: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn failing_n_times(n: u32) -> Self {
            Self {
                fail_count: std::sync::atomic::AtomicU32::new(n),
            }
        }
    }

    #[async_trait::async_trait]
    impl NotificationSender for MockSender {
        fn channel_type(&self) -> &str {
            "mock"
        }

        async fn send(
            &self,
            _notification: &Notification,
            _recipient: &str,
        ) -> std::result::Result<(), NotificationError> {
            let remaining = self.fail_count.load(std::sync::atomic::Ordering::SeqCst);
            if remaining > 0 {
                self.fail_count
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Err(NotificationError::Retryable("test failure".into()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_notification_service_success() {
        let service = NotificationService::new();
        service.register_sender(Arc::new(MockSender::new())).await;

        let notification = Notification::ApprovalRequest(ApprovalRequestNotification {
            workflow_id: Uuid::new_v4(),
            transaction_id: Uuid::new_v4(),
            transaction_details: TransactionDetails::new(
                "wallet-1".into(),
                "bc1q...".into(),
                100_000,
            ),
            pending_groups: vec![],
            expires_at: Utc::now(),
            approval_url: None,
        });

        let result = service
            .send("mock", &notification, "alice", Uuid::new_v4())
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, NotificationStatus::Sent);
    }

    #[tokio::test]
    async fn test_notification_service_retry() {
        let service = NotificationService::new().with_retry_policy(RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
        });
        service.register_sender(Arc::new(MockSender::failing_n_times(2))).await;

        let notification = Notification::ApprovalRequest(ApprovalRequestNotification {
            workflow_id: Uuid::new_v4(),
            transaction_id: Uuid::new_v4(),
            transaction_details: TransactionDetails::new(
                "wallet-1".into(),
                "bc1q...".into(),
                100_000,
            ),
            pending_groups: vec![],
            expires_at: Utc::now(),
            approval_url: None,
        });

        let result = service
            .send("mock", &notification, "alice", Uuid::new_v4())
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_retry_policy_delay() {
        let policy = RetryPolicy {
            max_attempts: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
        };

        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(policy.delay_for_attempt(4), Duration::from_secs(8));
        assert_eq!(policy.delay_for_attempt(10), Duration::from_secs(60));
    }
}
