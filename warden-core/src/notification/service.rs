//! Notification service and retry logic.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::types::{notification_type_name, Notification, NotificationRecord, NotificationStatus};

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_secs =
            self.initial_delay.as_secs_f64() * self.backoff_multiplier.powi(attempt as i32 - 1);
        Duration::from_secs_f64(delay_secs.min(self.max_delay.as_secs_f64()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationError {
    ChannelNotConfigured(String),
    SendFailed(String),
    Retryable(String),
    Permanent(String),
}

impl std::fmt::Display for NotificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelNotConfigured(ch) => write!(f, "channel not configured: {}", ch),
            Self::SendFailed(msg) => write!(f, "send failed: {}", msg),
            Self::Retryable(msg) => write!(f, "retryable error: {}", msg),
            Self::Permanent(msg) => write!(f, "permanent error: {}", msg),
        }
    }
}

impl std::error::Error for NotificationError {}

impl NotificationError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

#[async_trait]
pub trait NotificationSender: Send + Sync {
    fn channel_type(&self) -> &str;
    async fn send(
        &self,
        notification: &Notification,
        recipient: &str,
    ) -> std::result::Result<(), NotificationError>;
}

pub struct NotificationService {
    senders: Arc<RwLock<HashMap<String, Arc<dyn NotificationSender>>>>,
    retry_policy: RetryPolicy,
    records: RwLock<Vec<NotificationRecord>>,
}

impl NotificationService {
    pub fn new() -> Self {
        Self {
            senders: Arc::new(RwLock::new(HashMap::new())),
            retry_policy: RetryPolicy::default(),
            records: RwLock::new(Vec::new()),
        }
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    pub async fn register_sender(&self, sender: Arc<dyn NotificationSender>) {
        self.senders
            .write()
            .await
            .insert(sender.channel_type().to_string(), sender);
    }

    pub async fn send(
        &self,
        channel: &str,
        notification: &Notification,
        recipient: &str,
        workflow_id: Uuid,
    ) -> std::result::Result<NotificationRecord, NotificationError> {
        let senders = self.senders.read().await;
        let sender = senders
            .get(channel)
            .cloned()
            .ok_or_else(|| NotificationError::ChannelNotConfigured(channel.into()))?;
        drop(senders);

        let mut record = NotificationRecord {
            id: Uuid::new_v4(),
            workflow_id,
            recipient_id: recipient.into(),
            channel: channel.into(),
            notification_type: notification_type_name(notification),
            status: NotificationStatus::Pending,
            sent_at: None,
            delivered_at: None,
            error_message: None,
            retry_count: 0,
            created_at: Utc::now(),
        };

        let result = self
            .send_with_retry(sender.as_ref(), notification, recipient, &mut record)
            .await;

        self.records.write().await.push(record.clone());

        result.map(|_| record)
    }

    async fn send_with_retry(
        &self,
        sender: &dyn NotificationSender,
        notification: &Notification,
        recipient: &str,
        record: &mut NotificationRecord,
    ) -> std::result::Result<(), NotificationError> {
        if self.retry_policy.max_attempts == 0 {
            let err = NotificationError::SendFailed("max_attempts is 0".into());
            record.status = NotificationStatus::Failed;
            record.error_message = Some(err.to_string());
            return Err(err);
        }

        for attempt in 1..=self.retry_policy.max_attempts {
            record.retry_count = attempt - 1;

            match sender.send(notification, recipient).await {
                Ok(()) => {
                    record.status = NotificationStatus::Sent;
                    record.sent_at = Some(Utc::now());
                    return Ok(());
                }
                Err(e) if e.is_retryable() && attempt < self.retry_policy.max_attempts => {
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    record.status = NotificationStatus::Failed;
                    record.error_message = Some(e.to_string());
                    return Err(e);
                }
            }
        }

        unreachable!("loop always returns")
    }

    pub async fn get_records(&self, workflow_id: &Uuid) -> Vec<NotificationRecord> {
        self.records
            .read()
            .await
            .iter()
            .filter(|r| &r.workflow_id == workflow_id)
            .cloned()
            .collect()
    }
}

impl Default for NotificationService {
    fn default() -> Self {
        Self::new()
    }
}
