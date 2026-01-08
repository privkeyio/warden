use async_trait::async_trait;

use crate::notification::service::{NotificationError, NotificationSender};
use crate::notification::types::{notification_type_name, Notification};

pub struct LoggingSender {
    name: String,
}

impl LoggingSender {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl NotificationSender for LoggingSender {
    fn channel_type(&self) -> &str {
        &self.name
    }

    async fn send(
        &self,
        notification: &Notification,
        recipient: &str,
    ) -> std::result::Result<(), NotificationError> {
        tracing::info!(
            channel = %self.name,
            recipient = %recipient,
            notification_type = %notification_type_name(notification),
            "notification sent"
        );
        Ok(())
    }
}
