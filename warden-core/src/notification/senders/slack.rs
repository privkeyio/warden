use async_trait::async_trait;

use crate::notification::service::{NotificationError, NotificationSender};
use crate::notification::types::Notification;

#[derive(Debug, Clone)]
pub struct SlackConfig {
    pub webhook_url: String,
}

pub struct SlackSender {
    config: SlackConfig,
    client: reqwest::Client,
}

impl SlackSender {
    pub fn new(config: SlackConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    fn format_blocks(&self, notification: &Notification) -> serde_json::Value {
        match notification {
            Notification::ApprovalRequest(req) => {
                serde_json::json!({
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": "🔐 Approval Required", "emoji": true}
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": format!("*Transaction:*\n{}", req.transaction_id)},
                                {"type": "mrkdwn", "text": format!("*Amount:*\n{} sats", req.transaction_details.amount_sats)},
                                {"type": "mrkdwn", "text": format!("*From:*\n{}", req.transaction_details.source_wallet)},
                                {"type": "mrkdwn", "text": format!("*To:*\n`{}`", req.transaction_details.destination)},
                            ]
                        },
                        {
                            "type": "context",
                            "elements": [
                                {"type": "mrkdwn", "text": format!("Expires: {}", req.expires_at.format("%Y-%m-%d %H:%M UTC"))}
                            ]
                        }
                    ]
                })
            }
            Notification::ApprovalProgress(prog) => {
                let emoji = if prog.decision == "APPROVE" {
                    "✅"
                } else {
                    "❌"
                };
                serde_json::json!({
                    "blocks": [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": format!("{} *{}* ({}) {} transaction `{}`",
                                emoji, prog.approver_id, prog.approver_group, prog.decision.to_lowercase(), prog.transaction_id)}
                        }
                    ]
                })
            }
            Notification::WorkflowComplete(complete) => {
                let emoji = match complete.status.as_str() {
                    "APPROVED" => "🎉",
                    "REJECTED" => "🚫",
                    _ => "📋",
                };
                serde_json::json!({
                    "blocks": [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": format!("{} Workflow *{}* for transaction `{}`",
                                emoji, complete.status, complete.transaction_id)}
                        }
                    ]
                })
            }
            Notification::Timeout(timeout) => {
                serde_json::json!({
                    "blocks": [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": format!("⏰ Approval *timed out* for transaction `{}`\nCollected {} of required approvals",
                                timeout.transaction_id, timeout.approvals_collected.len())}
                        }
                    ]
                })
            }
        }
    }
}

#[async_trait]
impl NotificationSender for SlackSender {
    fn channel_type(&self) -> &str {
        "slack"
    }

    async fn send(
        &self,
        notification: &Notification,
        _recipient: &str,
    ) -> std::result::Result<(), NotificationError> {
        let payload = self.format_blocks(notification);

        let response = self
            .client
            .post(&self.config.webhook_url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() || e.is_connect() {
                    NotificationError::Retryable(e.to_string())
                } else {
                    NotificationError::SendFailed(e.to_string())
                }
            })?;

        if response.status().is_success() {
            Ok(())
        } else if response.status().is_server_error() {
            Err(NotificationError::Retryable(format!(
                "Slack error: {}",
                response.status()
            )))
        } else {
            Err(NotificationError::Permanent(format!(
                "Slack error: {}",
                response.status()
            )))
        }
    }
}
