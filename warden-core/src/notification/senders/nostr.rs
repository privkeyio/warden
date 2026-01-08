use async_trait::async_trait;

use crate::notification::service::{NotificationError, NotificationSender};
use crate::notification::types::{notification_type_name, Notification};
use crate::secrets::SecretValue;

#[derive(Debug, Clone)]
pub struct NostrConfig {
    pub relay_urls: Vec<String>,
    pub private_key: Option<SecretValue>,
}

impl NostrConfig {
    pub fn from_env() -> Self {
        Self {
            relay_urls: std::env::var("NOSTR_RELAY_URLS")
                .map(|s| s.split(',').map(|r| r.trim().to_string()).collect())
                .unwrap_or_else(|_| vec!["wss://relay.damus.io".into(), "wss://nos.lol".into()]),
            private_key: std::env::var("NOSTR_PRIVATE_KEY")
                .ok()
                .map(SecretValue::new),
        }
    }
}

impl Default for NostrConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

pub struct NostrSender {
    keys: Option<nostr_sdk::Keys>,
    relay_urls: Vec<String>,
}

impl NostrSender {
    pub fn new(config: NostrConfig) -> Self {
        let keys = config.private_key.as_ref().and_then(|secret| {
            nostr_sdk::SecretKey::parse(secret.expose())
                .ok()
                .map(nostr_sdk::Keys::new)
        });
        Self {
            keys,
            relay_urls: config.relay_urls,
        }
    }

    fn format_nostr_content(&self, notification: &Notification) -> String {
        match notification {
            Notification::ApprovalRequest(req) => {
                format!(
                    "Approval Required\nTransaction: {}\nAmount: {} sats\nFrom: {}\nTo: {}\nExpires: {}",
                    req.transaction_id,
                    req.transaction_details.amount_sats,
                    req.transaction_details.source_wallet,
                    req.transaction_details.destination,
                    req.expires_at.format("%Y-%m-%d %H:%M UTC")
                )
            }
            Notification::ApprovalProgress(prog) => {
                format!(
                    "Approval Progress\nTransaction: {}\nApprover: {} ({})\nDecision: {}\nComplete: {}",
                    prog.transaction_id,
                    prog.approver_id,
                    prog.approver_group,
                    prog.decision,
                    if prog.is_complete { "Yes" } else { "No" }
                )
            }
            Notification::WorkflowComplete(complete) => {
                format!(
                    "Workflow Complete\nTransaction: {}\nStatus: {}\nApprovals: {}",
                    complete.transaction_id,
                    complete.status,
                    complete.approvals.len()
                )
            }
            Notification::Timeout(timeout) => {
                format!(
                    "Approval Timeout\nTransaction: {}\nExpired at: {}\nCollected approvals: {}",
                    timeout.transaction_id,
                    timeout.expired_at.format("%Y-%m-%d %H:%M UTC"),
                    timeout.approvals_collected.len()
                )
            }
        }
    }
}

#[async_trait]
impl NotificationSender for NostrSender {
    fn channel_type(&self) -> &str {
        "nostr"
    }

    async fn send(
        &self,
        notification: &Notification,
        recipient: &str,
    ) -> std::result::Result<(), NotificationError> {
        let keys = self.keys.as_ref().ok_or_else(|| {
            NotificationError::Permanent(format!(
                "Nostr sender not configured with private key (recipient: {}, type: {})",
                recipient,
                notification_type_name(notification)
            ))
        })?;

        let recipient_pubkey = nostr_sdk::PublicKey::parse(recipient).map_err(|e| {
            NotificationError::Permanent(format!("invalid recipient pubkey: {}", e))
        })?;

        let content = self.format_nostr_content(notification);

        let gift_wrap = nostr_sdk::EventBuilder::private_msg(keys, recipient_pubkey, &content, [])
            .await
            .map_err(|e| {
                NotificationError::Permanent(format!("failed to create gift wrap: {}", e))
            })?;

        let client = nostr_sdk::Client::new(keys.clone());
        for relay_url in &self.relay_urls {
            if let Err(e) = client.add_relay(relay_url).await {
                tracing::warn!(relay = %relay_url, error = %e, "failed to add relay");
            }
        }

        client.connect().await;

        match client.send_event(gift_wrap).await {
            Ok(output) => {
                tracing::info!(
                    recipient_pubkey = %recipient,
                    notification_type = %notification_type_name(notification),
                    event_id = %output.id(),
                    success_count = output.success.len(),
                    failed_count = output.failed.len(),
                    "Nostr NIP-17 private message sent"
                );
            }
            Err(e) => {
                return Err(NotificationError::Retryable(format!(
                    "failed to send event: {}",
                    e
                )));
            }
        }

        let _ = client.disconnect().await;
        Ok(())
    }
}
