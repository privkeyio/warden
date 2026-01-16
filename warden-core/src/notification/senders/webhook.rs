use async_trait::async_trait;
use chrono::Utc;

use crate::notification::service::{NotificationError, NotificationSender};
use crate::notification::types::{notification_type_name, Notification};
use crate::secrets::SecretValue;
use crate::ssrf::{validate_url, SsrfPolicy};

pub struct WebhookSender {
    client: reqwest::Client,
    default_secret: Option<SecretValue>,
    ssrf_policy: SsrfPolicy,
}

impl WebhookSender {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            default_secret: None,
            ssrf_policy: SsrfPolicy::strict(),
        }
    }

    pub fn with_secret(mut self, secret: impl Into<SecretValue>) -> Self {
        self.default_secret = Some(secret.into());
        self
    }

    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf_policy = policy;
        self
    }

    fn sign_payload(&self, timestamp: i64, payload: &str, secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let signature_input = format!("{}.{}", timestamp, payload);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
        mac.update(signature_input.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn parse_recipient<'a>(
        &self,
        recipient: &'a str,
    ) -> std::result::Result<(&'a str, Option<SecretValue>), NotificationError> {
        if let Some(idx) = recipient.rfind('|') {
            let url = &recipient[..idx];
            let secret = &recipient[idx + 1..];
            if url.is_empty() || secret.is_empty() {
                return Err(NotificationError::Permanent(
                    "invalid recipient format".into(),
                ));
            }
            Ok((url, Some(SecretValue::new(secret))))
        } else {
            Ok((recipient, self.default_secret.clone()))
        }
    }
}

impl Default for WebhookSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NotificationSender for WebhookSender {
    fn channel_type(&self) -> &str {
        "webhook"
    }

    async fn send(
        &self,
        notification: &Notification,
        recipient: &str,
    ) -> std::result::Result<(), NotificationError> {
        let (url, secret) = self.parse_recipient(recipient)?;

        validate_url(url, &self.ssrf_policy)
            .map_err(|e| NotificationError::Permanent(e.to_string()))?;

        let secret = secret
            .ok_or_else(|| NotificationError::Permanent("webhook secret not configured".into()))?;

        if secret.expose().len() < 32 {
            return Err(NotificationError::Permanent(
                "webhook secret must be at least 32 bytes".into(),
            ));
        }

        let timestamp = Utc::now().timestamp();
        let event_type = notification_type_name(notification);
        let payload = serde_json::to_string(notification)
            .map_err(|e| NotificationError::Permanent(e.to_string()))?;

        let signature = self.sign_payload(timestamp, &payload, secret.expose());

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Warden-Timestamp", timestamp.to_string())
            .header("X-Warden-Signature", format!("v1={}", signature))
            .header("X-Warden-Event", &event_type)
            .body(payload)
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
                "server error: {}",
                response.status()
            )))
        } else {
            Err(NotificationError::Permanent(format!(
                "client error: {}",
                response.status()
            )))
        }
    }
}
