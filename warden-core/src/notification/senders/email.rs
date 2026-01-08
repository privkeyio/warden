use async_trait::async_trait;

use crate::notification::service::{NotificationError, NotificationSender};
use crate::notification::types::Notification;
use crate::secrets::SecretValue;

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: SecretValue,
    pub password: SecretValue,
    pub from_address: String,
    pub from_name: String,
}

impl EmailConfig {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            smtp_host: std::env::var("SMTP_HOST").ok()?,
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(587),
            username: std::env::var("SMTP_USERNAME").ok()?.into(),
            password: std::env::var("SMTP_PASSWORD").ok()?.into(),
            from_address: std::env::var("SMTP_FROM_ADDRESS").ok()?,
            from_name: std::env::var("SMTP_FROM_NAME").unwrap_or_else(|_| "Warden".into()),
        })
    }
}

pub struct EmailSender {
    config: EmailConfig,
}

impl EmailSender {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    fn format_subject(&self, notification: &Notification) -> String {
        match notification {
            Notification::ApprovalRequest(req) => {
                format!(
                    "Approval Required: {} sats transaction",
                    req.transaction_details.amount_sats
                )
            }
            Notification::ApprovalProgress(prog) => {
                format!("Approval Progress: Transaction {}", prog.transaction_id)
            }
            Notification::WorkflowComplete(complete) => {
                format!(
                    "Workflow {}: Transaction {}",
                    complete.status, complete.transaction_id
                )
            }
            Notification::Timeout(timeout) => {
                format!("Approval Timeout: Transaction {}", timeout.transaction_id)
            }
        }
    }

    fn format_body(&self, notification: &Notification) -> String {
        match notification {
            Notification::ApprovalRequest(req) => {
                let mut body = format!(
                    "A transaction requires your approval.\n\n\
                     Transaction ID: {}\n\
                     Amount: {} sats\n\
                     From: {}\n\
                     To: {}\n\
                     Expires: {}\n",
                    req.transaction_id,
                    req.transaction_details.amount_sats,
                    req.transaction_details.source_wallet,
                    req.transaction_details.destination,
                    req.expires_at.format("%Y-%m-%d %H:%M UTC")
                );
                if let Some(url) = &req.approval_url {
                    body.push_str(&format!("\nApprove or reject: {}", url));
                }
                body
            }
            Notification::ApprovalProgress(prog) => {
                format!(
                    "Approval received for transaction {}.\n\n\
                     Approver: {} ({})\n\
                     Decision: {}\n\
                     Complete: {}",
                    prog.transaction_id,
                    prog.approver_id,
                    prog.approver_group,
                    prog.decision,
                    if prog.is_complete { "Yes" } else { "No" }
                )
            }
            Notification::WorkflowComplete(complete) => {
                format!(
                    "Workflow completed for transaction {}.\n\n\
                     Status: {}\n\
                     Total approvals: {}\n\
                     Completed at: {}",
                    complete.transaction_id,
                    complete.status,
                    complete.approvals.len(),
                    complete.completed_at.format("%Y-%m-%d %H:%M UTC")
                )
            }
            Notification::Timeout(timeout) => {
                format!(
                    "Approval request has expired.\n\n\
                     Transaction ID: {}\n\
                     Expired at: {}\n\
                     Approvals collected: {}",
                    timeout.transaction_id,
                    timeout.expired_at.format("%Y-%m-%d %H:%M UTC"),
                    timeout.approvals_collected.len()
                )
            }
        }
    }
}

#[async_trait]
impl NotificationSender for EmailSender {
    fn channel_type(&self) -> &str {
        "email"
    }

    async fn send(
        &self,
        notification: &Notification,
        recipient: &str,
    ) -> std::result::Result<(), NotificationError> {
        use lettre::{
            message::header::ContentType, transport::smtp::authentication::Credentials,
            AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
        };

        let email = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_address)
                    .parse()
                    .map_err(|e| {
                        NotificationError::Permanent(format!("invalid from address: {}", e))
                    })?,
            )
            .to(recipient
                .parse()
                .map_err(|e| NotificationError::Permanent(format!("invalid recipient: {}", e)))?)
            .subject(self.format_subject(notification))
            .header(ContentType::TEXT_PLAIN)
            .body(self.format_body(notification))
            .map_err(|e| NotificationError::Permanent(format!("failed to build email: {}", e)))?;

        let creds = Credentials::new(
            self.config.username.expose().to_string(),
            self.config.password.expose().to_string(),
        );

        let mailer: AsyncSmtpTransport<Tokio1Executor> =
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_host)
                .map_err(|e| NotificationError::Permanent(format!("invalid SMTP host: {}", e)))?
                .port(self.config.smtp_port)
                .credentials(creds)
                .build();

        mailer.send(email).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("timeout") || msg.contains("connection") {
                NotificationError::Retryable(msg)
            } else {
                NotificationError::SendFailed(msg)
            }
        })?;

        Ok(())
    }
}
