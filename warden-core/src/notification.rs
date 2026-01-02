#![forbid(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

use crate::approval::{ApprovalWorkflow, TransactionDetails};
use crate::quorum::PendingGroupInfo;
use crate::secrets::SecretValue;
use crate::Result;

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
    senders: HashMap<String, Arc<dyn NotificationSender>>,
    retry_policy: RetryPolicy,
    records: RwLock<Vec<NotificationRecord>>,
}

impl NotificationService {
    pub fn new() -> Self {
        Self {
            senders: HashMap::new(),
            retry_policy: RetryPolicy::default(),
            records: RwLock::new(Vec::new()),
        }
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    pub fn register_sender(&mut self, sender: Arc<dyn NotificationSender>) {
        self.senders
            .insert(sender.channel_type().to_string(), sender);
    }

    pub async fn send(
        &self,
        channel: &str,
        notification: &Notification,
        recipient: &str,
        workflow_id: Uuid,
    ) -> std::result::Result<NotificationRecord, NotificationError> {
        let sender = self
            .senders
            .get(channel)
            .ok_or_else(|| NotificationError::ChannelNotConfigured(channel.into()))?;

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

        {
            let mut records = self.records.write().expect("lock poisoned");
            records.push(record.clone());
        }

        result.map(|_| record)
    }

    async fn send_with_retry(
        &self,
        sender: &dyn NotificationSender,
        notification: &Notification,
        recipient: &str,
        record: &mut NotificationRecord,
    ) -> std::result::Result<(), NotificationError> {
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

        let err = NotificationError::SendFailed("max retries exceeded".into());
        record.status = NotificationStatus::Failed;
        record.error_message = Some(err.to_string());
        Err(err)
    }

    pub fn get_records(&self, workflow_id: &Uuid) -> Vec<NotificationRecord> {
        let records = self.records.read().expect("lock poisoned");
        records
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

fn notification_type_name(notification: &Notification) -> String {
    match notification {
        Notification::ApprovalRequest(_) => "approval_request".into(),
        Notification::ApprovalProgress(_) => "approval_progress".into(),
        Notification::WorkflowComplete(_) => "workflow_complete".into(),
        Notification::Timeout(_) => "timeout".into(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct SsrfConfig {
    pub allowlist: Option<HashSet<String>>,
    pub allow_private_ips: bool,
}

impl SsrfConfig {
    pub fn strict() -> Self {
        Self {
            allowlist: None,
            allow_private_ips: false,
        }
    }

    pub fn with_allowlist(domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowlist: Some(domains.into_iter().map(Into::into).collect()),
            allow_private_ips: false,
        }
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()                                    // 127.0.0.0/8
        || ip.is_private()                              // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()                           // 169.254.0.0/16 (includes cloud metadata)
        || ip.is_broadcast()                            // 255.255.255.255
        || ip.is_documentation()                        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        || ip.is_unspecified()                          // 0.0.0.0
        || ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64  // 100.64.0.0/10 (CGNAT)
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()                                    // ::1
        || ip.is_unspecified()                          // ::
        || (ip.segments()[0] & 0xFE00) == 0xFC00        // fc00::/7 (ULA)
        || (ip.segments()[0] & 0xFFC0) == 0xFE80        // fe80::/10 (link-local)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "kubernetes.default.svc",
];

fn validate_webhook_url(url_str: &str, config: &SsrfConfig) -> std::result::Result<(), NotificationError> {
    let url = Url::parse(url_str)
        .map_err(|e| NotificationError::Permanent(format!("invalid URL: {}", e)))?;

    if url.scheme() != "https" {
        return Err(NotificationError::Permanent(
            "webhook URL must use HTTPS".into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| NotificationError::Permanent("webhook URL must have a host".into()))?;

    if let Some(ref allowlist) = config.allowlist {
        if !allowlist.contains(host) {
            return Err(NotificationError::Permanent(format!(
                "host '{}' not in allowlist",
                host
            )));
        }
        return Ok(());
    }

    let host_lower = host.to_lowercase();
    for blocked in BLOCKED_HOSTNAMES {
        if host_lower == *blocked || host_lower.ends_with(&format!(".{}", blocked)) {
            return Err(NotificationError::Permanent(format!(
                "blocked hostname: {}",
                host
            )));
        }
    }

    if config.allow_private_ips {
        return Ok(());
    }

    let port = url.port().unwrap_or(443);
    let socket_addr = format!("{}:{}", host, port);

    let resolved_ips: Vec<IpAddr> = socket_addr
        .to_socket_addrs()
        .map_err(|e| NotificationError::Permanent(format!("DNS resolution failed: {}", e)))?
        .map(|addr| addr.ip())
        .collect();

    if resolved_ips.is_empty() {
        return Err(NotificationError::Permanent(
            "DNS resolution returned no addresses".into(),
        ));
    }

    for ip in &resolved_ips {
        if is_private_ip(*ip) {
            return Err(NotificationError::Permanent(format!(
                "webhook URL resolves to private/internal IP: {}",
                ip
            )));
        }
    }

    Ok(())
}

pub struct WebhookSender {
    client: reqwest::Client,
    default_secret: Option<String>,
    ssrf_config: SsrfConfig,
}

impl WebhookSender {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            default_secret: None,
            ssrf_config: SsrfConfig::strict(),
        }
    }

    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.default_secret = Some(secret.into());
        self
    }

    pub fn with_ssrf_config(mut self, config: SsrfConfig) -> Self {
        self.ssrf_config = config;
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
    ) -> std::result::Result<(&'a str, Option<String>), NotificationError> {
        if let Some(idx) = recipient.rfind('|') {
            let url = &recipient[..idx];
            let secret = &recipient[idx + 1..];
            if url.is_empty() || secret.is_empty() {
                return Err(NotificationError::Permanent(
                    "invalid recipient format".into(),
                ));
            }
            Ok((url, Some(secret.to_string())))
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

        validate_webhook_url(url, &self.ssrf_config)?;

        let secret = secret
            .ok_or_else(|| NotificationError::Permanent("webhook secret not configured".into()))?;

        let timestamp = Utc::now().timestamp();
        let event_type = notification_type_name(notification);
        let payload = serde_json::to_string(notification)
            .map_err(|e| NotificationError::Permanent(e.to_string()))?;

        let signature = self.sign_payload(timestamp, &payload, &secret);

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
        let keys = match &self.keys {
            Some(k) => k,
            None => {
                tracing::warn!(
                    recipient = %recipient,
                    notification_type = %notification_type_name(notification),
                    "Nostr sender not configured with private key, skipping"
                );
                return Ok(());
            }
        };

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

#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn save_record(&self, record: NotificationRecord) -> Result<NotificationRecord>;
    async fn get_records_for_workflow(&self, workflow_id: &Uuid)
        -> Result<Vec<NotificationRecord>>;
    async fn update_record(&self, record: NotificationRecord) -> Result<NotificationRecord>;
    async fn list_pending(&self) -> Result<Vec<NotificationRecord>>;
}

pub struct InMemoryNotificationStore {
    records: RwLock<HashMap<Uuid, NotificationRecord>>,
}

impl InMemoryNotificationStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryNotificationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NotificationStore for InMemoryNotificationStore {
    async fn save_record(&self, record: NotificationRecord) -> Result<NotificationRecord> {
        let mut records = self.records.write().expect("lock poisoned");
        records.insert(record.id, record.clone());
        Ok(record)
    }

    async fn get_records_for_workflow(
        &self,
        workflow_id: &Uuid,
    ) -> Result<Vec<NotificationRecord>> {
        let records = self.records.read().expect("lock poisoned");
        Ok(records
            .values()
            .filter(|r| &r.workflow_id == workflow_id)
            .cloned()
            .collect())
    }

    async fn update_record(&self, record: NotificationRecord) -> Result<NotificationRecord> {
        let mut records = self.records.write().expect("lock poisoned");
        records.insert(record.id, record.clone());
        Ok(record)
    }

    async fn list_pending(&self) -> Result<Vec<NotificationRecord>> {
        let records = self.records.read().expect("lock poisoned");
        Ok(records
            .values()
            .filter(|r| r.status == NotificationStatus::Pending)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSender {
        fail_count: std::sync::atomic::AtomicU32,
    }

    impl MockSender {
        fn new(_should_fail: bool) -> Self {
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

    #[async_trait]
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
        let mut service = NotificationService::new();
        service.register_sender(Arc::new(MockSender::new(false)));

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
        let mut service = NotificationService::new().with_retry_policy(RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
        });
        service.register_sender(Arc::new(MockSender::failing_n_times(2)));

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

    #[test]
    fn test_ssrf_blocks_http() {
        let config = SsrfConfig::strict();
        let result = validate_webhook_url("http://example.com/webhook", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        let config = SsrfConfig::strict();
        let result = validate_webhook_url("https://localhost/webhook", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("blocked hostname"));
    }

    #[test]
    fn test_ssrf_blocks_cloud_metadata() {
        let config = SsrfConfig::strict();
        let result = validate_webhook_url("https://metadata.google.internal/computeMetadata", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("blocked hostname"));
    }

    #[test]
    fn test_ssrf_blocks_private_ip_loopback() {
        assert!(is_private_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_ssrf_blocks_private_ip_class_a() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_ssrf_blocks_private_ip_class_b() {
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 15, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 32, 0, 0)));
    }

    #[test]
    fn test_ssrf_blocks_private_ip_class_c() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 169, 254)));
    }

    #[test]
    fn test_ssrf_blocks_cgnat() {
        assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn test_ssrf_allows_public_ip() {
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_ssrf_blocks_ipv6_loopback() {
        assert!(is_private_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_ssrf_blocks_ipv6_ula() {
        assert!(is_private_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(Ipv6Addr::new(0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)));
    }

    #[test]
    fn test_ssrf_blocks_ipv6_link_local() {
        assert!(is_private_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_ssrf_allowlist() {
        let config = SsrfConfig::with_allowlist(["api.example.com", "hooks.slack.com"]);

        let result = validate_webhook_url("https://api.example.com/webhook", &config);
        assert!(result.is_ok());

        let result = validate_webhook_url("https://hooks.slack.com/webhook", &config);
        assert!(result.is_ok());

        let result = validate_webhook_url("https://evil.com/webhook", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in allowlist"));
    }

    #[test]
    fn test_ssrf_config_strict() {
        let config = SsrfConfig::strict();
        assert!(config.allowlist.is_none());
        assert!(!config.allow_private_ips);
    }
}
