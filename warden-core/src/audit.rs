#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: EventId,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor: Option<ActorInfo>,
    pub resource: ResourceInfo,
    pub details: Value,
    pub previous_hash: Hash,
    pub hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuditEventType {
    PolicyCreated {
        policy_id: String,
        version: String,
    },
    PolicyActivated {
        policy_id: String,
        version: String,
    },
    PolicyDeactivated {
        policy_id: String,
    },
    BundleLoaded {
        version: String,
        merkle_root: String,
    },
    TransactionSubmitted {
        transaction_id: String,
    },
    PolicyEvaluated {
        transaction_id: String,
        decision: String,
        matched_rule: Option<String>,
        evaluation_time_us: u64,
    },
    ApprovalWorkflowStarted {
        transaction_id: String,
        workflow_id: String,
    },
    ApprovalReceived {
        transaction_id: String,
        approver_id: String,
        decision: String,
    },
    ApprovalWorkflowCompleted {
        transaction_id: String,
        outcome: String,
    },
    CallbackInvoked {
        transaction_id: String,
        handler_id: String,
    },
    CallbackCompleted {
        transaction_id: String,
        handler_id: String,
        decision: String,
        latency_ms: u64,
    },
    SigningInitiated {
        transaction_id: String,
        session_id: String,
    },
    SigningCompleted {
        transaction_id: String,
        txid: String,
    },
    SigningFailed {
        transaction_id: String,
        error: String,
    },
    SystemStarted {
        version: String,
    },
    ConfigurationChanged {
        key: String,
    },
    EnclaveAttestationVerified {
        pcr0: String,
    },
    EscalationTriggered {
        transaction_id: String,
        stage: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorInfo {
    pub actor_type: ActorType,
    pub id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActorType {
    User,
    ApiKey,
    System,
    Enclave,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub resource_type: String,
    pub resource_id: String,
}

impl ResourceInfo {
    pub fn policy(id: &str) -> Self {
        Self {
            resource_type: "policy".into(),
            resource_id: id.into(),
        }
    }

    pub fn transaction(id: &str) -> Self {
        Self {
            resource_type: "transaction".into(),
            resource_id: id.into(),
        }
    }

    pub fn workflow(id: &str) -> Self {
        Self {
            resource_type: "workflow".into(),
            resource_id: id.into(),
        }
    }

    pub fn system() -> Self {
        Self {
            resource_type: "system".into(),
            resource_id: "warden".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ChainVerification {
    Valid {
        events_checked: usize,
        last_sequence: u64,
    },
    Broken {
        at_sequence: u64,
        expected: Hash,
        found: Hash,
    },
    Tampered {
        at_sequence: u64,
    },
}

#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub from_time: Option<DateTime<Utc>>,
    pub to_time: Option<DateTime<Utc>>,
    pub resource_id: Option<String>,
    pub event_types: Option<Vec<String>>,
    pub actor_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[async_trait::async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, event: &AuditEvent) -> Result<()>;
    async fn get_event(&self, sequence: u64) -> Result<AuditEvent>;
    async fn get_range(&self, from: u64, to: u64) -> Result<Vec<AuditEvent>>;
    async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>>;
    async fn get_latest_sequence(&self) -> Result<u64>;
    async fn get_latest_hash(&self) -> Result<Hash>;
}

pub struct AuditLog<S: AuditStore> {
    store: S,
    sequence: AtomicU64,
    last_hash: RwLock<Hash>,
    record_mutex: Mutex<()>,
}

impl<S: AuditStore> AuditLog<S> {
    pub async fn new(store: S) -> Result<Self> {
        let sequence = store.get_latest_sequence().await.unwrap_or(0);
        let last_hash = store.get_latest_hash().await.unwrap_or([0u8; 32]);

        Ok(Self {
            store,
            sequence: AtomicU64::new(sequence),
            last_hash: RwLock::new(last_hash),
            record_mutex: Mutex::new(()),
        })
    }

    pub async fn record(
        &self,
        event_type: AuditEventType,
        actor: Option<ActorInfo>,
        resource: ResourceInfo,
        details: Value,
    ) -> Result<EventId> {
        let _guard = self.record_mutex.lock().await;

        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let previous_hash = *self.last_hash.read().await;

        let mut event = AuditEvent {
            id: EventId::new(),
            sequence,
            timestamp: Utc::now(),
            event_type,
            actor,
            resource,
            details,
            previous_hash,
            hash: [0u8; 32],
        };

        event.hash = self.compute_hash(&event)?;

        self.store.append(&event).await?;

        *self.last_hash.write().await = event.hash;

        Ok(event.id)
    }

    fn compute_hash(&self, event: &AuditEvent) -> Result<Hash> {
        let mut hasher = Sha256::new();

        hasher.update(event.id.as_bytes());
        hasher.update(event.sequence.to_le_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        let event_type_bytes = serde_json::to_vec(&event.event_type)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        hasher.update(&event_type_bytes);
        hasher.update(event.previous_hash);

        Ok(hasher.finalize().into())
    }

    pub async fn verify_chain(&self, from_sequence: u64) -> Result<ChainVerification> {
        let latest = self.store.get_latest_sequence().await?;
        let events = self.store.get_range(from_sequence, latest).await?;

        if events.is_empty() {
            return Ok(ChainVerification::Valid {
                events_checked: 0,
                last_sequence: from_sequence.saturating_sub(1),
            });
        }

        let mut expected_hash = if from_sequence > 1 {
            self.store.get_event(from_sequence - 1).await?.hash
        } else {
            [0u8; 32]
        };

        for event in &events {
            if event.previous_hash != expected_hash {
                return Ok(ChainVerification::Broken {
                    at_sequence: event.sequence,
                    expected: expected_hash,
                    found: event.previous_hash,
                });
            }

            let computed = self.compute_hash(event)?;
            if computed != event.hash {
                return Ok(ChainVerification::Tampered {
                    at_sequence: event.sequence,
                });
            }

            expected_hash = event.hash;
        }

        Ok(ChainVerification::Valid {
            events_checked: events.len(),
            last_sequence: events.last().map(|e| e.sequence).unwrap_or(0),
        })
    }

    pub async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        self.store.query(query).await
    }

    pub async fn get_latest_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }
}

pub struct InMemoryAuditStore {
    events: RwLock<Vec<AuditEvent>>,
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn append(&self, event: &AuditEvent) -> Result<()> {
        self.events.write().await.push(event.clone());
        Ok(())
    }

    async fn get_event(&self, sequence: u64) -> Result<AuditEvent> {
        self.events
            .read()
            .await
            .iter()
            .find(|e| e.sequence == sequence)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("Event {} not found", sequence)))
    }

    async fn get_range(&self, from: u64, to: u64) -> Result<Vec<AuditEvent>> {
        Ok(self
            .events
            .read()
            .await
            .iter()
            .filter(|e| e.sequence >= from && e.sequence <= to)
            .cloned()
            .collect())
    }

    async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let mut results: Vec<_> = events
            .iter()
            .filter(|e| {
                if let Some(ref from) = query.from_time {
                    if e.timestamp < *from {
                        return false;
                    }
                }
                if let Some(ref to) = query.to_time {
                    if e.timestamp > *to {
                        return false;
                    }
                }
                if let Some(ref resource_id) = query.resource_id {
                    if e.resource.resource_id != *resource_id {
                        return false;
                    }
                }
                if let Some(ref actor_id) = query.actor_id {
                    if let Some(ref actor) = e.actor {
                        if actor.id != *actor_id {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if let Some(ref event_types) = query.event_types {
                    let event_type_name = serde_json::to_value(&e.event_type)
                        .ok()
                        .and_then(|v| v.get("type").and_then(|t| t.as_str().map(String::from)));
                    match event_type_name {
                        Some(name) => {
                            if !event_types.contains(&name) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
                true
            })
            .cloned()
            .collect();

        if let Some(offset) = query.offset {
            results = results.into_iter().skip(offset).collect();
        }
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn get_latest_sequence(&self) -> Result<u64> {
        Ok(self
            .events
            .read()
            .await
            .last()
            .map(|e| e.sequence)
            .unwrap_or(0))
    }

    async fn get_latest_hash(&self) -> Result<Hash> {
        Ok(self
            .events
            .read()
            .await
            .last()
            .map(|e| e.hash)
            .unwrap_or([0u8; 32]))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOC2AuditReport {
    pub period: DateRange,
    pub access_controls: Vec<AuditEvent>,
    pub change_management: Vec<AuditEvent>,
    pub incident_response: Vec<AuditEvent>,
    pub chain_verification: ChainVerificationReport,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationReport {
    pub status: String,
    pub events_checked: usize,
    pub last_sequence: u64,
}

impl From<ChainVerification> for ChainVerificationReport {
    fn from(v: ChainVerification) -> Self {
        match v {
            ChainVerification::Valid {
                events_checked,
                last_sequence,
            } => Self {
                status: "valid".into(),
                events_checked,
                last_sequence,
            },
            ChainVerification::Broken { at_sequence, .. } => Self {
                status: format!("broken at sequence {}", at_sequence),
                events_checked: 0,
                last_sequence: at_sequence,
            },
            ChainVerification::Tampered { at_sequence } => Self {
                status: format!("tampered at sequence {}", at_sequence),
                events_checked: 0,
                last_sequence: at_sequence,
            },
        }
    }
}

pub struct ComplianceExporter<S: AuditStore> {
    audit_log: AuditLog<S>,
}

impl<S: AuditStore> ComplianceExporter<S> {
    pub fn new(audit_log: AuditLog<S>) -> Self {
        Self { audit_log }
    }

    pub async fn export_soc2(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<SOC2AuditReport> {
        let all_events = self
            .audit_log
            .query(&AuditQuery {
                from_time: Some(from),
                to_time: Some(to),
                ..Default::default()
            })
            .await?;

        let access_controls: Vec<_> = all_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AuditEventType::ApprovalReceived { .. }
                        | AuditEventType::SigningInitiated { .. }
                        | AuditEventType::SigningCompleted { .. }
                )
            })
            .cloned()
            .collect();

        let change_management: Vec<_> = all_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AuditEventType::PolicyCreated { .. }
                        | AuditEventType::PolicyActivated { .. }
                        | AuditEventType::PolicyDeactivated { .. }
                        | AuditEventType::BundleLoaded { .. }
                        | AuditEventType::ConfigurationChanged { .. }
                )
            })
            .cloned()
            .collect();

        let incident_response: Vec<_> = all_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AuditEventType::SigningFailed { .. }
                        | AuditEventType::EscalationTriggered { .. }
                )
            })
            .cloned()
            .collect();

        let chain_verification = self.audit_log.verify_chain(1).await?;

        Ok(SOC2AuditReport {
            period: DateRange { from, to },
            access_controls,
            change_management,
            incident_response,
            chain_verification: chain_verification.into(),
            generated_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_log_record_and_verify() {
        let store = InMemoryAuditStore::new();
        let log = AuditLog::new(store).await.unwrap();

        log.record(
            AuditEventType::SystemStarted {
                version: "1.0.0".into(),
            },
            None,
            ResourceInfo::system(),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::PolicyCreated {
                policy_id: "policy-1".into(),
                version: "1.0.0".into(),
            },
            Some(ActorInfo {
                actor_type: ActorType::User,
                id: "admin".into(),
                ip_address: None,
                user_agent: None,
            }),
            ResourceInfo::policy("policy-1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let verification = log.verify_chain(1).await.unwrap();
        assert!(matches!(
            verification,
            ChainVerification::Valid {
                events_checked: 2,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_audit_query() {
        let store = InMemoryAuditStore::new();
        let log = AuditLog::new(store).await.unwrap();

        log.record(
            AuditEventType::TransactionSubmitted {
                transaction_id: "tx-1".into(),
            },
            None,
            ResourceInfo::transaction("tx-1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::TransactionSubmitted {
                transaction_id: "tx-2".into(),
            },
            None,
            ResourceInfo::transaction("tx-2"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let results = log
            .query(&AuditQuery {
                resource_id: Some("tx-1".into()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
    }
}
