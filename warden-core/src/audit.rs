#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::secrets::SecretRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

pub type Hash = [u8; 32];
pub type Signature = [u8; 64];

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
    #[serde(with = "hex_serde")]
    pub signature: Signature,
    #[serde(with = "hex_serde")]
    pub signer_pubkey: [u8; 32],
    pub rfc3161_token: Option<Rfc3161Token>,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte array length"))
    }
}

/// RFC 3161 timestamp token from a Time Stamping Authority (TSA).
///
/// This token proves that the associated hash existed at `timestamp`.
/// The `token` field contains the raw ASN.1 DER-encoded TimeStampResp.
///
/// **Note**: The token is stored but not validated. For production use,
/// consider verifying the TSA signature and that the token contains the
/// expected hash. See RFC 3161 section 2.4 for validation requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc3161Token {
    pub tsa_url: String,
    pub timestamp: DateTime<Utc>,
    #[serde(with = "base64_serde")]
    pub token: Vec<u8>,
}

mod base64_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
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
    InvalidSignature {
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

    async fn verify_append_only(&self, event: &AuditEvent) -> Result<()> {
        let latest_seq = self.get_latest_sequence().await.unwrap_or(0);
        if event.sequence != latest_seq + 1 {
            return Err(Error::Audit(format!(
                "append-only violation: expected sequence {}, got {}",
                latest_seq + 1,
                event.sequence
            )));
        }
        if latest_seq > 0 {
            let prev = self.get_event(latest_seq).await?;
            if event.previous_hash != prev.hash {
                return Err(Error::Audit(
                    "append-only violation: previous_hash mismatch".into(),
                ));
            }
        }
        Ok(())
    }
}

pub trait AuditSigner: Send + Sync {
    fn sign(&self, hash: &Hash) -> Result<Signature>;
    fn verify(&self, hash: &Hash, signature: &Signature, pubkey: &[u8; 32]) -> Result<bool>;
    fn public_key(&self) -> [u8; 32];
}

#[derive(Clone)]
pub struct Secp256k1AuditSigner {
    keys: nostr_sdk::Keys,
}

impl Secp256k1AuditSigner {
    pub fn new(secret_key: &str) -> Result<Self> {
        let sk = nostr_sdk::SecretKey::parse(secret_key)
            .map_err(|e| Error::Audit(format!("invalid secret key: {}", e)))?;
        Ok(Self {
            keys: nostr_sdk::Keys::new(sk),
        })
    }

    pub fn generate() -> Self {
        Self {
            keys: nostr_sdk::Keys::generate(),
        }
    }

    pub fn public_key_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }
}

impl AuditSigner for Secp256k1AuditSigner {
    fn sign(&self, hash: &Hash) -> Result<Signature> {
        use nostr_sdk::secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let msg = Message::from_digest(*hash);
        let keypair = self.keys.secret_key().keypair(&secp);
        let sig = secp.sign_schnorr(&msg, &keypair);
        Ok(*sig.as_ref())
    }

    fn verify(&self, hash: &Hash, signature: &Signature, pubkey: &[u8; 32]) -> Result<bool> {
        use nostr_sdk::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};

        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(*hash);
        let sig = schnorr::Signature::from_slice(signature)
            .map_err(|e| Error::Audit(format!("invalid signature format: {}", e)))?;
        let pk = XOnlyPublicKey::from_slice(pubkey)
            .map_err(|e| Error::Audit(format!("invalid public key: {}", e)))?;

        Ok(secp.verify_schnorr(&sig, &msg, &pk).is_ok())
    }

    fn public_key(&self) -> [u8; 32] {
        use nostr_sdk::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let keypair = self.keys.secret_key().keypair(&secp);
        let (xonly, _parity) = keypair.x_only_public_key();
        xonly.serialize()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSignerConfig {
    pub secret_key: SecretRef,
    pub rfc3161_tsa_url: Option<String>,
}

impl Default for AuditSignerConfig {
    fn default() -> Self {
        Self {
            secret_key: SecretRef::Env {
                name: "WARDEN_AUDIT_SIGNING_KEY".into(),
            },
            rfc3161_tsa_url: None,
        }
    }
}

impl AuditSignerConfig {
    /// Build a signer from this configuration using the provided secrets provider.
    pub async fn build_signer(
        &self,
        provider: &dyn crate::secrets::SecretsProvider,
    ) -> Result<Secp256k1AuditSigner> {
        let secret = provider
            .get(&self.secret_key)
            .await
            .map_err(|e| Error::Audit(format!("failed to fetch signing key: {}", e)))?;
        Secp256k1AuditSigner::new(secret.expose())
    }
}

/// Client for RFC 3161 Time Stamping Authority (TSA) requests.
///
/// This client sends hash values to a TSA and receives signed timestamps
/// that prove the hash existed at a specific time. This is useful for
/// audit log integrity verification.
///
/// **Limitations**:
/// - The response is stored but not cryptographically validated
/// - For production, the TSA certificate chain should be verified
/// - Consider using a trusted TSA (e.g., DigiCert, Entrust, FreeTSA)
pub struct Rfc3161Client {
    tsa_url: String,
    client: reqwest::Client,
}

impl Rfc3161Client {
    pub fn new(tsa_url: String) -> Self {
        Self {
            tsa_url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn timestamp(&self, hash: &Hash) -> Result<Rfc3161Token> {
        let request_body = self.build_timestamp_request(hash);

        let response = self
            .client
            .post(&self.tsa_url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| Error::Audit(format!("TSA request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Audit(format!(
                "TSA returned error: {}",
                response.status()
            )));
        }

        let token = response
            .bytes()
            .await
            .map_err(|e| Error::Audit(format!("Failed to read TSA response: {}", e)))?;

        Ok(Rfc3161Token {
            tsa_url: self.tsa_url.clone(),
            timestamp: Utc::now(),
            token: token.to_vec(),
        })
    }

    fn build_timestamp_request(&self, hash: &Hash) -> Vec<u8> {
        #[rustfmt::skip]
        const ASN1_HEADER: [u8; 24] = [
            0x30, 0x39,                                                 // SEQUENCE (TimeStampReq), len 57
            0x02, 0x01, 0x01,                                           // INTEGER version = 1
            0x30, 0x31,                                                 // SEQUENCE (MessageImprint), len 49
            0x30, 0x0d,                                                 // SEQUENCE (AlgorithmIdentifier), len 13
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID SHA-256
            0x05, 0x00,                                                 // NULL parameters
            0x04, 0x20,                                                 // OCTET STRING, len 32
        ];
        const ASN1_FOOTER: [u8; 3] = [0x01, 0x01, 0xff]; // BOOLEAN certReq = TRUE

        let mut request = Vec::with_capacity(59);
        request.extend_from_slice(&ASN1_HEADER);
        request.extend_from_slice(hash);
        request.extend_from_slice(&ASN1_FOOTER);
        request
    }
}

pub struct AuditLog<S: AuditStore, T: AuditSigner = Secp256k1AuditSigner> {
    store: S,
    signer: Arc<T>,
    sequence: AtomicU64,
    last_hash: RwLock<Hash>,
    record_mutex: Mutex<()>,
    tsa_client: Option<Rfc3161Client>,
}

impl<S: AuditStore> AuditLog<S, Secp256k1AuditSigner> {
    pub async fn new(store: S, signer: Secp256k1AuditSigner) -> Result<Self> {
        Self::with_signer(store, signer).await
    }
}

impl<S: AuditStore, T: AuditSigner> AuditLog<S, T> {
    pub async fn with_signer(store: S, signer: T) -> Result<Self> {
        let sequence = store.get_latest_sequence().await.unwrap_or(0);
        let last_hash = store.get_latest_hash().await.unwrap_or([0u8; 32]);

        Ok(Self {
            store,
            signer: Arc::new(signer),
            sequence: AtomicU64::new(sequence),
            last_hash: RwLock::new(last_hash),
            record_mutex: Mutex::new(()),
            tsa_client: None,
        })
    }

    pub fn with_tsa(mut self, tsa_url: String) -> Self {
        self.tsa_client = Some(Rfc3161Client::new(tsa_url));
        self
    }

    pub fn signer_public_key(&self) -> [u8; 32] {
        self.signer.public_key()
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
            signature: [0u8; 64],
            signer_pubkey: self.signer.public_key(),
            rfc3161_token: None,
        };

        event.hash = self.compute_hash(&event)?;
        event.signature = self.signer.sign(&event.hash)?;

        if let Some(ref tsa) = self.tsa_client {
            event.rfc3161_token = tsa.timestamp(&event.hash).await.ok();
        }

        self.store.verify_append_only(&event).await?;
        self.store.append(&event).await?;

        *self.last_hash.write().await = event.hash;

        Ok(event.id)
    }

    fn compute_hash(&self, event: &AuditEvent) -> Result<Hash> {
        fn hash_json<T: Serialize>(hasher: &mut Sha256, value: &T) -> Result<()> {
            let bytes =
                serde_json::to_vec(value).map_err(|e| Error::Serialization(e.to_string()))?;
            hasher.update(&bytes);
            Ok(())
        }

        let mut hasher = Sha256::new();
        hasher.update(event.id.as_bytes());
        hasher.update(event.sequence.to_le_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        hash_json(&mut hasher, &event.event_type)?;
        if let Some(ref actor) = event.actor {
            hash_json(&mut hasher, actor)?;
        }
        hash_json(&mut hasher, &event.resource)?;
        hash_json(&mut hasher, &event.details)?;
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

            if !self
                .signer
                .verify(&event.hash, &event.signature, &event.signer_pubkey)?
            {
                return Ok(ChainVerification::InvalidSignature {
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

impl ChainVerificationReport {
    fn error_at(kind: &str, at_sequence: u64) -> Self {
        Self {
            status: format!("{} at sequence {}", kind, at_sequence),
            events_checked: 0,
            last_sequence: at_sequence,
        }
    }
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
            ChainVerification::Broken { at_sequence, .. } => Self::error_at("broken", at_sequence),
            ChainVerification::Tampered { at_sequence } => Self::error_at("tampered", at_sequence),
            ChainVerification::InvalidSignature { at_sequence } => {
                Self::error_at("invalid signature", at_sequence)
            }
        }
    }
}

pub struct ComplianceExporter<S: AuditStore, T: AuditSigner = Secp256k1AuditSigner> {
    audit_log: AuditLog<S, T>,
}

impl<S: AuditStore, T: AuditSigner> ComplianceExporter<S, T> {
    pub fn new(audit_log: AuditLog<S, T>) -> Self {
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
        let signer = Secp256k1AuditSigner::generate();
        let log = AuditLog::new(store, signer).await.unwrap();

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
        let signer = Secp256k1AuditSigner::generate();
        let log = AuditLog::new(store, signer).await.unwrap();

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

    #[tokio::test]
    async fn test_signature_verification() {
        let store = InMemoryAuditStore::new();
        let signer = Secp256k1AuditSigner::generate();
        let pubkey = signer.public_key();
        let log = AuditLog::new(store, signer).await.unwrap();

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

        let events = log.query(&AuditQuery::default()).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signer_pubkey, pubkey);
        assert_ne!(events[0].signature, [0u8; 64]);
    }

    #[test]
    fn test_signer_roundtrip() {
        let signer = Secp256k1AuditSigner::generate();
        let hash: Hash = [42u8; 32];

        let signature = signer.sign(&hash).unwrap();
        let pubkey = signer.public_key();

        assert!(signer.verify(&hash, &signature, &pubkey).unwrap());

        let wrong_hash: Hash = [0u8; 32];
        assert!(!signer.verify(&wrong_hash, &signature, &pubkey).unwrap());
    }

    #[test]
    fn test_signer_from_secret_key() {
        let signer = Secp256k1AuditSigner::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let pubkey_hex = signer.public_key_hex();
        assert!(!pubkey_hex.is_empty());
    }
}
