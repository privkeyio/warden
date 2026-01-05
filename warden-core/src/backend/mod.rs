#![forbid(unsafe_code)]

mod keep;

use async_trait::async_trait;
#[cfg(any(test, feature = "mock"))]
use chrono::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::{Error, Result};

#[cfg(feature = "keep")]
pub use keep::KeepFrostBackend;
pub use keep::{KeepFrostConfig, StubKeepBackend};

pub type SessionId = Uuid;
pub type WalletId = String;
pub type TransactionId = Uuid;
pub type SignerId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Pending,
    CollectingShares { collected: u32, required: u32 },
    Signing,
    Completed,
    Failed { reason: String },
    Cancelled,
    Expired,
}

#[derive(Debug, Clone)]
pub enum SigningPayload {
    Psbt(Vec<u8>),
    NostrEvent(UnsignedNostrEvent),
    RawMessage(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct UnsignedNostrEvent {
    pub kind: u32,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct SigningRequest {
    pub transaction_id: TransactionId,
    pub wallet_id: WalletId,
    pub payload: SigningPayload,
    pub required_signers: Vec<SignerId>,
    pub timeout: std::time::Duration,
    pub metadata: SigningMetadata,
}

#[derive(Debug, Clone, Default)]
pub struct SigningMetadata {
    pub nip46_session: Option<String>,
    pub kfp_channel: Option<String>,
    pub requires_mobile: bool,
}

#[derive(Debug, Clone)]
pub struct SigningSession {
    pub session_id: SessionId,
    pub status: SessionStatus,
    pub signature: Option<Signature>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum Signature {
    Schnorr([u8; 64]),
    Ecdsa(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct PublicKey(pub [u8; 32]);

#[async_trait]
pub trait SigningBackend: Send + Sync {
    fn backend_id(&self) -> &str;
    async fn health_check(&self) -> Result<HealthStatus>;
    async fn get_public_key(&self, wallet_id: &WalletId) -> Result<PublicKey>;
    async fn initiate_signing(&self, request: SigningRequest) -> Result<SigningSession>;
    async fn get_session(&self, session_id: &SessionId) -> Result<SigningSession>;
    async fn get_session_status(&self, session_id: &SessionId) -> Result<SessionStatus>;
    async fn get_signature(&self, session_id: &SessionId) -> Result<Signature>;
    async fn cancel_session(&self, session_id: &SessionId) -> Result<()>;
}

pub struct BackendRegistry {
    backends: RwLock<HashMap<String, Arc<dyn SigningBackend>>>,
    default_backend: RwLock<String>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(HashMap::new()),
            default_backend: RwLock::new(String::new()),
        }
    }

    pub fn register(&self, backend: Arc<dyn SigningBackend>) {
        let id = backend.backend_id().to_string();
        let mut backends = self.backends.write().expect("lock poisoned");
        let is_first = backends.is_empty();
        backends.insert(id.clone(), backend);
        if is_first {
            *self.default_backend.write().expect("lock poisoned") = id;
        }
    }

    pub fn set_default(&self, id: &str) -> Result<()> {
        let backends = self.backends.read().expect("lock poisoned");
        if !backends.contains_key(id) {
            return Err(Error::Backend(format!("backend '{}' not found", id)));
        }
        *self.default_backend.write().expect("lock poisoned") = id.to_string();
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn SigningBackend>> {
        self.backends
            .read()
            .expect("lock poisoned")
            .get(id)
            .cloned()
    }

    pub fn get_default(&self) -> Result<Arc<dyn SigningBackend>> {
        let default_id = self.default_backend.read().expect("lock poisoned").clone();
        if default_id.is_empty() {
            return Err(Error::Backend("no backends registered".into()));
        }
        self.get(&default_id)
            .ok_or_else(|| Error::Backend("default backend not found".into()))
    }

    pub fn list(&self) -> Vec<String> {
        self.backends
            .read()
            .expect("lock poisoned")
            .keys()
            .cloned()
            .collect()
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "mock"))]
pub struct MockSigningBackend {
    sessions: RwLock<HashMap<SessionId, SigningSession>>,
}

#[cfg(any(test, feature = "mock"))]
impl MockSigningBackend {
    pub fn new() -> Self {
        tracing::warn!(
            "MockSigningBackend initialized - this backend always succeeds and should NEVER be used in production"
        );
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockSigningBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "mock"))]
#[async_trait]
impl SigningBackend for MockSigningBackend {
    fn backend_id(&self) -> &str {
        "mock"
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus::Healthy)
    }

    async fn get_public_key(&self, _wallet_id: &WalletId) -> Result<PublicKey> {
        Ok(PublicKey([0u8; 32]))
    }

    async fn initiate_signing(&self, request: SigningRequest) -> Result<SigningSession> {
        let session = SigningSession {
            session_id: SessionId::new_v4(),
            status: SessionStatus::Pending,
            signature: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(request.timeout.as_secs() as i64),
        };
        self.sessions
            .write()
            .expect("lock poisoned")
            .insert(session.session_id, session.clone());
        Ok(session)
    }

    async fn get_session(&self, session_id: &SessionId) -> Result<SigningSession> {
        self.sessions
            .read()
            .expect("lock poisoned")
            .get(session_id)
            .cloned()
            .ok_or_else(|| Error::SessionNotFound(session_id.to_string()))
    }

    async fn get_session_status(&self, session_id: &SessionId) -> Result<SessionStatus> {
        self.sessions
            .read()
            .expect("lock poisoned")
            .get(session_id)
            .map(|s| s.status.clone())
            .ok_or_else(|| Error::SessionNotFound(session_id.to_string()))
    }

    async fn get_signature(&self, session_id: &SessionId) -> Result<Signature> {
        let sessions = self.sessions.read().expect("lock poisoned");
        match sessions.get(session_id) {
            Some(s) => s
                .signature
                .clone()
                .ok_or_else(|| Error::SignatureNotReady(session_id.to_string())),
            None => Err(Error::SessionNotFound(session_id.to_string())),
        }
    }

    async fn cancel_session(&self, session_id: &SessionId) -> Result<()> {
        let mut sessions = self.sessions.write().expect("lock poisoned");
        match sessions.get_mut(session_id) {
            Some(session) => {
                session.status = SessionStatus::Cancelled;
                Ok(())
            }
            None => Err(Error::SessionNotFound(session_id.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backend_registry() {
        let registry = BackendRegistry::new();
        let mock = Arc::new(MockSigningBackend::new());
        registry.register(mock);
        assert!(registry.get("mock").is_some());
        assert!(registry.get_default().is_ok());
    }

    #[tokio::test]
    async fn test_mock_signing() {
        let backend = MockSigningBackend::new();
        let request = SigningRequest {
            transaction_id: Uuid::new_v4(),
            wallet_id: "test".into(),
            payload: SigningPayload::RawMessage(vec![0; 32]),
            required_signers: vec![],
            timeout: std::time::Duration::from_secs(60),
            metadata: SigningMetadata::default(),
        };
        let session = backend.initiate_signing(request).await.unwrap();
        assert_eq!(session.status, SessionStatus::Pending);
    }
}
