#![forbid(unsafe_code)]

use async_trait::async_trait;

#[cfg(feature = "keep")]
use super::SigningPayload;
use super::{
    HealthStatus, PublicKey, SessionId, SessionStatus, Signature, SigningBackend, SigningRequest,
    SigningSession, WalletId,
};
use crate::{Error, Result};

pub struct KeepFrostConfig {
    pub share_path: String,
    pub relays: Vec<String>,
}

#[cfg(feature = "keep")]
mod implementation {
    use super::*;
    use chrono::{Duration, Utc};
    use keep_core::frost::SharePackage;
    use keep_frost_net::KfpNode;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    pub struct KeepFrostBackend {
        node: Arc<KfpNode>,
        threshold: u16,
        node_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
    }

    impl KeepFrostBackend {
        pub async fn new(share: SharePackage, relays: Vec<String>) -> Result<Self> {
            let threshold = share.metadata.threshold;
            let node = KfpNode::new(share, relays)
                .await
                .map_err(|e| Error::Backend(format!("KfpNode init failed: {}", e)))?;

            Ok(Self {
                node: Arc::new(node),
                threshold,
                node_handle: RwLock::new(None),
            })
        }

        pub async fn start(&self) -> Result<()> {
            let node = Arc::clone(&self.node);
            let handle = tokio::spawn(async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "KFP node error");
                }
            });
            *self.node_handle.write().await = Some(handle);
            Ok(())
        }

        pub fn node(&self) -> &Arc<KfpNode> {
            &self.node
        }
    }

    #[async_trait]
    impl SigningBackend for KeepFrostBackend {
        fn backend_id(&self) -> &str {
            "keep-frost-kfp"
        }

        async fn health_check(&self) -> Result<HealthStatus> {
            let online = self.node.online_peers();
            let needed = (self.threshold - 1) as usize;

            if online >= needed {
                Ok(HealthStatus::Healthy)
            } else {
                Ok(HealthStatus::Degraded {
                    reason: format!("Only {}/{} peers online", online, needed),
                })
            }
        }

        async fn get_public_key(&self, _wallet_id: &WalletId) -> Result<PublicKey> {
            let group_pk = self.node.group_pubkey();
            Ok(PublicKey(*group_pk))
        }

        async fn initiate_signing(&self, request: SigningRequest) -> Result<SigningSession> {
            let message = match &request.payload {
                SigningPayload::Psbt(psbt) => {
                    let mut hasher = Sha256::new();
                    hasher.update(psbt);
                    hasher.finalize().to_vec()
                }
                SigningPayload::NostrEvent(event) => {
                    let mut hasher = Sha256::new();
                    hasher.update(event.kind.to_be_bytes());
                    hasher.update(event.created_at.to_be_bytes());
                    hasher.update(&event.content);
                    hasher.finalize().to_vec()
                }
                SigningPayload::RawMessage(msg) => msg.clone(),
            };

            let msg_type = match &request.payload {
                SigningPayload::Psbt(_) => "psbt",
                SigningPayload::NostrEvent(_) => "nostr_event",
                SigningPayload::RawMessage(_) => "raw",
            };

            let signature = self
                .node
                .request_signature(message, msg_type)
                .await
                .map_err(|e| Error::SigningFailed(e.to_string()))?;

            let session_id = SessionId::new_v4();

            Ok(SigningSession {
                session_id,
                status: SessionStatus::Completed,
                signature: Some(Signature::Schnorr(signature)),
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::seconds(request.timeout.as_secs() as i64),
            })
        }

        async fn get_session_status(&self, _session_id: &SessionId) -> Result<SessionStatus> {
            Ok(SessionStatus::Completed)
        }

        async fn get_signature(&self, session_id: &SessionId) -> Result<Signature> {
            Err(Error::SessionNotFound(session_id.to_string()))
        }

        async fn cancel_session(&self, _session_id: &SessionId) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(feature = "keep")]
pub use implementation::KeepFrostBackend;

pub struct StubKeepBackend;

impl StubKeepBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StubKeepBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SigningBackend for StubKeepBackend {
    fn backend_id(&self) -> &str {
        "keep-frost-stub"
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus::Unavailable {
            reason: "Keep integration not enabled (compile with --features keep)".into(),
        })
    }

    async fn get_public_key(&self, _wallet_id: &WalletId) -> Result<PublicKey> {
        Err(Error::Backend("Keep integration not enabled".into()))
    }

    async fn initiate_signing(&self, _request: SigningRequest) -> Result<SigningSession> {
        Err(Error::Backend("Keep integration not enabled".into()))
    }

    async fn get_session_status(&self, session_id: &SessionId) -> Result<SessionStatus> {
        Err(Error::SessionNotFound(session_id.to_string()))
    }

    async fn get_signature(&self, session_id: &SessionId) -> Result<Signature> {
        Err(Error::SessionNotFound(session_id.to_string()))
    }

    async fn cancel_session(&self, session_id: &SessionId) -> Result<()> {
        Err(Error::SessionNotFound(session_id.to_string()))
    }
}
