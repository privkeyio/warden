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
    use crate::audit::{ActorInfo, ActorType, AuditEventType, AuditLog, AuditStore, ResourceInfo};
    use crate::workflow::CompletionCallback;
    use chrono::{Duration, Utc};
    use keep_core::frost::SharePackage;
    use keep_frost_net::{KfpNode, PeerPolicy, SessionInfo, SigningHooks};
    use parking_lot::RwLock as ParkingLotRwLock;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tracing::{info, warn};
    use uuid::Uuid;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SigningAuthorization {
        Approved,
        Pending,
        Rejected,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct SigningSessionContext {
        pub workflow_id: Uuid,
        pub transaction_id: Uuid,
        pub authorization: SigningAuthorization,
    }

    pub struct WardenSigningHooks<S: AuditStore + 'static> {
        sessions: Arc<ParkingLotRwLock<HashMap<[u8; 32], SigningSessionContext>>>,
        audit_log: Option<Arc<AuditLog<S>>>,
        callbacks: Arc<ParkingLotRwLock<Vec<Arc<dyn CompletionCallback>>>>,
    }

    impl<S: AuditStore + 'static> Default for WardenSigningHooks<S> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<S: AuditStore + 'static> WardenSigningHooks<S> {
        pub fn new() -> Self {
            Self {
                sessions: Arc::new(ParkingLotRwLock::new(HashMap::new())),
                audit_log: None,
                callbacks: Arc::new(ParkingLotRwLock::new(Vec::new())),
            }
        }

        pub fn with_audit_log(mut self, audit_log: Arc<AuditLog<S>>) -> Self {
            self.audit_log = Some(audit_log);
            self
        }

        pub fn add_callback(&self, callback: Arc<dyn CompletionCallback>) {
            self.callbacks.write().push(callback);
        }

        pub fn authorize_session(
            &self,
            session_id: [u8; 32],
            workflow_id: Uuid,
            transaction_id: Uuid,
        ) {
            self.sessions.write().insert(
                session_id,
                SigningSessionContext {
                    workflow_id,
                    transaction_id,
                    authorization: SigningAuthorization::Approved,
                },
            );
        }

        pub fn revoke_session(&self, session_id: &[u8; 32]) {
            if let Some(ctx) = self.sessions.write().get_mut(session_id) {
                ctx.authorization = SigningAuthorization::Rejected;
            }
        }

        pub fn get_session_context(&self, session_id: &[u8; 32]) -> Option<SigningSessionContext> {
            self.sessions.read().get(session_id).copied()
        }

        pub fn remove_session(&self, session_id: &[u8; 32]) {
            self.sessions.write().remove(session_id);
        }

        fn system_actor() -> ActorInfo {
            ActorInfo {
                actor_type: ActorType::System,
                id: "keep-frost".into(),
                ip_address: None,
                user_agent: None,
            }
        }

        fn audit_pre_sign_failure(
            &self,
            session: &SessionInfo,
            reason: &str,
            workflow_id: Option<Uuid>,
        ) {
            let Some(audit_log) = &self.audit_log else {
                return;
            };
            let audit_log = Arc::clone(audit_log);
            let session_id_hex = hex::encode(session.session_id);
            let reason = reason.to_string();
            let resource = workflow_id
                .map(|id| ResourceInfo::workflow(&id.to_string()))
                .unwrap_or_else(ResourceInfo::system);
            tokio::spawn(async move {
                if let Err(e) = audit_log
                    .record(
                        AuditEventType::SigningFailed {
                            transaction_id: session_id_hex.clone(),
                            error: format!("Pre-sign check failed: {}", reason),
                        },
                        Some(Self::system_actor()),
                        resource,
                        serde_json::json!({
                            "session_id": session_id_hex,
                            "failure_reason": reason,
                            "backend": "keep-frost-kfp"
                        }),
                    )
                    .await
                {
                    warn!(error = %e, "Failed to record signing failure in audit log");
                }
            });
        }

        fn spawn_post_sign_tasks(&self, session: &SessionInfo, signature: &[u8; 64]) {
            let Some(ctx) = self.sessions.read().get(&session.session_id).copied() else {
                return;
            };

            let workflow_id = ctx.workflow_id;
            let session_id_hex = hex::encode(session.session_id);

            if let Some(audit_log) = &self.audit_log {
                let audit_log = Arc::clone(audit_log);
                let transaction_id = ctx.transaction_id;
                let signature_hex = hex::encode(signature);
                let session_id_hex = session_id_hex.clone();
                tokio::spawn(async move {
                    if let Err(e) = audit_log
                        .record(
                            AuditEventType::SigningCompleted {
                                transaction_id: transaction_id.to_string(),
                                txid: signature_hex,
                            },
                            Some(Self::system_actor()),
                            ResourceInfo::workflow(&workflow_id.to_string()),
                            serde_json::json!({
                                "session_id": session_id_hex,
                                "backend": "keep-frost-kfp"
                            }),
                        )
                        .await
                    {
                        warn!(error = %e, "Failed to record signing completion in audit log");
                    }
                });
            }

            let callbacks_snapshot: Vec<_> = self.callbacks.read().iter().cloned().collect();
            let session_id_bytes: [u8; 16] = session.session_id[..16]
                .try_into()
                .expect("slice is exactly 16 bytes");
            let session_id = Uuid::from_bytes(session_id_bytes);
            let signature_copy = *signature;
            let now = Utc::now();
            tokio::spawn(async move {
                let signing_session = SigningSession {
                    session_id,
                    status: SessionStatus::Completed,
                    signature: Some(Signature::Schnorr(signature_copy)),
                    created_at: now,
                    expires_at: now + Duration::hours(1),
                };

                for callback in callbacks_snapshot {
                    if let Err(e) = callback
                        .on_signing_completed(workflow_id, &signing_session)
                        .await
                    {
                        warn!(error = %e, workflow_id = %workflow_id, "Completion callback failed");
                    }
                }
            });
        }
    }

    impl<S: AuditStore + 'static> Clone for WardenSigningHooks<S> {
        fn clone(&self) -> Self {
            Self {
                sessions: Arc::clone(&self.sessions),
                audit_log: self.audit_log.clone(),
                callbacks: Arc::clone(&self.callbacks),
            }
        }
    }

    impl<S: AuditStore + 'static> SigningHooks for WardenSigningHooks<S> {
        fn pre_sign(&self, session: &SessionInfo) -> keep_frost_net::Result<()> {
            let sessions = self.sessions.read();
            let Some(ctx) = sessions.get(&session.session_id) else {
                warn!(
                    session_id = %hex::encode(session.session_id),
                    "Pre-sign: no workflow authorization found for session"
                );
                self.audit_pre_sign_failure(session, "unauthorized", None);
                return Err(keep_frost_net::FrostNetError::PolicyViolation(
                    "No workflow authorization for signing session".into(),
                ));
            };

            if ctx.authorization == SigningAuthorization::Approved {
                info!(
                    workflow_id = %ctx.workflow_id,
                    session_id = %hex::encode(session.session_id),
                    "Pre-sign: workflow approved, proceeding with signing"
                );
                return Ok(());
            }

            let (reason, message) = match ctx.authorization {
                SigningAuthorization::Pending => ("pending", "Workflow approval pending"),
                SigningAuthorization::Rejected => ("rejected", "Workflow rejected"),
                SigningAuthorization::Approved => unreachable!(),
            };

            warn!(
                workflow_id = %ctx.workflow_id,
                "Pre-sign: workflow {}", reason
            );
            self.audit_pre_sign_failure(session, reason, Some(ctx.workflow_id));
            Err(keep_frost_net::FrostNetError::PolicyViolation(
                message.into(),
            ))
        }

        fn post_sign(&self, session: &SessionInfo, signature: &[u8; 64]) {
            info!(
                session_id = %hex::encode(session.session_id),
                signature = %hex::encode(signature),
                "Post-sign: signature generated"
            );
            self.spawn_post_sign_tasks(session, signature);
            self.remove_session(&session.session_id);
        }
    }

    pub struct KeepFrostBackend<S: AuditStore + 'static = crate::audit::InMemoryAuditStore> {
        node: Arc<KfpNode>,
        threshold: u16,
        node_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
        sessions: RwLock<HashMap<SessionId, SigningSession>>,
        signing_hooks: Option<WardenSigningHooks<S>>,
    }

    impl<S: AuditStore + 'static> KeepFrostBackend<S> {
        pub async fn new(share: SharePackage, relays: Vec<String>) -> Result<Self> {
            let threshold = share.metadata.threshold;
            let node = KfpNode::new(share, relays)
                .await
                .map_err(|e| Error::Backend(format!("KfpNode init failed: {}", e)))?;

            Ok(Self {
                node: Arc::new(node),
                threshold,
                node_handle: RwLock::new(None),
                sessions: RwLock::new(HashMap::new()),
                signing_hooks: None,
            })
        }

        pub fn with_signing_hooks(mut self, hooks: WardenSigningHooks<S>) -> Self {
            self.node.set_hooks(Arc::new(hooks.clone()));
            self.signing_hooks = Some(hooks);
            self
        }

        pub fn signing_hooks(&self) -> Option<&WardenSigningHooks<S>> {
            self.signing_hooks.as_ref()
        }

        pub fn authorize_signing(
            &self,
            session_id: [u8; 32],
            workflow_id: Uuid,
            transaction_id: Uuid,
        ) {
            if let Some(hooks) = &self.signing_hooks {
                hooks.authorize_session(session_id, workflow_id, transaction_id);
            }
        }

        pub fn revoke_signing(&self, session_id: &[u8; 32]) {
            if let Some(hooks) = &self.signing_hooks {
                hooks.revoke_session(session_id);
            }
        }

        pub fn set_peer_policy_hex(
            &self,
            pubkey_hex: &str,
            allow_send: bool,
            allow_receive: bool,
        ) -> Result<()> {
            let pk = nostr_sdk::PublicKey::from_hex(pubkey_hex)
                .map_err(|e| Error::InvalidInput(format!("Invalid pubkey hex: {}", e)))?;
            let policy = PeerPolicy::new(pk)
                .allow_send(allow_send)
                .allow_receive(allow_receive);
            self.node.set_peer_policy(policy);
            Ok(())
        }

        pub fn remove_peer_policy(&self, pubkey_hex: &str) -> Result<()> {
            let pk = nostr_sdk::PublicKey::from_hex(pubkey_hex)
                .map_err(|e| Error::InvalidInput(format!("Invalid pubkey hex: {}", e)))?;
            self.node.remove_peer_policy(&pk);
            Ok(())
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

        async fn cleanup_expired_sessions(&self) {
            let now = Utc::now();
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| session.expires_at > now);
        }
    }

    #[async_trait]
    impl<S: AuditStore + 'static> SigningBackend for KeepFrostBackend<S> {
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
            self.cleanup_expired_sessions().await;

            let (message, msg_type) = match &request.payload {
                SigningPayload::Psbt(psbt) => {
                    let mut hasher = Sha256::new();
                    hasher.update(psbt);
                    (hasher.finalize().to_vec(), "psbt")
                }
                SigningPayload::NostrEvent(event) => {
                    let mut hasher = Sha256::new();
                    hasher.update(event.kind.to_be_bytes());
                    hasher.update(event.created_at.to_be_bytes());
                    hasher.update(&event.content);
                    (hasher.finalize().to_vec(), "nostr_event")
                }
                SigningPayload::RawMessage(msg) => (msg.clone(), "raw"),
            };

            let signature = self
                .node
                .request_signature(message, msg_type)
                .await
                .map_err(|e| Error::SigningFailed(e.to_string()))?;

            let now = Utc::now();
            let session = SigningSession {
                session_id: SessionId::new_v4(),
                status: SessionStatus::Completed,
                signature: Some(Signature::Schnorr(signature)),
                created_at: now,
                expires_at: now + Duration::seconds(request.timeout.as_secs() as i64),
            };

            self.sessions
                .write()
                .await
                .insert(session.session_id, session.clone());

            Ok(session)
        }

        async fn get_session(&self, session_id: &SessionId) -> Result<SigningSession> {
            self.sessions
                .read()
                .await
                .get(session_id)
                .cloned()
                .ok_or_else(|| Error::SessionNotFound(session_id.to_string()))
        }

        async fn get_session_status(&self, session_id: &SessionId) -> Result<SessionStatus> {
            self.sessions
                .read()
                .await
                .get(session_id)
                .map(|s| s.status.clone())
                .ok_or_else(|| Error::SessionNotFound(session_id.to_string()))
        }

        async fn get_signature(&self, session_id: &SessionId) -> Result<Signature> {
            let sessions = self.sessions.read().await;
            match sessions.get(session_id) {
                Some(s) => s
                    .signature
                    .clone()
                    .ok_or_else(|| Error::SignatureNotReady(session_id.to_string())),
                None => Err(Error::SessionNotFound(session_id.to_string())),
            }
        }

        async fn cancel_session(&self, session_id: &SessionId) -> Result<()> {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(session_id) {
                session.status = SessionStatus::Cancelled;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "keep")]
pub use implementation::{
    KeepFrostBackend, SigningAuthorization, SigningSessionContext, WardenSigningHooks,
};

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

    async fn get_session(&self, session_id: &SessionId) -> Result<SigningSession> {
        Err(Error::SessionNotFound(session_id.to_string()))
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
