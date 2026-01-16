#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use nostr_sdk::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::retry::{ClassifyError, ErrorKind, RetryDecision, TieredRetryPolicy};

const JTI_CACHE_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackRequest {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub request_type: String,
    pub transaction: TransactionDetails,
    pub policy_context: PolicyContext,
    pub callback_config: CallbackConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetails {
    pub id: String,
    pub source_wallet: String,
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub policy_id: String,
    pub policy_version: String,
    pub matched_rule_id: Option<String>,
    pub evaluation_trace: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallbackConfig {
    pub timeout_seconds: Option<u32>,
    pub include_metadata: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackResponse {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub jti: String,
    pub decision: CallbackDecision,
    pub reason: Option<String>,
    pub metadata: HashMap<String, Value>,
    pub retry_after_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallbackDecision {
    Approve,
    Reject,
    Retry,
}

#[derive(Debug, Clone)]
pub struct CallbackResult {
    pub decision: CallbackDecision,
    pub reason: Option<String>,
    pub metadata: HashMap<String, Value>,
    pub handler_id: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackHandlerConfig {
    pub id: String,
    pub url: String,
    pub public_key: Option<String>,
    pub timeout_seconds: u32,
    pub enabled: bool,
}

impl Default for CallbackHandlerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            url: String::new(),
            public_key: None,
            timeout_seconds: 30,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CallbackError {
    #[error("Handler not found: {0}")]
    HandlerNotFound(String),
    #[error("Handler disabled: {0}")]
    HandlerDisabled(String),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("Timeout")]
    Timeout,
    #[error("JTI mismatch")]
    JtiMismatch,
    #[error("JTI replay detected")]
    JtiReplay,
    #[error("Invalid audience")]
    InvalidAudience,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Max retries exceeded")]
    MaxRetriesExceeded,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl ClassifyError for CallbackError {
    fn error_kind(&self) -> ErrorKind {
        match self {
            Self::Timeout => ErrorKind::Timeout,
            Self::HttpError(msg) if msg.contains("429") => ErrorKind::RateLimited,
            Self::HttpError(_) => ErrorKind::Transient,
            Self::HandlerNotFound(_) => ErrorKind::NotFound,
            Self::HandlerDisabled(_) => ErrorKind::Permanent,
            Self::JtiMismatch => ErrorKind::InvalidArgument,
            Self::InvalidAudience => ErrorKind::InvalidArgument,
            Self::InvalidSignature => ErrorKind::Unauthorized,
            Self::MaxRetriesExceeded => ErrorKind::Permanent,
            Self::SerializationError(_) => ErrorKind::InvalidArgument,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

pub struct JwsVerifier {
    secp: Secp256k1<nostr_sdk::secp256k1::All>,
}

impl JwsVerifier {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    pub fn verify(&self, jws_token: &str, public_key_hex: &str) -> Result<String, CallbackError> {
        let parts: Vec<&str> = jws_token.split('.').collect();
        if parts.len() != 3 {
            return Err(CallbackError::InvalidSignature);
        }

        let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| CallbackError::InvalidSignature)?;

        let header: JwsHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| CallbackError::InvalidSignature)?;

        if header.alg != "ES256K-SR" {
            return Err(CallbackError::InvalidSignature);
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| CallbackError::InvalidSignature)?;

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| CallbackError::InvalidSignature)?;

        let public_key_bytes =
            hex::decode(public_key_hex).map_err(|_| CallbackError::InvalidSignature)?;

        let public_key = XOnlyPublicKey::from_slice(&public_key_bytes)
            .map_err(|_| CallbackError::InvalidSignature)?;

        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| CallbackError::InvalidSignature)?;

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let hash = Sha256::digest(signing_input.as_bytes());
        let message = Message::from_digest(hash.into());

        self.secp
            .verify_schnorr(&signature, &message, &public_key)
            .map_err(|_| CallbackError::InvalidSignature)?;

        String::from_utf8(payload_bytes).map_err(|_| CallbackError::InvalidSignature)
    }
}

impl Default for JwsVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CallbackJtiCache {
    entries: RwLock<HashMap<String, i64>>,
    max_entries: usize,
}

impl CallbackJtiCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn check_and_insert(&self, jti: &str, exp: i64) -> bool {
        let now = Utc::now().timestamp();

        let mut entries = self.entries.write();

        if entries.len() > self.max_entries / 2 {
            entries.retain(|_, &mut exp_time| exp_time > now);
        }

        if entries.contains_key(jti) {
            return false;
        }

        if entries.len() >= self.max_entries {
            return false;
        }

        entries.insert(jti.to_string(), exp);
        true
    }

    pub fn contains(&self, jti: &str) -> bool {
        self.entries.read().contains_key(jti)
    }
}

pub struct CallbackGateway {
    http_client: reqwest::Client,
    handlers: HashMap<String, CallbackHandlerConfig>,
    retry_policy: TieredRetryPolicy,
    jws_verifier: JwsVerifier,
    jti_cache: Arc<CallbackJtiCache>,
}

impl CallbackGateway {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
            handlers: HashMap::new(),
            retry_policy: TieredRetryPolicy::default(),
            jws_verifier: JwsVerifier::new(),
            jti_cache: Arc::new(CallbackJtiCache::new(10000)),
        }
    }

    pub fn with_handler(mut self, config: CallbackHandlerConfig) -> Self {
        self.handlers.insert(config.id.clone(), config);
        self
    }

    pub fn with_retry_policy(mut self, policy: TieredRetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    pub fn register_handler(&mut self, config: CallbackHandlerConfig) {
        self.handlers.insert(config.id.clone(), config);
    }

    pub fn remove_handler(&mut self, handler_id: &str) {
        self.handlers.remove(handler_id);
    }

    pub async fn invoke(
        &self,
        handler_id: &str,
        transaction: &TransactionDetails,
        policy_context: &PolicyContext,
    ) -> std::result::Result<CallbackResult, CallbackError> {
        let handler = self
            .handlers
            .get(handler_id)
            .ok_or_else(|| CallbackError::HandlerNotFound(handler_id.to_string()))?;

        if !handler.enabled {
            return Err(CallbackError::HandlerDisabled(handler_id.to_string()));
        }

        let request = CallbackRequest {
            iss: "warden".into(),
            aud: handler_id.into(),
            iat: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 60,
            jti: Uuid::new_v4().to_string(),
            request_type: "transaction_authorization".into(),
            transaction: transaction.clone(),
            policy_context: policy_context.clone(),
            callback_config: CallbackConfig::default(),
        };

        let request_json = serde_json::to_string(&request)
            .map_err(|e| CallbackError::SerializationError(e.to_string()))?;

        let mut attempt = 0u32;

        loop {
            let start = std::time::Instant::now();

            match self
                .send_request(handler, &request_json, &request.jti)
                .await
            {
                Ok(response) => {
                    return Ok(CallbackResult {
                        decision: response.decision,
                        reason: response.reason,
                        metadata: response.metadata,
                        handler_id: handler_id.into(),
                        latency_ms: start.elapsed().as_millis() as u64,
                    });
                }
                Err(e) => {
                    let error_kind = e.error_kind();
                    match self.retry_policy.should_retry(error_kind, attempt) {
                        RetryDecision::Retry { after } => {
                            attempt += 1;
                            tokio::time::sleep(after).await;
                        }
                        RetryDecision::Abort => return Err(e),
                    }
                }
            }
        }
    }

    async fn send_request(
        &self,
        handler: &CallbackHandlerConfig,
        request_json: &str,
        expected_jti: &str,
    ) -> std::result::Result<CallbackResponse, CallbackError> {
        let timeout = Duration::from_secs(handler.timeout_seconds as u64);

        let response = self
            .http_client
            .post(&handler.url)
            .header("Content-Type", "application/json")
            .header("X-Warden-Request-Id", expected_jti)
            .body(request_json.to_owned())
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    CallbackError::Timeout
                } else {
                    CallbackError::HttpError(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            return Err(CallbackError::HttpError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| CallbackError::HttpError(e.to_string()))?;

        let payload_json = match &handler.public_key {
            Some(public_key) => self.jws_verifier.verify(&response_text, public_key)?,
            None => response_text,
        };

        let callback_response: CallbackResponse = serde_json::from_str(&payload_json)
            .map_err(|e| CallbackError::SerializationError(e.to_string()))?;

        if callback_response.jti != expected_jti {
            return Err(CallbackError::JtiMismatch);
        }

        if callback_response.aud != "warden" {
            return Err(CallbackError::InvalidAudience);
        }

        let cache_expiry = Utc::now().timestamp() + JTI_CACHE_TTL_SECONDS;
        if !self
            .jti_cache
            .check_and_insert(&callback_response.jti, cache_expiry)
        {
            return Err(CallbackError::JtiReplay);
        }

        Ok(callback_response)
    }

    pub fn list_handlers(&self) -> Vec<&CallbackHandlerConfig> {
        self.handlers.values().collect()
    }

    pub fn get_handler(&self, id: &str) -> Option<&CallbackHandlerConfig> {
        self.handlers.get(id)
    }
}

impl Default for CallbackGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackRuleConfig {
    pub handler: String,
    pub on_approve: CallbackAction,
    pub on_reject: CallbackAction,
    pub on_timeout: CallbackAction,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallbackAction {
    Allow,
    Deny,
    RequireApproval,
}

impl Default for CallbackRuleConfig {
    fn default() -> Self {
        Self {
            handler: String::new(),
            on_approve: CallbackAction::Allow,
            on_reject: CallbackAction::Deny,
            on_timeout: CallbackAction::RequireApproval,
            timeout_seconds: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::secp256k1::{Keypair, SecretKey};

    fn create_test_jws(payload: &str, secret_key: &SecretKey) -> String {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);

        let header = JwsHeader {
            alg: "ES256K-SR".into(),
            kid: None,
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let hash = Sha256::digest(signing_input.as_bytes());
        let message = Message::from_digest(hash.into());
        let signature = secp.sign_schnorr(&message, &keypair);

        format!(
            "{}.{}.{}",
            header_b64,
            payload_b64,
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    #[test]
    fn test_jws_verify_valid_signature() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (public_key, _) = keypair.x_only_public_key();
        let public_key_hex = hex::encode(public_key.serialize());

        let payload = r#"{"decision":"APPROVE","jti":"test-123"}"#;
        let jws = create_test_jws(payload, &secret_key);

        let verifier = JwsVerifier::new();
        let result = verifier.verify(&jws, &public_key_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_jws_verify_wrong_public_key() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let wrong_secret_key = SecretKey::from_slice(&[0x43; 32]).unwrap();
        let wrong_keypair = Keypair::from_secret_key(&secp, &wrong_secret_key);
        let (wrong_public_key, _) = wrong_keypair.x_only_public_key();
        let wrong_public_key_hex = hex::encode(wrong_public_key.serialize());

        let payload = r#"{"decision":"APPROVE"}"#;
        let jws = create_test_jws(payload, &secret_key);

        let verifier = JwsVerifier::new();
        let result = verifier.verify(&jws, &wrong_public_key_hex);
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));
    }

    #[test]
    fn test_jws_verify_tampered_payload() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (public_key, _) = keypair.x_only_public_key();
        let public_key_hex = hex::encode(public_key.serialize());

        let payload = r#"{"decision":"APPROVE"}"#;
        let jws = create_test_jws(payload, &secret_key);

        let mut parts: Vec<&str> = jws.split('.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(r#"{"decision":"REJECT"}"#.as_bytes());
        parts[1] = &tampered_payload;
        let tampered_jws = parts.join(".");

        let verifier = JwsVerifier::new();
        let result = verifier.verify(&tampered_jws, &public_key_hex);
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));
    }

    #[test]
    fn test_jws_verify_invalid_format() {
        let verifier = JwsVerifier::new();

        let result = verifier.verify("not.a.valid.jws.token", "deadbeef");
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));

        let result = verifier.verify("only-one-part", "deadbeef");
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));

        let result = verifier.verify("..", &hex::encode([0u8; 32]));
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));
    }

    #[test]
    fn test_jws_verify_invalid_algorithm() {
        let header = JwsHeader {
            alg: "RS256".into(),
            kid: None,
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"test");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);

        let jws = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

        let verifier = JwsVerifier::new();
        let result = verifier.verify(&jws, &hex::encode([0u8; 32]));
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));
    }

    #[test]
    fn test_jws_verify_invalid_public_key_hex() {
        let secret_key = SecretKey::from_slice(&[0x42; 32]).unwrap();

        let payload = r#"{"decision":"APPROVE"}"#;
        let jws = create_test_jws(payload, &secret_key);

        let verifier = JwsVerifier::new();
        let result = verifier.verify(&jws, "not-valid-hex");
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));

        let result = verifier.verify(&jws, "deadbeef");
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));
    }

    #[test]
    fn test_jws_verify_tampered_header() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (public_key, _) = keypair.x_only_public_key();
        let public_key_hex = hex::encode(public_key.serialize());

        let payload = r#"{"decision":"APPROVE"}"#;
        let jws = create_test_jws(payload, &secret_key);

        let tampered_header = JwsHeader {
            alg: "RS256".into(),
            kid: None,
        };
        let tampered_header_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&tampered_header).unwrap().as_bytes());

        let mut parts: Vec<&str> = jws.split('.').collect();
        parts[0] = &tampered_header_b64;
        let tampered_jws = parts.join(".");

        let verifier = JwsVerifier::new();
        let result = verifier.verify(&tampered_jws, &public_key_hex);
        assert!(matches!(result, Err(CallbackError::InvalidSignature)));
    }

    #[test]
    fn test_callback_decision_serialization() {
        let approve = CallbackDecision::Approve;
        let json = serde_json::to_string(&approve).unwrap();
        assert_eq!(json, "\"APPROVE\"");

        let reject = CallbackDecision::Reject;
        let json = serde_json::to_string(&reject).unwrap();
        assert_eq!(json, "\"REJECT\"");
    }

    #[test]
    fn test_callback_error_retryable() {
        assert!(ClassifyError::is_retryable(&CallbackError::Timeout));
        assert!(ClassifyError::is_retryable(&CallbackError::HttpError(
            "connection failed".into()
        )));
        assert!(!ClassifyError::is_retryable(&CallbackError::JtiMismatch));
        assert!(!ClassifyError::is_retryable(&CallbackError::JtiReplay));
        assert!(!ClassifyError::is_retryable(
            &CallbackError::InvalidAudience
        ));
        assert!(!ClassifyError::is_retryable(
            &CallbackError::InvalidSignature
        ));
    }

    #[test]
    fn test_callback_handler_config_default() {
        let config = CallbackHandlerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_callback_jti_cache_replay_prevention() {
        let cache = CallbackJtiCache::new(100);
        let jti = "callback-jti-12345";
        let exp = Utc::now().timestamp() + 300;

        assert!(cache.check_and_insert(jti, exp));
        assert!(!cache.check_and_insert(jti, exp));
        assert!(cache.contains(jti));
    }

    #[test]
    fn test_callback_jti_cache_expiration_cleanup() {
        let cache = CallbackJtiCache::new(4);
        let past_exp = Utc::now().timestamp() - 100;
        let future_exp = Utc::now().timestamp() + 300;

        cache.check_and_insert("expired-1", past_exp);
        cache.check_and_insert("expired-2", past_exp);
        cache.check_and_insert("valid-1", future_exp);

        assert!(cache.check_and_insert("new-jti", future_exp));
        assert!(!cache.contains("expired-1"));
        assert!(!cache.contains("expired-2"));
        assert!(cache.contains("valid-1"));
    }
}
