#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::evaluator::TransactionRequest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "keep")]
pub use keep_enclave_host::{
    AttestationVerifier as KeepAttestationVerifier, ExpectedPcrs as KeepExpectedPcrs,
    VerifiedAttestation as KeepVerifiedAttestation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveDecision {
    Allow,
    Deny,
    RequireApproval,
}

pub const VSOCK_PORT: u32 = 5000;
pub const ENCLAVE_CID: u32 = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveRequest {
    Evaluate(EvaluationRequest),
    InitiateSigning(SigningInitRequest),
    GetAttestation { nonce: [u8; 32] },
    LoadBundle(BundleData),
    GetSessionStatus { session_id: String },
    GetSignature { session_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub transaction: TransactionRequest,
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningInitRequest {
    pub transaction_id: String,
    pub psbt: Vec<u8>,
    pub wallet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleData {
    pub manifest_json: Vec<u8>,
    pub files: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveResponse {
    EvaluationResult(EvaluationResult),
    SigningSession(SigningSession),
    Attestation { document: Vec<u8> },
    SessionStatus(SessionStatus),
    Signature { signature: Vec<u8> },
    Ok,
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub decision: EnclaveDecision,
    pub matched_rule_id: Option<String>,
    pub evaluation_time_us: u64,
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    pub session_id: String,
    pub status: SessionStatus,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Pending,
    CollectingShares { collected: u32, required: u32 },
    Signing,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidRequest,
    PolicyDenied,
    RateLimitExceeded,
    KeyNotFound,
    SigningFailed,
    InternalError,
    AttestationFailed,
    BundleVerificationFailed,
}

#[derive(Clone)]
pub struct ExpectedPcrs {
    pub pcr0: [u8; 48],
    pub pcr1: [u8; 48],
    pub pcr2: [u8; 48],
}

impl ExpectedPcrs {
    pub fn new(pcr0: [u8; 48], pcr1: [u8; 48], pcr2: [u8; 48]) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }

    pub fn from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<Self> {
        let parse = |s: &str| -> Result<[u8; 48]> {
            let bytes = hex::decode(s).map_err(|e| Error::Enclave(e.to_string()))?;
            bytes
                .try_into()
                .map_err(|_| Error::Enclave("PCR must be 48 bytes".into()))
        };
        Ok(Self {
            pcr0: parse(pcr0)?,
            pcr1: parse(pcr1)?,
            pcr2: parse(pcr2)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub enclave_pubkey: Vec<u8>,
    pub pcrs: HashMap<u32, Vec<u8>>,
    pub timestamp: u64,
    pub user_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    pub cid: u32,
    pub port: u32,
    pub expected_pcrs: Option<PcrConfig>,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrConfig {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            cid: ENCLAVE_CID,
            port: VSOCK_PORT,
            expected_pcrs: None,
            timeout_seconds: 30,
        }
    }
}

#[async_trait::async_trait]
pub trait EnclaveClient: Send + Sync {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResult>;
    async fn initiate_signing(&self, request: SigningInitRequest) -> Result<SigningSession>;
    async fn get_attestation(&self, nonce: [u8; 32]) -> Result<Vec<u8>>;
    async fn load_bundle(&self, bundle: BundleData) -> Result<()>;
    async fn get_session_status(&self, session_id: &str) -> Result<SessionStatus>;
    async fn get_signature(&self, session_id: &str) -> Result<Vec<u8>>;
    async fn verify_attestation(&self) -> Result<VerifiedAttestation>;
}

pub struct EnclaveProxy {
    config: EnclaveConfig,
    expected_pcrs: Option<ExpectedPcrs>,
    #[cfg(feature = "keep")]
    attestation_verifier: Option<KeepAttestationVerifier>,
}

impl EnclaveProxy {
    pub fn new(config: EnclaveConfig) -> Result<Self> {
        let expected_pcrs = config
            .expected_pcrs
            .as_ref()
            .map(|p| ExpectedPcrs::from_hex(&p.pcr0, &p.pcr1, &p.pcr2))
            .transpose()?;

        #[cfg(feature = "keep")]
        let attestation_verifier = config
            .expected_pcrs
            .as_ref()
            .map(|p| {
                KeepExpectedPcrs::from_hex(&p.pcr0, &p.pcr1, &p.pcr2)
                    .map(|pcrs| KeepAttestationVerifier::new(Some(pcrs)))
            })
            .transpose()
            .map_err(|e| Error::Enclave(format!("Failed to create attestation verifier: {}", e)))?;

        Ok(Self {
            config,
            expected_pcrs,
            #[cfg(feature = "keep")]
            attestation_verifier,
        })
    }

    #[cfg(target_os = "linux")]
    async fn send_request(&self, request: &EnclaveRequest) -> Result<EnclaveResponse> {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        let timeout_duration = Duration::from_secs(self.config.timeout_seconds as u64);

        let request_bytes = serde_json::to_vec(request)
            .map_err(|e| Error::Enclave(format!("Serialization error: {}", e)))?;

        let mut stream = timeout(
            timeout_duration,
            tokio::net::UnixStream::connect(format!(
                "/tmp/vsock-{}-{}",
                self.config.cid, self.config.port
            )),
        )
        .await
        .map_err(|_| Error::Enclave("Connection timeout".into()))?
        .map_err(|e| Error::Enclave(format!("Connection error: {}", e)))?;

        let len = (request_bytes.len() as u32).to_le_bytes();
        timeout(timeout_duration, stream.write_all(&len))
            .await
            .map_err(|_| Error::Enclave("Write timeout".into()))?
            .map_err(|e| Error::Enclave(e.to_string()))?;
        timeout(timeout_duration, stream.write_all(&request_bytes))
            .await
            .map_err(|_| Error::Enclave("Write timeout".into()))?
            .map_err(|e| Error::Enclave(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        timeout(timeout_duration, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| Error::Enclave("Read timeout".into()))?
            .map_err(|e| Error::Enclave(e.to_string()))?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        let mut response_bytes = vec![0u8; response_len];
        timeout(timeout_duration, stream.read_exact(&mut response_bytes))
            .await
            .map_err(|_| Error::Enclave("Read timeout".into()))?
            .map_err(|e| Error::Enclave(e.to_string()))?;

        serde_json::from_slice(&response_bytes)
            .map_err(|e| Error::Enclave(format!("Deserialization error: {}", e)))
    }

    #[cfg(not(target_os = "linux"))]
    async fn send_request(&self, _request: &EnclaveRequest) -> Result<EnclaveResponse> {
        Err(Error::Enclave(
            "Enclave communication only supported on Linux".into(),
        ))
    }
}

#[async_trait::async_trait]
impl EnclaveClient for EnclaveProxy {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResult> {
        match self
            .send_request(&EnclaveRequest::Evaluate(request))
            .await?
        {
            EnclaveResponse::EvaluationResult(result) => Ok(result),
            EnclaveResponse::Error { code, message } => {
                Err(Error::Enclave(format!("{:?}: {}", code, message)))
            }
            _ => Err(Error::Enclave("Unexpected response".into())),
        }
    }

    async fn initiate_signing(&self, request: SigningInitRequest) -> Result<SigningSession> {
        match self
            .send_request(&EnclaveRequest::InitiateSigning(request))
            .await?
        {
            EnclaveResponse::SigningSession(session) => Ok(session),
            EnclaveResponse::Error { code, message } => {
                Err(Error::Enclave(format!("{:?}: {}", code, message)))
            }
            _ => Err(Error::Enclave("Unexpected response".into())),
        }
    }

    async fn get_attestation(&self, nonce: [u8; 32]) -> Result<Vec<u8>> {
        match self
            .send_request(&EnclaveRequest::GetAttestation { nonce })
            .await?
        {
            EnclaveResponse::Attestation { document } => Ok(document),
            EnclaveResponse::Error { code, message } => {
                Err(Error::Enclave(format!("{:?}: {}", code, message)))
            }
            _ => Err(Error::Enclave("Unexpected response".into())),
        }
    }

    async fn load_bundle(&self, bundle: BundleData) -> Result<()> {
        match self
            .send_request(&EnclaveRequest::LoadBundle(bundle))
            .await?
        {
            EnclaveResponse::Ok => Ok(()),
            EnclaveResponse::Error { code, message } => {
                Err(Error::Enclave(format!("{:?}: {}", code, message)))
            }
            _ => Err(Error::Enclave("Unexpected response".into())),
        }
    }

    async fn get_session_status(&self, session_id: &str) -> Result<SessionStatus> {
        match self
            .send_request(&EnclaveRequest::GetSessionStatus {
                session_id: session_id.to_string(),
            })
            .await?
        {
            EnclaveResponse::SessionStatus(status) => Ok(status),
            EnclaveResponse::Error { code, message } => {
                Err(Error::Enclave(format!("{:?}: {}", code, message)))
            }
            _ => Err(Error::Enclave("Unexpected response".into())),
        }
    }

    async fn get_signature(&self, session_id: &str) -> Result<Vec<u8>> {
        match self
            .send_request(&EnclaveRequest::GetSignature {
                session_id: session_id.to_string(),
            })
            .await?
        {
            EnclaveResponse::Signature { signature } => Ok(signature),
            EnclaveResponse::Error { code, message } => {
                Err(Error::Enclave(format!("{:?}: {}", code, message)))
            }
            _ => Err(Error::Enclave("Unexpected response".into())),
        }
    }

    async fn verify_attestation(&self) -> Result<VerifiedAttestation> {
        let nonce: [u8; 32] = rand_bytes();
        let doc = self.get_attestation(nonce).await?;

        if self.expected_pcrs.is_none() {
            tracing::warn!("PCR verification not configured - attestation cannot be verified");
            return Err(Error::Enclave(
                "PCR verification not configured: expected_pcrs is None".into(),
            ));
        }

        #[cfg(feature = "keep")]
        {
            if let Some(ref verifier) = self.attestation_verifier {
                let verified = verifier.verify(&doc, &nonce).map_err(|e| {
                    Error::Enclave(format!("Attestation verification failed: {}", e))
                })?;
                return Ok(VerifiedAttestation {
                    enclave_pubkey: verified.enclave_pubkey,
                    pcrs: verified.pcrs,
                    timestamp: verified.timestamp,
                    user_data: verified.user_data,
                });
            }
        }

        #[cfg(not(feature = "keep"))]
        {
            let _ = doc;
            return Err(Error::Enclave(
                "Full attestation verification requires keep feature".into(),
            ));
        }

        #[cfg(feature = "keep")]
        Err(Error::Enclave("Attestation verifier not configured".into()))
    }
}

fn rand_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes from OS RNG");
    bytes
}

#[cfg(any(test, feature = "mock"))]
pub struct MockEnclaveClient {}

#[cfg(any(test, feature = "mock"))]
impl MockEnclaveClient {
    pub fn new() -> Self {
        tracing::warn!(
            "MockEnclaveClient initialized - this backend always returns Allow and should NEVER be used in production"
        );
        Self {}
    }
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockEnclaveClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "mock"))]
#[async_trait::async_trait]
impl EnclaveClient for MockEnclaveClient {
    async fn evaluate(&self, _request: EvaluationRequest) -> Result<EvaluationResult> {
        Ok(EvaluationResult {
            decision: EnclaveDecision::Allow,
            matched_rule_id: None,
            evaluation_time_us: 100,
            policy_version: "mock-1.0.0".into(),
        })
    }

    async fn initiate_signing(&self, _request: SigningInitRequest) -> Result<SigningSession> {
        Ok(SigningSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            status: SessionStatus::Pending,
            created_at: chrono::Utc::now().timestamp(),
        })
    }

    async fn get_attestation(&self, _nonce: [u8; 32]) -> Result<Vec<u8>> {
        Ok(vec![0u8; 64])
    }

    async fn load_bundle(&self, _bundle: BundleData) -> Result<()> {
        Ok(())
    }

    async fn get_session_status(&self, _session_id: &str) -> Result<SessionStatus> {
        Ok(SessionStatus::Completed)
    }

    async fn get_signature(&self, _session_id: &str) -> Result<Vec<u8>> {
        Ok(vec![0u8; 64])
    }

    async fn verify_attestation(&self) -> Result<VerifiedAttestation> {
        Ok(VerifiedAttestation {
            enclave_pubkey: vec![0u8; 32],
            pcrs: HashMap::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            user_data: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcrs_from_hex() {
        let pcr0 = "0".repeat(96);
        let pcr1 = "1".repeat(96);
        let pcr2 = "2".repeat(96);

        let pcrs = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2).unwrap();
        assert_eq!(pcrs.pcr0[0], 0x00);
        assert_eq!(pcrs.pcr1[0], 0x11);
        assert_eq!(pcrs.pcr2[0], 0x22);
    }

    #[test]
    fn test_enclave_config_default() {
        let config = EnclaveConfig::default();
        assert_eq!(config.cid, ENCLAVE_CID);
        assert_eq!(config.port, VSOCK_PORT);
        assert!(config.expected_pcrs.is_none());
    }

    #[tokio::test]
    async fn test_mock_enclave_client() {
        let client = MockEnclaveClient::new();

        let result = client
            .evaluate(EvaluationRequest {
                transaction: TransactionRequest {
                    id: uuid::Uuid::new_v4(),
                    source_wallet: "wallet-1".into(),
                    destination: "bc1q...".into(),
                    amount_sats: 1000,
                    timestamp: chrono::Utc::now(),
                    metadata: std::collections::HashMap::new(),
                },
                policy_id: None,
            })
            .await
            .unwrap();

        assert_eq!(result.decision, EnclaveDecision::Allow);
    }
}
