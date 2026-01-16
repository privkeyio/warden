#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::secrets::SecretRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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
/// The `timestamp` field contains the TSA-provided genTime extracted from
/// the validated TSTInfo structure.
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

mod oid {
    use der::oid::ObjectIdentifier;

    // Hash algorithm OIDs
    pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

    // RSA signature algorithm OIDs
    pub const RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    pub const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    pub const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    pub const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

    // ECDSA signature algorithm OIDs
    pub const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    pub const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

    // Key type OIDs
    pub const EC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    // EC curve OIDs
    pub const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    pub const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

    // CMS/PKCS#7 OIDs
    pub const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    pub const MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

    // X.509 extension OIDs
    pub const SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
    pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    pub const EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
    pub const TSA_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
}

mod rfc3161 {
    use der::asn1::{GeneralizedTime, OctetString};
    use der::Sequence;
    use spki::AlgorithmIdentifierOwned;

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct TimeStampResp {
        pub status: PkiStatusInfo,
        pub time_stamp_token: Option<der::asn1::Any>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct PkiStatusInfo {
        pub status: PkiStatus,
        pub status_string: Option<der::asn1::Any>,
        pub fail_info: Option<der::asn1::BitString>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PkiStatus(u8);

    impl PkiStatus {
        pub fn to_u8(self) -> u8 {
            self.0
        }
    }

    impl<'a> der::Decode<'a> for PkiStatus {
        fn decode<R: der::Reader<'a>>(reader: &mut R) -> der::Result<Self> {
            let val = der::asn1::Int::decode(reader)?;
            let bytes = val.as_bytes();
            let status = if bytes.is_empty() {
                0
            } else {
                bytes[bytes.len() - 1]
            };
            Ok(Self(status))
        }
    }

    impl der::Encode for PkiStatus {
        fn encoded_len(&self) -> der::Result<der::Length> {
            der::Length::ONE + der::Length::ONE
        }
        fn encode(&self, writer: &mut impl der::Writer) -> der::Result<()> {
            writer.write(&[der::Tag::Integer.into(), 1, self.0])
        }
    }

    impl der::FixedTag for PkiStatus {
        const TAG: der::Tag = der::Tag::Integer;
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct TstInfo {
        pub version: der::asn1::Int,
        pub policy: der::asn1::ObjectIdentifier,
        pub message_imprint: MessageImprint,
        pub serial_number: der::asn1::Int,
        pub gen_time: GeneralizedTime,
        pub accuracy: Option<der::asn1::Any>,
        #[asn1(default = "default_false")]
        pub ordering: bool,
        pub nonce: Option<der::asn1::Int>,
        #[asn1(context_specific = "0", optional = "true")]
        pub tsa: Option<der::asn1::Any>,
        #[asn1(context_specific = "1", optional = "true")]
        pub extensions: Option<der::asn1::Any>,
    }

    fn default_false() -> bool {
        false
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct MessageImprint {
        pub hash_algorithm: AlgorithmIdentifierOwned,
        pub hashed_message: OctetString,
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
    UntrustedSigner {
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
        let latest_seq = self.get_latest_sequence().await?;
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

pub struct Rfc3161Client {
    tsa_url: String,
    client: reqwest::Client,
    trusted_roots: Vec<x509_cert::Certificate>,
}

impl Rfc3161Client {
    pub fn new(tsa_url: String) -> Self {
        Self {
            tsa_url,
            client: reqwest::Client::new(),
            trusted_roots: Vec::new(),
        }
    }

    pub fn with_trusted_roots(mut self, roots: Vec<x509_cert::Certificate>) -> Self {
        self.trusted_roots = roots;
        self
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

        let token_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Audit(format!("Failed to read TSA response: {}", e)))?;

        let (gen_time, _signer_cert) = self.validate_timestamp_response(&token_bytes, hash)?;

        Ok(Rfc3161Token {
            tsa_url: self.tsa_url.clone(),
            timestamp: gen_time,
            token: token_bytes.to_vec(),
        })
    }

    fn validate_timestamp_response(
        &self,
        response_bytes: &[u8],
        expected_hash: &Hash,
    ) -> Result<(DateTime<Utc>, x509_cert::Certificate)> {
        let (gen_time, signer_cert, chain_certs) =
            self.validate_timestamp_response_with_chain(response_bytes, expected_hash)?;

        if !self.trusted_roots.is_empty() {
            self.validate_certificate_chain(&signer_cert, &chain_certs, gen_time)?;
        }

        Ok((gen_time, signer_cert))
    }

    fn compute_digest(&self, alg_oid: &der::oid::ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest;

        match *alg_oid {
            oid::SHA256 => Ok(sha2::Sha256::digest(data).to_vec()),
            oid::SHA384 => Ok(sha2::Sha384::digest(data).to_vec()),
            oid::SHA512 => Ok(sha2::Sha512::digest(data).to_vec()),
            _ => Err(Error::Audit(format!(
                "Unsupported digest algorithm: {}",
                alg_oid
            ))),
        }
    }

    fn validate_timestamp_response_with_chain(
        &self,
        response_bytes: &[u8],
        expected_hash: &Hash,
    ) -> Result<(
        DateTime<Utc>,
        x509_cert::Certificate,
        Vec<x509_cert::Certificate>,
    )> {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::{Decode, Encode};

        let tsp_resp = rfc3161::TimeStampResp::from_der(response_bytes)
            .map_err(|e| Error::Audit(format!("Failed to parse TimeStampResp: {}", e)))?;

        let status = tsp_resp.status.status.to_u8();
        if status != 0 && status != 1 {
            return Err(Error::Audit(format!(
                "TSA returned non-success status: {}",
                status
            )));
        }

        let token_bytes = tsp_resp
            .time_stamp_token
            .ok_or_else(|| Error::Audit("TimeStampResp missing token".into()))?
            .to_der()
            .map_err(|e| Error::Audit(format!("Failed to encode token: {}", e)))?;

        let content_info = ContentInfo::from_der(&token_bytes)
            .map_err(|e| Error::Audit(format!("Failed to parse ContentInfo: {}", e)))?;

        if content_info.content_type != oid::SIGNED_DATA {
            return Err(Error::Audit("TimeStampToken is not SignedData".into()));
        }

        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(|e| Error::Audit(format!("Failed to parse SignedData: {}", e)))?;

        let tst_info_bytes = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or_else(|| Error::Audit("SignedData missing encapsulated content".into()))?
            .value();

        let tst_info = rfc3161::TstInfo::from_der(tst_info_bytes)
            .map_err(|e| Error::Audit(format!("Failed to parse TSTInfo: {}", e)))?;

        if tst_info.message_imprint.hash_algorithm.oid != oid::SHA256 {
            return Err(Error::Audit(
                "TSTInfo uses unexpected hash algorithm".into(),
            ));
        }

        if tst_info.message_imprint.hashed_message.as_bytes() != expected_hash {
            return Err(Error::Audit(
                "TSTInfo messageImprint does not match expected hash".into(),
            ));
        }

        let signer_info = signed_data
            .signer_infos
            .0
            .iter()
            .next()
            .ok_or_else(|| Error::Audit("SignedData missing signer info".into()))?;

        let certs = signed_data
            .certificates
            .as_ref()
            .ok_or_else(|| Error::Audit("SignedData missing certificates".into()))?;

        let (signer_cert, chain_certs) =
            self.find_signer_certificate_and_chain(certs, signer_info)?;

        self.verify_signature(&signed_data, signer_info, &signer_cert)?;

        let gen_time = self.parse_generalized_time(&tst_info.gen_time)?;
        self.validate_certificate_validity(&signer_cert, gen_time)?;

        Ok((gen_time, signer_cert, chain_certs))
    }

    fn find_signer_certificate_and_chain(
        &self,
        certs: &cms::signed_data::CertificateSet,
        signer_info: &cms::signed_data::SignerInfo,
    ) -> Result<(x509_cert::Certificate, Vec<x509_cert::Certificate>)> {
        use cms::cert::CertificateChoices;
        use cms::signed_data::SignerIdentifier;
        use der::{Decode, Encode};

        let mut chain_certs = Vec::new();
        let mut signer_cert = None;

        for cert_choice in certs.0.iter() {
            let CertificateChoices::Certificate(cert_inner) = cert_choice else {
                continue;
            };

            let cert_bytes = cert_inner
                .to_der()
                .map_err(|e| Error::Audit(format!("Failed to encode certificate: {}", e)))?;
            let cert = x509_cert::Certificate::from_der(&cert_bytes)
                .map_err(|e| Error::Audit(format!("Failed to parse certificate: {}", e)))?;

            let is_signer = match &signer_info.sid {
                SignerIdentifier::IssuerAndSerialNumber(issuer_serial) => {
                    cert.tbs_certificate.issuer == issuer_serial.issuer
                        && cert.tbs_certificate.serial_number == issuer_serial.serial_number
                }
                SignerIdentifier::SubjectKeyIdentifier(skid) => cert
                    .tbs_certificate
                    .extensions
                    .as_ref()
                    .is_some_and(|exts| {
                        exts.iter().any(|ext| {
                            if ext.extn_id != oid::SUBJECT_KEY_ID {
                                return false;
                            }
                            // Decode the DER-encoded OCTET STRING to get the actual SKID bytes
                            der::asn1::OctetString::from_der(ext.extn_value.as_bytes())
                                .map(|decoded| decoded.as_bytes() == skid.0.as_bytes())
                                .unwrap_or(false)
                        })
                    }),
            };

            if is_signer {
                signer_cert = Some(cert);
            } else {
                chain_certs.push(cert);
            }
        }

        let signer = signer_cert
            .ok_or_else(|| Error::Audit("Signer certificate not found in token".into()))?;
        Ok((signer, chain_certs))
    }

    fn verify_signature(
        &self,
        signed_data: &cms::signed_data::SignedData,
        signer_info: &cms::signed_data::SignerInfo,
        cert: &x509_cert::Certificate,
    ) -> Result<()> {
        use der::Encode;

        let content_to_hash = match signer_info.signed_attrs {
            Some(ref signed_attrs) => signed_attrs
                .to_der()
                .map_err(|e| Error::Audit(format!("Failed to encode signed attrs: {}", e)))?,
            None => signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .ok_or_else(|| Error::Audit("Missing content to verify".into()))?
                .value()
                .to_vec(),
        };

        let digest = self.compute_digest(&signer_info.digest_alg.oid, &content_to_hash)?;

        let sig_alg = &signer_info.signature_algorithm.oid;
        let is_rsa = matches!(
            *sig_alg,
            oid::RSA_ENCRYPTION | oid::RSA_SHA256 | oid::RSA_SHA384 | oid::RSA_SHA512
        );
        let is_ecdsa = matches!(*sig_alg, oid::ECDSA_SHA256 | oid::ECDSA_SHA384);

        if !is_rsa && !is_ecdsa {
            return Err(Error::Audit(format!(
                "Unsupported signature algorithm: {}",
                sig_alg
            )));
        }

        if let Some(ref signed_attrs) = signer_info.signed_attrs {
            self.verify_message_digest_attribute(
                signed_attrs,
                signed_data,
                &signer_info.digest_alg.oid,
            )?;
        }

        let pubkey_info = &cert.tbs_certificate.subject_public_key_info;
        let signature_bytes = signer_info.signature.as_bytes();
        let pubkey_bytes = pubkey_info.subject_public_key.raw_bytes();

        if pubkey_info.algorithm.oid == oid::RSA_ENCRYPTION {
            self.verify_rsa_signature(pubkey_bytes, &digest, signature_bytes, sig_alg, &signer_info.digest_alg.oid)?;
        } else if pubkey_info.algorithm.oid == oid::EC_KEY {
            let curve_oid = pubkey_info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::oid::ObjectIdentifier>().ok())
                .ok_or_else(|| Error::Audit("Missing EC curve parameter".into()))?;

            if curve_oid == oid::SECP256R1 {
                self.verify_p256_signature(pubkey_bytes, &digest, signature_bytes)?;
            } else if curve_oid == oid::SECP384R1 {
                self.verify_p384_signature(pubkey_bytes, &digest, signature_bytes)?;
            } else {
                return Err(Error::Audit(format!("Unsupported EC curve: {}", curve_oid)));
            }
        } else {
            return Err(Error::Audit(format!(
                "Unsupported public key algorithm: {}",
                pubkey_info.algorithm.oid
            )));
        }

        Ok(())
    }

    fn verify_message_digest_attribute(
        &self,
        signed_attrs: &cms::signed_data::SignedAttributes,
        signed_data: &cms::signed_data::SignedData,
        digest_alg_oid: &der::oid::ObjectIdentifier,
    ) -> Result<()> {
        for attr in signed_attrs.iter() {
            if attr.oid != oid::MESSAGE_DIGEST {
                continue;
            }

            let Some(value) = attr.values.iter().next() else {
                continue;
            };

            let attr_digest: der::asn1::OctetString = value
                .decode_as()
                .map_err(|e| Error::Audit(format!("Failed to decode digest: {}", e)))?;

            let content_bytes = signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .ok_or_else(|| Error::Audit("Missing encap content".into()))?
                .value();

            let content_digest = self.compute_digest(digest_alg_oid, content_bytes)?;

            if attr_digest.as_bytes() != content_digest.as_slice() {
                return Err(Error::Audit(
                    "Message digest attribute does not match content".into(),
                ));
            }

            return Ok(());
        }

        Err(Error::Audit(
            "Signed attributes missing message digest".into(),
        ))
    }

    fn verify_rsa_signature(
        &self,
        pubkey_der: &[u8],
        digest: &[u8],
        signature: &[u8],
        sig_alg: &der::oid::ObjectIdentifier,
        digest_alg: &der::oid::ObjectIdentifier,
    ) -> Result<()> {
        use der::Decode;
        use rsa::{pkcs1v15::Pkcs1v15Sign, RsaPublicKey};

        let rsa_pubkey_parsed = rsa::pkcs1::RsaPublicKey::from_der(pubkey_der)
            .map_err(|e| Error::Audit(format!("Failed to parse RSA public key: {}", e)))?;
        let rsa_pubkey = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(rsa_pubkey_parsed.modulus.as_bytes()),
            rsa::BigUint::from_bytes_be(rsa_pubkey_parsed.public_exponent.as_bytes()),
        )
        .map_err(|e| Error::Audit(format!("Invalid RSA public key: {}", e)))?;

        // When sig_alg is RSA_ENCRYPTION (key algorithm, not signature algorithm),
        // use the digest algorithm to determine the PKCS#1v15 scheme
        let scheme = match *sig_alg {
            oid::RSA_ENCRYPTION => match *digest_alg {
                oid::SHA256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
                oid::SHA384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
                oid::SHA512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
                _ => {
                    return Err(Error::Audit(format!(
                        "Unsupported digest algorithm for RSA signature: {}",
                        digest_alg
                    )));
                }
            },
            oid::RSA_SHA256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
            oid::RSA_SHA384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
            oid::RSA_SHA512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
            _ => {
                return Err(Error::Audit(format!(
                    "Unsupported RSA signature algorithm: {}",
                    sig_alg
                )));
            }
        };

        rsa_pubkey
            .verify(scheme, digest, signature)
            .map_err(|e| Error::Audit(format!("RSA signature verification failed: {}", e)))
    }

    fn verify_p256_signature(
        &self,
        pubkey_bytes: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use p256::ecdsa::{Signature, VerifyingKey};
        use signature::hazmat::PrehashVerifier;

        let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|e| Error::Audit(format!("Failed to parse P-256 public key: {}", e)))?;
        let sig = Signature::from_der(signature)
            .map_err(|e| Error::Audit(format!("Failed to parse P-256 signature: {}", e)))?;

        verifying_key
            .verify_prehash(digest, &sig)
            .map_err(|e| Error::Audit(format!("P-256 signature verification failed: {}", e)))
    }

    fn verify_p384_signature(
        &self,
        pubkey_bytes: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use p384::ecdsa::{Signature, VerifyingKey};
        use signature::hazmat::PrehashVerifier;

        let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|e| Error::Audit(format!("Failed to parse P-384 public key: {}", e)))?;
        let sig = Signature::from_der(signature)
            .map_err(|e| Error::Audit(format!("Failed to parse P-384 signature: {}", e)))?;

        verifying_key
            .verify_prehash(digest, &sig)
            .map_err(|e| Error::Audit(format!("P-384 signature verification failed: {}", e)))
    }

    fn parse_generalized_time(
        &self,
        gen_time: &der::asn1::GeneralizedTime,
    ) -> Result<DateTime<Utc>> {
        let time: std::time::SystemTime = (*gen_time).into();
        let duration = time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Audit(format!("Invalid timestamp: {}", e)))?;
        DateTime::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos())
            .ok_or_else(|| Error::Audit("Failed to convert timestamp".into()))
    }

    fn validate_certificate_validity(
        &self,
        cert: &x509_cert::Certificate,
        timestamp: DateTime<Utc>,
    ) -> Result<()> {
        let validity = &cert.tbs_certificate.validity;
        let not_before: std::time::SystemTime = validity.not_before.to_system_time();
        let not_after: std::time::SystemTime = validity.not_after.to_system_time();

        let ts_system =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp.timestamp() as u64);

        if ts_system < not_before {
            return Err(Error::Audit(
                "TST genTime is before certificate validity period".into(),
            ));
        }
        if ts_system > not_after {
            return Err(Error::Audit(
                "TST genTime is after certificate validity period".into(),
            ));
        }
        Ok(())
    }

    fn validate_certificate_chain(
        &self,
        signer_cert: &x509_cert::Certificate,
        chain_certs: &[x509_cert::Certificate],
        gen_time: DateTime<Utc>,
    ) -> Result<()> {
        if self.trusted_roots.is_empty() {
            return Ok(());
        }

        self.validate_timestamping_eku(signer_cert)?;

        let chain = self.build_certificate_chain(signer_cert, chain_certs)?;
        let chain_len = chain.len();

        for (i, cert) in chain.iter().enumerate() {
            let is_end_entity = i == 0;
            let is_root = i == chain_len - 1;
            let is_ca = !is_end_entity;

            // Validate certificate validity (notBefore/notAfter) against genTime
            self.validate_certificate_validity(cert, gen_time)?;

            if is_ca {
                self.validate_basic_constraints(cert, !is_root)?;
            }

            if !is_root {
                self.verify_certificate_signature(cert, &chain[i + 1])?;
            }

            self.validate_key_usage_for_signing(cert, is_ca)?;
        }

        Ok(())
    }

    fn validate_timestamping_eku(&self, cert: &x509_cert::Certificate) -> Result<()> {
        use der::Decode;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or_else(|| Error::Audit("TSA certificate missing extensions".into()))?;

        let eku_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == oid::EXT_KEY_USAGE)
            .ok_or_else(|| {
                Error::Audit("TSA certificate missing Extended Key Usage extension".into())
            })?;

        let eku_seq = der::asn1::SequenceOf::<der::oid::ObjectIdentifier, 16>::from_der(
            eku_ext.extn_value.as_bytes(),
        )
        .map_err(|e| Error::Audit(format!("Failed to parse EKU: {}", e)))?;

        if eku_seq.iter().any(|o| *o == oid::TSA_EKU) {
            Ok(())
        } else {
            Err(Error::Audit(
                "TSA certificate missing timestamping EKU".into(),
            ))
        }
    }

    fn build_certificate_chain(
        &self,
        signer_cert: &x509_cert::Certificate,
        chain_certs: &[x509_cert::Certificate],
    ) -> Result<Vec<x509_cert::Certificate>> {
        const MAX_CHAIN_LENGTH: usize = 10;

        let mut chain = vec![signer_cert.clone()];
        let mut available: Vec<_> = chain_certs.to_vec();

        while chain.len() < MAX_CHAIN_LENGTH {
            let current = chain.last().unwrap();
            let issuer = &current.tbs_certificate.issuer;

            if let Some(root) = self
                .trusted_roots
                .iter()
                .find(|r| &r.tbs_certificate.subject == issuer)
            {
                chain.push(root.clone());
                return Ok(chain);
            }

            let intermediate_idx = available
                .iter()
                .position(|c| &c.tbs_certificate.subject == issuer);

            match intermediate_idx {
                Some(idx) => chain.push(available.remove(idx)),
                None => {
                    return Err(Error::Audit(
                        "Could not build certificate chain to trusted root".into(),
                    ))
                }
            }
        }

        Err(Error::Audit("Certificate chain too long".into()))
    }

    fn validate_basic_constraints(
        &self,
        cert: &x509_cert::Certificate,
        must_be_ca: bool,
    ) -> Result<()> {
        use der::Decode;

        #[derive(der::Sequence)]
        struct BasicConstraints {
            #[asn1(default = "default_false")]
            ca: bool,
            #[asn1(optional = "true")]
            path_len_constraint: Option<u32>,
        }

        fn default_false() -> bool {
            false
        }

        let Some(extensions) = &cert.tbs_certificate.extensions else {
            if must_be_ca {
                return Err(Error::Audit(
                    "CA certificate missing Basic Constraints extension".into(),
                ));
            }
            return Ok(());
        };

        let bc_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == oid::BASIC_CONSTRAINTS);

        match bc_ext {
            Some(ext) => {
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    Error::Audit(format!("Failed to parse Basic Constraints: {}", e))
                })?;

                if must_be_ca && !bc.ca {
                    return Err(Error::Audit("Intermediate certificate is not a CA".into()));
                }
                Ok(())
            }
            None if must_be_ca => Err(Error::Audit(
                "CA certificate missing Basic Constraints extension".into(),
            )),
            None => Ok(()),
        }
    }

    fn validate_key_usage_for_signing(
        &self,
        cert: &x509_cert::Certificate,
        is_ca: bool,
    ) -> Result<()> {
        use der::Decode;

        const DIGITAL_SIGNATURE: u8 = 0x80;
        const KEY_CERT_SIGN: u8 = 0x04;

        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return Ok(());
        };

        let Some(ku_ext) = extensions.iter().find(|ext| ext.extn_id == oid::KEY_USAGE) else {
            return Ok(());
        };

        let ku = der::asn1::BitString::from_der(ku_ext.extn_value.as_bytes())
            .map_err(|e| Error::Audit(format!("Failed to parse Key Usage: {}", e)))?;

        let ku_bytes = ku.raw_bytes();
        if ku_bytes.is_empty() {
            return Err(Error::Audit("Key Usage extension is empty".into()));
        }

        let usage = ku_bytes[0];
        if is_ca && (usage & KEY_CERT_SIGN == 0) {
            return Err(Error::Audit(
                "CA certificate missing keyCertSign key usage".into(),
            ));
        }
        if !is_ca && (usage & DIGITAL_SIGNATURE == 0) {
            return Err(Error::Audit(
                "End-entity certificate missing digitalSignature key usage".into(),
            ));
        }

        Ok(())
    }

    fn verify_certificate_signature(
        &self,
        cert: &x509_cert::Certificate,
        issuer: &x509_cert::Certificate,
    ) -> Result<()> {
        use der::Encode;
        use sha2::Digest;

        let tbs_bytes = cert
            .tbs_certificate
            .to_der()
            .map_err(|e| Error::Audit(format!("Failed to encode TBS certificate: {}", e)))?;

        let signature_bytes = cert.signature.raw_bytes();
        let sig_alg = &cert.signature_algorithm.oid;
        let pubkey_info = &issuer.tbs_certificate.subject_public_key_info;
        let pubkey_bytes = pubkey_info.subject_public_key.raw_bytes();

        if pubkey_info.algorithm.oid == oid::RSA_ENCRYPTION {
            let (digest, digest_alg) = match *sig_alg {
                oid::RSA_SHA256 => (sha2::Sha256::digest(&tbs_bytes).to_vec(), oid::SHA256),
                oid::RSA_SHA384 => (sha2::Sha384::digest(&tbs_bytes).to_vec(), oid::SHA384),
                oid::RSA_SHA512 => (sha2::Sha512::digest(&tbs_bytes).to_vec(), oid::SHA512),
                _ => {
                    return Err(Error::Audit(format!(
                        "Unsupported certificate signature algorithm: {}",
                        sig_alg
                    )));
                }
            };
            self.verify_rsa_signature(pubkey_bytes, &digest, signature_bytes, sig_alg, &digest_alg)?;
        } else if pubkey_info.algorithm.oid == oid::EC_KEY {
            let curve_oid = pubkey_info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::oid::ObjectIdentifier>().ok())
                .ok_or_else(|| Error::Audit("Missing EC curve parameter".into()))?;

            match (curve_oid, *sig_alg) {
                (c, s) if c == oid::SECP256R1 && s == oid::ECDSA_SHA256 => {
                    let digest = sha2::Sha256::digest(&tbs_bytes).to_vec();
                    self.verify_p256_signature(pubkey_bytes, &digest, signature_bytes)?;
                }
                (c, s) if c == oid::SECP384R1 && s == oid::ECDSA_SHA384 => {
                    let digest = sha2::Sha384::digest(&tbs_bytes).to_vec();
                    self.verify_p384_signature(pubkey_bytes, &digest, signature_bytes)?;
                }
                _ => {
                    return Err(Error::Audit(format!(
                        "Unsupported EC curve/signature combination: {} / {}",
                        curve_oid, sig_alg
                    )));
                }
            }
        } else {
            return Err(Error::Audit(format!(
                "Unsupported issuer public key algorithm: {}",
                pubkey_info.algorithm.oid
            )));
        }

        Ok(())
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
    trusted_signers: HashSet<[u8; 32]>,
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
        let pubkey = signer.public_key();

        let mut trusted_signers = HashSet::new();
        trusted_signers.insert(pubkey);

        Ok(Self {
            store,
            signer: Arc::new(signer),
            sequence: AtomicU64::new(sequence),
            last_hash: RwLock::new(last_hash),
            record_mutex: Mutex::new(()),
            tsa_client: None,
            trusted_signers,
        })
    }

    pub fn with_tsa(mut self, tsa_url: String) -> Self {
        self.tsa_client = Some(Rfc3161Client::new(tsa_url));
        self
    }

    pub fn with_trusted_signers(mut self, signers: impl IntoIterator<Item = [u8; 32]>) -> Self {
        self.trusted_signers.extend(signers);
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
            match tsa.timestamp(&event.hash).await {
                Ok(token) => event.rfc3161_token = Some(token),
                Err(e) => {
                    tracing::error!(
                        event_id = %event.id.0,
                        sequence = event.sequence,
                        error = %e,
                        "RFC3161 timestamp request failed"
                    );
                }
            }
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

            if !self.trusted_signers.contains(&event.signer_pubkey) {
                return Ok(ChainVerification::UntrustedSigner {
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
            ChainVerification::UntrustedSigner { at_sequence } => {
                Self::error_at("untrusted signer", at_sequence)
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
