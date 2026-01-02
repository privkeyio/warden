#![forbid(unsafe_code)]

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone, thiserror::Error)]
pub enum SecretsError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("SSRF validation failed: {0}")]
    SsrfBlocked(String),
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64) // CGNAT
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || (ip.segments()[0] & 0xFE00) == 0xFC00 // ULA
        || (ip.segments()[0] & 0xFFC0) == 0xFE80 // link-local
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

/// Validates that a URL is safe for outbound requests (SSRF protection).
/// Requires HTTPS, blocks private IPs, and blocks known internal hostnames.
pub fn validate_provider_url(url_str: &str) -> Result<(), SecretsError> {
    let url = Url::parse(url_str)
        .map_err(|e| SecretsError::Configuration(format!("invalid URL: {}", e)))?;

    if url.scheme() != "https" {
        return Err(SecretsError::SsrfBlocked(
            "provider URL must use HTTPS".into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| SecretsError::Configuration("URL must have a host".into()))?;

    let host_lower = host.to_lowercase();
    for blocked in BLOCKED_HOSTNAMES {
        if host_lower == *blocked || host_lower.ends_with(&format!(".{}", blocked)) {
            return Err(SecretsError::SsrfBlocked(format!(
                "blocked hostname: {}",
                host
            )));
        }
    }

    let port = url.port().unwrap_or(443);
    let socket_addr = format!("{}:{}", host, port);

    let resolved_ips: Vec<IpAddr> = socket_addr
        .to_socket_addrs()
        .map_err(|e| SecretsError::Configuration(format!("DNS resolution failed: {}", e)))?
        .map(|addr| addr.ip())
        .collect();

    if resolved_ips.is_empty() {
        return Err(SecretsError::Configuration(
            "DNS resolution returned no addresses".into(),
        ));
    }

    for ip in &resolved_ips {
        if is_private_ip(*ip) {
            return Err(SecretsError::SsrfBlocked(format!(
                "URL resolves to private/internal IP: {}",
                ip
            )));
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct SecretValue(SecretString);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn into_inner(self) -> SecretString {
        self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecretValue {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretValue {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl Serialize for SecretValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretValue::new(s))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretRef {
    Env {
        name: String,
    },
    Vault {
        path: String,
        key: String,
    },
    AwsSecretsManager {
        secret_id: String,
        key: Option<String>,
    },
    /// Inline literal secret value. Use only for testing/development.
    /// Warning: The value will be serialized to config files in plain text.
    Literal {
        value: String,
    },
}

impl std::fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env { name } => f.debug_struct("Env").field("name", name).finish(),
            Self::Vault { path, key } => f
                .debug_struct("Vault")
                .field("path", path)
                .field("key", key)
                .finish(),
            Self::AwsSecretsManager { secret_id, key } => f
                .debug_struct("AwsSecretsManager")
                .field("secret_id", secret_id)
                .field("key", key)
                .finish(),
            Self::Literal { .. } => f
                .debug_struct("Literal")
                .field("value", &"[REDACTED]")
                .finish(),
        }
    }
}

impl SecretRef {
    pub fn env(name: impl Into<String>) -> Self {
        Self::Env { name: name.into() }
    }

    pub fn vault(path: impl Into<String>, key: impl Into<String>) -> Self {
        Self::Vault {
            path: path.into(),
            key: key.into(),
        }
    }

    pub fn aws(secret_id: impl Into<String>, key: Option<String>) -> Self {
        Self::AwsSecretsManager {
            secret_id: secret_id.into(),
            key,
        }
    }
}

#[async_trait]
pub trait SecretsProvider: Send + Sync {
    async fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretsError>;
}

pub struct EnvSecretsProvider;

impl EnvSecretsProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnvSecretsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretsProvider for EnvSecretsProvider {
    async fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretsError> {
        match reference {
            SecretRef::Env { name } => std::env::var(name)
                .map(SecretValue::new)
                .map_err(|_| SecretsError::NotFound(format!("env var: {}", name))),
            SecretRef::Literal { value } => Ok(SecretValue::new(value.clone())),
            _ => Err(SecretsError::Configuration(
                "EnvSecretsProvider only supports Env and Literal references".into(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: SecretValue,
    pub namespace: Option<String>,
    pub timeout_seconds: u32,
}

impl VaultConfig {
    pub fn new(address: impl Into<String>, token: SecretValue) -> Self {
        Self {
            address: address.into(),
            token,
            namespace: None,
            timeout_seconds: 30,
        }
    }
}

pub struct VaultSecretsProvider {
    config: VaultConfig,
    client: reqwest::Client,
}

impl VaultSecretsProvider {
    /// Creates a new VaultSecretsProvider with SSRF validation.
    ///
    /// # Errors
    /// Returns `SecretsError::SsrfBlocked` if the Vault address fails SSRF validation
    /// (e.g., points to localhost, private IPs, or uses non-HTTPS).
    pub fn new(config: VaultConfig) -> Result<Self, SecretsError> {
        validate_provider_url(&config.address)?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.timeout_seconds as u64,
            ))
            .build()
            .unwrap_or_default();
        Ok(Self { config, client })
    }

    /// Creates a new VaultSecretsProvider without SSRF validation.
    ///
    /// # Safety
    /// Use only when the Vault address is from a trusted source (e.g., hardcoded
    /// or from a validated configuration file). Never use with user-provided URLs.
    pub fn new_unchecked(config: VaultConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.timeout_seconds as u64,
            ))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
}

#[async_trait]
impl SecretsProvider for VaultSecretsProvider {
    async fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretsError> {
        match reference {
            SecretRef::Vault { path, key } => {
                let url = format!("{}/v1/{}", self.config.address, path);

                let mut request = self
                    .client
                    .get(&url)
                    .header("X-Vault-Token", self.config.token.expose());

                if let Some(ns) = &self.config.namespace {
                    request = request.header("X-Vault-Namespace", ns);
                }

                let response = request
                    .send()
                    .await
                    .map_err(|e| SecretsError::Provider(e.to_string()))?;

                if !response.status().is_success() {
                    return Err(SecretsError::Provider(format!(
                        "Vault returned {}",
                        response.status()
                    )));
                }

                let body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| SecretsError::Provider(e.to_string()))?;

                let data = body
                    .get("data")
                    .and_then(|d| d.get("data").or(Some(d)))
                    .ok_or_else(|| SecretsError::Provider("invalid Vault response".into()))?;

                let value = data.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
                    SecretsError::NotFound(format!("key {} in path {}", key, path))
                })?;

                Ok(SecretValue::new(value))
            }
            SecretRef::Env { .. } => EnvSecretsProvider.get(reference).await,
            SecretRef::Literal { value } => Ok(SecretValue::new(value.clone())),
            _ => Err(SecretsError::Configuration(
                "VaultSecretsProvider does not support this reference type".into(),
            )),
        }
    }
}

/// Configuration for AWS Secrets Manager provider.
///
/// Note: This provider requires AWS credentials to be available in the environment
/// (via AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, instance metadata, or other standard
/// AWS credential sources). The reqwest client relies on system-level AWS credential
/// chain for authentication.
#[derive(Debug, Clone)]
pub struct AwsSecretsManagerConfig {
    pub region: String,
    pub endpoint_url: Option<String>,
    pub timeout_seconds: u32,
}

impl AwsSecretsManagerConfig {
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            endpoint_url: None,
            timeout_seconds: 30,
        }
    }
}

/// AWS Secrets Manager provider for retrieving secrets.
///
/// **WARNING**: This provider is not yet functional. AWS API requests require Sigv4
/// signing which is not implemented. See: https://github.com/privkeyio/warden/issues/21
///
/// TODO: Replace with aws-sdk-secretsmanager from https://github.com/awslabs/aws-sdk-rust
pub struct AwsSecretsManagerProvider {
    config: AwsSecretsManagerConfig,
    client: reqwest::Client,
}

impl AwsSecretsManagerProvider {
    /// Creates a new AwsSecretsManagerProvider with SSRF validation.
    ///
    /// If `endpoint_url` is provided, it will be validated against SSRF attacks.
    /// The default AWS endpoint is always allowed.
    ///
    /// # Errors
    /// Returns `SecretsError::SsrfBlocked` if the custom endpoint_url fails SSRF validation.
    pub fn new(config: AwsSecretsManagerConfig) -> Result<Self, SecretsError> {
        if let Some(ref endpoint) = config.endpoint_url {
            validate_provider_url(endpoint)?;
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.timeout_seconds as u64,
            ))
            .build()
            .unwrap_or_default();
        Ok(Self { config, client })
    }

    /// Creates a new AwsSecretsManagerProvider without SSRF validation.
    ///
    /// # Safety
    /// Use only when the endpoint URL is from a trusted source.
    pub fn new_unchecked(config: AwsSecretsManagerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.timeout_seconds as u64,
            ))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    fn get_endpoint(&self) -> String {
        self.config.endpoint_url.clone().unwrap_or_else(|| {
            format!(
                "https://secretsmanager.{}.amazonaws.com",
                self.config.region
            )
        })
    }
}

#[async_trait]
impl SecretsProvider for AwsSecretsManagerProvider {
    async fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretsError> {
        match reference {
            SecretRef::AwsSecretsManager { secret_id, key } => {
                let endpoint = self.get_endpoint();

                let request_body = serde_json::json!({
                    "SecretId": secret_id
                });

                let response = self
                    .client
                    .post(&endpoint)
                    .header("Content-Type", "application/x-amz-json-1.1")
                    .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                    .json(&request_body)
                    .send()
                    .await
                    .map_err(|e| SecretsError::Provider(e.to_string()))?;

                if !response.status().is_success() {
                    return Err(SecretsError::Provider(format!(
                        "AWS Secrets Manager returned {}",
                        response.status()
                    )));
                }

                let body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| SecretsError::Provider(e.to_string()))?;

                let secret_string = body
                    .get("SecretString")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SecretsError::Provider("no SecretString in response".into()))?;

                if let Some(key) = key {
                    let parsed: serde_json::Value = serde_json::from_str(secret_string)
                        .map_err(|e| SecretsError::Provider(e.to_string()))?;

                    let value = parsed
                        .get(key)
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| SecretsError::NotFound(format!("key {} in secret", key)))?;

                    Ok(SecretValue::new(value))
                } else {
                    Ok(SecretValue::new(secret_string))
                }
            }
            SecretRef::Env { .. } => EnvSecretsProvider.get(reference).await,
            SecretRef::Literal { value } => Ok(SecretValue::new(value.clone())),
            _ => Err(SecretsError::Configuration(
                "AwsSecretsManagerProvider does not support this reference type".into(),
            )),
        }
    }
}

pub struct CompositeSecretsProvider {
    providers: Vec<Arc<dyn SecretsProvider>>,
}

impl CompositeSecretsProvider {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn with_provider(mut self, provider: Arc<dyn SecretsProvider>) -> Self {
        self.providers.push(provider);
        self
    }
}

impl Default for CompositeSecretsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretsProvider for CompositeSecretsProvider {
    async fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretsError> {
        for provider in &self.providers {
            match provider.get(reference).await {
                Ok(value) => return Ok(value),
                Err(SecretsError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(SecretsError::NotFound(format!("{:?}", reference)))
    }
}

pub fn default_provider() -> Arc<dyn SecretsProvider> {
    Arc::new(EnvSecretsProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_env_provider() {
        std::env::set_var("TEST_SECRET_123", "secret_value");

        let provider = EnvSecretsProvider::new();
        let secret = provider
            .get(&SecretRef::env("TEST_SECRET_123"))
            .await
            .unwrap();

        assert_eq!(secret.expose(), "secret_value");
        std::env::remove_var("TEST_SECRET_123");
    }

    #[tokio::test]
    async fn test_literal_ref() {
        let provider = EnvSecretsProvider::new();
        let secret = provider
            .get(&SecretRef::Literal {
                value: "inline_secret".into(),
            })
            .await
            .unwrap();

        assert_eq!(secret.expose(), "inline_secret");
    }

    #[test]
    fn test_secret_value_debug() {
        let secret = SecretValue::new("super_secret");
        let debug_str = format!("{:?}", secret);
        assert_eq!(debug_str, "[REDACTED]");
        assert!(!debug_str.contains("super_secret"));
    }

    #[test]
    fn test_secret_value_serialize() {
        let secret = SecretValue::new("super_secret");
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"[REDACTED]\"");
        assert!(!json.contains("super_secret"));
    }

    #[test]
    fn test_secret_ref_debug_redacts_literal() {
        let secret_ref = SecretRef::Literal {
            value: "super_secret_value".into(),
        };
        let debug_str = format!("{:?}", secret_ref);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super_secret_value"));
    }

    #[test]
    fn test_secret_ref_debug_shows_env_name() {
        let secret_ref = SecretRef::Env {
            name: "MY_SECRET_VAR".into(),
        };
        let debug_str = format!("{:?}", secret_ref);
        assert!(debug_str.contains("MY_SECRET_VAR"));
    }

    #[test]
    fn test_ssrf_blocks_http() {
        let result = validate_provider_url("http://vault.example.com");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecretsError::SsrfBlocked(_)));
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        let result = validate_provider_url("https://localhost/v1/secret");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SecretsError::SsrfBlocked(_)));
        assert!(err.to_string().contains("blocked hostname"));
    }

    #[test]
    fn test_ssrf_blocks_cloud_metadata() {
        let result = validate_provider_url("https://metadata.google.internal/computeMetadata");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("blocked hostname"));
    }

    #[test]
    fn test_ssrf_private_ip_detection() {
        // Test private IPv4 ranges
        assert!(is_private_ipv4(Ipv4Addr::new(127, 0, 0, 1))); // loopback
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1))); // class A
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1))); // class B
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1))); // class C
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 169, 254))); // link-local
        assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1))); // CGNAT

        // Public IPs should not be blocked
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_ssrf_private_ipv6_detection() {
        assert!(is_private_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))); // ::1
        assert!(is_private_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))); // ULA
        assert!(is_private_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))); // link-local
    }

    #[test]
    fn test_vault_provider_ssrf_protection() {
        let config = VaultConfig::new("http://localhost:8200", SecretValue::new("test-token"));
        let result = VaultSecretsProvider::new(config);
        assert!(result.is_err());
        match result {
            Err(SecretsError::SsrfBlocked(_)) => {}
            _ => panic!("expected SsrfBlocked error"),
        }
    }

    #[test]
    fn test_aws_provider_ssrf_protection() {
        let mut config = AwsSecretsManagerConfig::new("us-east-1");
        config.endpoint_url = Some("http://localhost:4566".into()); // LocalStack-like
        let result = AwsSecretsManagerProvider::new(config);
        assert!(result.is_err());
        match result {
            Err(SecretsError::SsrfBlocked(_)) => {}
            _ => panic!("expected SsrfBlocked error"),
        }
    }

    #[test]
    fn test_aws_provider_default_endpoint_allowed() {
        let config = AwsSecretsManagerConfig::new("us-east-1");
        // Default AWS endpoint should be allowed (no custom endpoint)
        let result = AwsSecretsManagerProvider::new(config);
        assert!(result.is_ok());
    }
}
