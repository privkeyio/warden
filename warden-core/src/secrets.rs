#![forbid(unsafe_code)]

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;

#[derive(Debug, Clone, thiserror::Error)]
pub enum SecretsError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("configuration error: {0}")]
    Configuration(String),
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
    pub fn new(config: VaultConfig) -> Self {
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
/// Requires AWS credentials in the environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
/// or via instance metadata/IAM role when running on AWS infrastructure.
pub struct AwsSecretsManagerProvider {
    config: AwsSecretsManagerConfig,
    client: reqwest::Client,
}

impl AwsSecretsManagerProvider {
    pub fn new(config: AwsSecretsManagerConfig) -> Self {
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
}
