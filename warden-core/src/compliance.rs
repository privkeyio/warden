#![forbid(unsafe_code)]

use crate::callback::{CallbackDecision, CallbackRequest, CallbackResponse};
use crate::secrets::SecretValue;
use crate::ssrf::{validate_url, SsrfError, SsrfPolicy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreeningResult {
    pub address: String,
    pub risk_score: f64,
    pub risk_category: Option<String>,
    pub exposure: Option<ExposureInfo>,
    pub alerts: Vec<ComplianceAlert>,
    pub screened_at: DateTime<Utc>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureInfo {
    pub direct: f64,
    pub indirect: f64,
    pub categories: Vec<ExposureCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureCategory {
    pub category: String,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAlert {
    pub alert_id: String,
    pub severity: AlertSeverity,
    pub category: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ComplianceError {
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Address not found: {0}")]
    AddressNotFound(String),
    #[error("Timeout")]
    Timeout,
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("SSRF validation failed: {0}")]
    SsrfBlocked(String),
}

impl From<SsrfError> for ComplianceError {
    fn from(err: SsrfError) -> Self {
        ComplianceError::SsrfBlocked(err.to_string())
    }
}

#[async_trait::async_trait]
pub trait ComplianceProvider: Send + Sync {
    fn provider_name(&self) -> &str;
    async fn screen_address(
        &self,
        address: &str,
    ) -> std::result::Result<ScreeningResult, ComplianceError>;
    async fn register_transfer(
        &self,
        tx_hash: &str,
        output_address: &str,
        amount_btc: f64,
    ) -> std::result::Result<(), ComplianceError>;
    async fn health_check(&self) -> std::result::Result<(), ComplianceError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainalysisConfig {
    pub api_key: SecretValue,
    pub base_url: String,
    pub timeout_seconds: u32,
}

impl ChainalysisConfig {
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("CHAINALYSIS_API_KEY")
                .unwrap_or_default()
                .into(),
            base_url: std::env::var("CHAINALYSIS_BASE_URL")
                .unwrap_or_else(|_| "https://api.chainalysis.com".into()),
            timeout_seconds: 30,
        }
    }
}

impl Default for ChainalysisConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

pub struct ChainalysisClient {
    config: ChainalysisConfig,
    http_client: reqwest::Client,
}

impl ChainalysisClient {
    pub fn new(config: ChainalysisConfig) -> Result<Self, ComplianceError> {
        validate_url(&config.base_url, &SsrfPolicy::strict())?;
        Ok(Self {
            config,
            http_client: reqwest::Client::new(),
        })
    }

    pub fn new_unchecked(config: ChainalysisConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ComplianceProvider for ChainalysisClient {
    fn provider_name(&self) -> &str {
        "chainalysis"
    }

    async fn screen_address(
        &self,
        address: &str,
    ) -> std::result::Result<ScreeningResult, ComplianceError> {
        let url = format!(
            "{}/api/kyt/v2/users/{}/transfers",
            self.config.base_url, address
        );

        let response = self
            .http_client
            .get(&url)
            .header("Token", self.config.api_key.expose())
            .timeout(std::time::Duration::from_secs(
                self.config.timeout_seconds as u64,
            ))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ComplianceError::Timeout
                } else {
                    ComplianceError::ApiError(e.to_string())
                }
            })?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ComplianceError::AuthenticationFailed);
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ComplianceError::RateLimited);
        }

        if !response.status().is_success() {
            return Err(ComplianceError::ApiError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let data: ChainalysisResponse = response
            .json()
            .await
            .map_err(|e| ComplianceError::ApiError(e.to_string()))?;

        Ok(ScreeningResult {
            address: address.to_string(),
            risk_score: data.risk_score.unwrap_or(0.0),
            risk_category: data.risk_category,
            exposure: data.exposure.map(|e| ExposureInfo {
                direct: e.direct,
                indirect: e.indirect,
                categories: e
                    .categories
                    .into_iter()
                    .map(|c| ExposureCategory {
                        category: c.category,
                        percentage: c.percentage,
                    })
                    .collect(),
            }),
            alerts: data
                .alerts
                .unwrap_or_default()
                .into_iter()
                .map(|a| ComplianceAlert {
                    alert_id: a.alert_id,
                    severity: match a.severity.to_lowercase().as_str() {
                        "high" => AlertSeverity::High,
                        "critical" => AlertSeverity::Critical,
                        "medium" => AlertSeverity::Medium,
                        _ => AlertSeverity::Low,
                    },
                    category: a.category,
                    description: a.description,
                    created_at: a.created_at,
                })
                .collect(),
            screened_at: Utc::now(),
            provider: "chainalysis".into(),
        })
    }

    async fn register_transfer(
        &self,
        tx_hash: &str,
        output_address: &str,
        amount_btc: f64,
    ) -> std::result::Result<(), ComplianceError> {
        let url = format!("{}/api/kyt/v2/transfers", self.config.base_url);

        let request = RegisterTransferRequest {
            network: "Bitcoin".into(),
            asset: "BTC".into(),
            transfer_reference: tx_hash.into(),
            direction: "sent".into(),
            output_address: output_address.into(),
            amount: amount_btc,
        };

        let response = self
            .http_client
            .post(&url)
            .header("Token", self.config.api_key.expose())
            .json(&request)
            .timeout(std::time::Duration::from_secs(
                self.config.timeout_seconds as u64,
            ))
            .send()
            .await
            .map_err(|e| ComplianceError::ApiError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ComplianceError::ApiError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn health_check(&self) -> std::result::Result<(), ComplianceError> {
        let url = format!("{}/api/kyt/v2/health", self.config.base_url);

        let response = self
            .http_client
            .get(&url)
            .header("Token", self.config.api_key.expose())
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| ComplianceError::ApiError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ComplianceError::ApiError(format!(
                "HTTP {}",
                response.status()
            )))
        }
    }
}

#[derive(Debug, Deserialize)]
struct ChainalysisResponse {
    risk_score: Option<f64>,
    risk_category: Option<String>,
    exposure: Option<ChainalysisExposure>,
    alerts: Option<Vec<ChainalysisAlert>>,
}

#[derive(Debug, Deserialize)]
struct ChainalysisExposure {
    direct: f64,
    indirect: f64,
    categories: Vec<ChainalysisCategory>,
}

#[derive(Debug, Deserialize)]
struct ChainalysisCategory {
    category: String,
    percentage: f64,
}

#[derive(Debug, Deserialize)]
struct ChainalysisAlert {
    alert_id: String,
    severity: String,
    category: String,
    description: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct RegisterTransferRequest {
    network: String,
    asset: String,
    transfer_reference: String,
    direction: String,
    output_address: String,
    amount: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EllipticConfig {
    pub api_key: SecretValue,
    pub api_secret: SecretValue,
    pub base_url: String,
    pub timeout_seconds: u32,
}

impl EllipticConfig {
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("ELLIPTIC_API_KEY").unwrap_or_default().into(),
            api_secret: std::env::var("ELLIPTIC_API_SECRET")
                .unwrap_or_default()
                .into(),
            base_url: std::env::var("ELLIPTIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.elliptic.co".into()),
            timeout_seconds: 30,
        }
    }
}

impl Default for EllipticConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

pub struct EllipticClient {
    config: EllipticConfig,
    http_client: reqwest::Client,
}

const HMAC_MIN_KEY_LENGTH: usize = 32;

impl EllipticClient {
    pub fn new(config: EllipticConfig) -> std::result::Result<Self, ComplianceError> {
        validate_url(&config.base_url, &SsrfPolicy::strict())?;
        let key_len = config.api_secret.expose().len();
        if key_len < HMAC_MIN_KEY_LENGTH {
            return Err(ComplianceError::ConfigurationError(format!(
                "HMAC key must be at least {} bytes, got {}",
                HMAC_MIN_KEY_LENGTH, key_len
            )));
        }
        Ok(Self {
            config,
            http_client: reqwest::Client::new(),
        })
    }

    pub fn new_unchecked(config: EllipticConfig) -> std::result::Result<Self, ComplianceError> {
        let key_len = config.api_secret.expose().len();
        if key_len < HMAC_MIN_KEY_LENGTH {
            return Err(ComplianceError::ConfigurationError(format!(
                "HMAC key must be at least {} bytes, got {}",
                HMAC_MIN_KEY_LENGTH, key_len
            )));
        }
        Ok(Self {
            config,
            http_client: reqwest::Client::new(),
        })
    }
}

#[async_trait::async_trait]
impl ComplianceProvider for EllipticClient {
    fn provider_name(&self) -> &str {
        "elliptic"
    }

    async fn screen_address(
        &self,
        address: &str,
    ) -> std::result::Result<ScreeningResult, ComplianceError> {
        let url = format!("{}/v2/wallet/synchronous", self.config.base_url);

        let request = serde_json::json!({
            "subject": {
                "asset": "holistic",
                "blockchain": "bitcoin",
                "type": "address",
                "hash": address
            },
            "type": "wallet_exposure"
        });

        let (timestamp, signature) = self.sign_request(&request)?;
        let response = self
            .http_client
            .post(&url)
            .header("x-access-key", self.config.api_key.expose())
            .header("x-access-timestamp", &timestamp)
            .header("x-access-sign", signature)
            .json(&request)
            .timeout(std::time::Duration::from_secs(
                self.config.timeout_seconds as u64,
            ))
            .send()
            .await
            .map_err(|e| ComplianceError::ApiError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ComplianceError::AuthenticationFailed);
        }

        if !response.status().is_success() {
            return Err(ComplianceError::ApiError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let data: EllipticResponse = response
            .json()
            .await
            .map_err(|e| ComplianceError::ApiError(e.to_string()))?;

        Ok(ScreeningResult {
            address: address.to_string(),
            risk_score: data.risk_score.unwrap_or(0.0),
            risk_category: data.risk_score_detail.map(|d| d.risk_category),
            exposure: None,
            alerts: vec![],
            screened_at: Utc::now(),
            provider: "elliptic".into(),
        })
    }

    async fn register_transfer(
        &self,
        _tx_hash: &str,
        _output_address: &str,
        _amount_btc: f64,
    ) -> std::result::Result<(), ComplianceError> {
        Ok(())
    }

    async fn health_check(&self) -> std::result::Result<(), ComplianceError> {
        Ok(())
    }
}

impl EllipticClient {
    fn sign_request(
        &self,
        request: &serde_json::Value,
    ) -> std::result::Result<(String, String), ComplianceError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let body = serde_json::to_string(request).unwrap_or_default();
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let message = format!("{}{}", timestamp, body);

        let mut mac = Hmac::<Sha256>::new_from_slice(self.config.api_secret.expose().as_bytes())
            .map_err(|_| ComplianceError::ConfigurationError("Invalid HMAC key".into()))?;
        mac.update(message.as_bytes());
        let result = mac.finalize();

        Ok((timestamp, hex::encode(result.into_bytes())))
    }
}

#[derive(Debug, Deserialize)]
struct EllipticResponse {
    risk_score: Option<f64>,
    risk_score_detail: Option<EllipticRiskDetail>,
}

#[derive(Debug, Deserialize)]
struct EllipticRiskDetail {
    risk_category: String,
}

pub struct ComplianceCallbackHandler<P: ComplianceProvider> {
    provider: P,
    risk_threshold: f64,
}

impl<P: ComplianceProvider> ComplianceCallbackHandler<P> {
    pub fn new(provider: P, risk_threshold: f64) -> Self {
        Self {
            provider,
            risk_threshold,
        }
    }

    pub async fn handle(&self, request: CallbackRequest) -> CallbackResponse {
        let screening = match self
            .provider
            .screen_address(&request.transaction.destination)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                return CallbackResponse {
                    iss: self.provider.provider_name().into(),
                    aud: "warden".into(),
                    iat: Utc::now().timestamp(),
                    jti: request.jti,
                    decision: CallbackDecision::Retry,
                    reason: Some(format!("Screening failed: {}", e)),
                    metadata: HashMap::new(),
                    retry_after_seconds: Some(30),
                };
            }
        };

        if screening.risk_score > self.risk_threshold {
            return CallbackResponse {
                iss: self.provider.provider_name().into(),
                aud: "warden".into(),
                iat: Utc::now().timestamp(),
                jti: request.jti,
                decision: CallbackDecision::Reject,
                reason: Some(format!(
                    "High risk destination: {} (score: {:.2})",
                    screening.risk_category.as_deref().unwrap_or("unknown"),
                    screening.risk_score
                )),
                metadata: HashMap::new(),
                retry_after_seconds: None,
            };
        }

        if screening
            .alerts
            .iter()
            .any(|a| a.severity == AlertSeverity::High || a.severity == AlertSeverity::Critical)
        {
            return CallbackResponse {
                iss: self.provider.provider_name().into(),
                aud: "warden".into(),
                iat: Utc::now().timestamp(),
                jti: request.jti,
                decision: CallbackDecision::Reject,
                reason: Some("High severity compliance alert".into()),
                metadata: HashMap::new(),
                retry_after_seconds: None,
            };
        }

        CallbackResponse {
            iss: self.provider.provider_name().into(),
            aud: "warden".into(),
            iat: Utc::now().timestamp(),
            jti: request.jti,
            decision: CallbackDecision::Approve,
            reason: Some(format!(
                "Screening passed (score: {:.2})",
                screening.risk_score
            )),
            metadata: HashMap::new(),
            retry_after_seconds: None,
        }
    }
}

pub struct MockComplianceProvider {
    risk_scores: HashMap<String, f64>,
}

impl MockComplianceProvider {
    pub fn new() -> Self {
        Self {
            risk_scores: HashMap::new(),
        }
    }

    pub fn with_risk_score(mut self, address: &str, score: f64) -> Self {
        self.risk_scores.insert(address.to_string(), score);
        self
    }
}

impl Default for MockComplianceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ComplianceProvider for MockComplianceProvider {
    fn provider_name(&self) -> &str {
        "mock"
    }

    async fn screen_address(
        &self,
        address: &str,
    ) -> std::result::Result<ScreeningResult, ComplianceError> {
        let risk_score = self.risk_scores.get(address).copied().unwrap_or(0.1);

        Ok(ScreeningResult {
            address: address.to_string(),
            risk_score,
            risk_category: if risk_score > 0.7 {
                Some("high_risk".into())
            } else {
                Some("low_risk".into())
            },
            exposure: None,
            alerts: vec![],
            screened_at: Utc::now(),
            provider: "mock".into(),
        })
    }

    async fn register_transfer(
        &self,
        _tx_hash: &str,
        _output_address: &str,
        _amount_btc: f64,
    ) -> std::result::Result<(), ComplianceError> {
        Ok(())
    }

    async fn health_check(&self) -> std::result::Result<(), ComplianceError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_compliance_provider() {
        let provider = MockComplianceProvider::new()
            .with_risk_score("bc1q_risky", 0.9)
            .with_risk_score("bc1q_safe", 0.1);

        let risky = provider.screen_address("bc1q_risky").await.unwrap();
        assert!(risky.risk_score > 0.7);

        let safe = provider.screen_address("bc1q_safe").await.unwrap();
        assert!(safe.risk_score < 0.3);
    }

    #[test]
    fn test_alert_severity_serialization() {
        let high = AlertSeverity::High;
        let json = serde_json::to_string(&high).unwrap();
        assert_eq!(json, "\"high\"");
    }

    #[test]
    fn test_elliptic_client_rejects_short_hmac_key() {
        let config = EllipticConfig {
            api_key: "test-key".to_string().into(),
            api_secret: "short".to_string().into(),
            base_url: "https://api.elliptic.co".into(),
            timeout_seconds: 30,
        };
        let result = EllipticClient::new_unchecked(config);
        assert!(matches!(
            result,
            Err(ComplianceError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_elliptic_client_accepts_valid_hmac_key() {
        let valid_key = "a".repeat(HMAC_MIN_KEY_LENGTH);
        let config = EllipticConfig {
            api_key: "test-key".to_string().into(),
            api_secret: valid_key.into(),
            base_url: "https://api.elliptic.co".into(),
            timeout_seconds: 30,
        };
        let result = EllipticClient::new_unchecked(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_chainalysis_client_rejects_private_ip() {
        let config = ChainalysisConfig {
            api_key: "test-key".into(),
            base_url: "https://localhost/api".into(),
            timeout_seconds: 30,
        };
        let result = ChainalysisClient::new(config);
        assert!(matches!(result, Err(ComplianceError::SsrfBlocked(_))));
    }

    #[test]
    fn test_elliptic_client_rejects_private_ip() {
        let valid_key = "a".repeat(HMAC_MIN_KEY_LENGTH);
        let config = EllipticConfig {
            api_key: "test-key".into(),
            api_secret: valid_key.into(),
            base_url: "https://localhost/api".into(),
            timeout_seconds: 30,
        };
        let result = EllipticClient::new(config);
        assert!(matches!(result, Err(ComplianceError::SsrfBlocked(_))));
    }
}
