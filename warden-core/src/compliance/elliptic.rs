use crate::secrets::SecretValue;
use crate::ssrf::{validate_url, SsrfPolicy};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::types::{ComplianceError, ComplianceProvider, ScreeningResult};

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

#[derive(Debug, Deserialize)]
struct EllipticResponse {
    risk_score: Option<f64>,
    risk_score_detail: Option<EllipticRiskDetail>,
}

#[derive(Debug, Deserialize)]
struct EllipticRiskDetail {
    risk_category: String,
}

#[cfg(test)]
pub(crate) fn hmac_min_key_length() -> usize {
    HMAC_MIN_KEY_LENGTH
}
