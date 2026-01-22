use crate::secrets::SecretValue;
use crate::ssrf::{validate_url, SsrfPolicy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::{
    AlertSeverity, ComplianceAlert, ComplianceError, ComplianceProvider, ExposureCategory,
    ExposureInfo, ScreeningResult,
};

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
