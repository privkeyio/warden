use crate::retry::{ClassifyError, ErrorKind};
use crate::ssrf::SsrfError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

impl ClassifyError for ComplianceError {
    fn error_kind(&self) -> ErrorKind {
        match self {
            Self::Timeout => ErrorKind::Timeout,
            Self::RateLimited => ErrorKind::RateLimited,
            Self::AuthenticationFailed => ErrorKind::Unauthorized,
            Self::AddressNotFound(_) => ErrorKind::NotFound,
            Self::ConfigurationError(_) => ErrorKind::InvalidArgument,
            Self::SsrfBlocked(_) => ErrorKind::Permanent,
            Self::ApiError(_) => ErrorKind::Transient,
        }
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
