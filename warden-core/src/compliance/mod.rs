#![forbid(unsafe_code)]

mod chainalysis;
mod elliptic;
mod handler;
mod retry;
mod types;

pub use chainalysis::{ChainalysisClient, ChainalysisConfig};
pub use elliptic::{EllipticClient, EllipticConfig};
pub use handler::{ComplianceCallbackHandler, MockComplianceProvider};
pub use retry::RetryingComplianceProvider;
pub use types::{
    AlertSeverity, ComplianceAlert, ComplianceError, ComplianceProvider, ExposureCategory,
    ExposureInfo, ScreeningResult,
};

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
        let valid_key = "a".repeat(elliptic::hmac_min_key_length());
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
        let valid_key = "a".repeat(elliptic::hmac_min_key_length());
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
