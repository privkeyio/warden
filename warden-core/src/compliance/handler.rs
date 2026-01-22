use crate::callback::{CallbackDecision, CallbackRequest, CallbackResponse};
use chrono::Utc;
use std::collections::HashMap;

use super::types::{AlertSeverity, ComplianceProvider, ScreeningResult};

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
    ) -> std::result::Result<ScreeningResult, super::types::ComplianceError> {
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
    ) -> std::result::Result<(), super::types::ComplianceError> {
        Ok(())
    }

    async fn health_check(&self) -> std::result::Result<(), super::types::ComplianceError> {
        Ok(())
    }
}
