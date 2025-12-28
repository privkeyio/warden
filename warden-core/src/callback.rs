#![forbid(unsafe_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackRequest {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub request_type: String,
    pub transaction: TransactionDetails,
    pub policy_context: PolicyContext,
    pub callback_config: CallbackConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetails {
    pub id: String,
    pub source_wallet: String,
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub policy_id: String,
    pub policy_version: String,
    pub matched_rule_id: Option<String>,
    pub evaluation_trace: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallbackConfig {
    pub timeout_seconds: Option<u32>,
    pub include_metadata: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackResponse {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub jti: String,
    pub decision: CallbackDecision,
    pub reason: Option<String>,
    pub metadata: HashMap<String, Value>,
    pub retry_after_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallbackDecision {
    Approve,
    Reject,
    Retry,
}

#[derive(Debug, Clone)]
pub struct CallbackResult {
    pub decision: CallbackDecision,
    pub reason: Option<String>,
    pub metadata: HashMap<String, Value>,
    pub handler_id: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackHandlerConfig {
    pub id: String,
    pub url: String,
    pub public_key: Option<String>,
    pub timeout_seconds: u32,
    pub enabled: bool,
    pub max_retries: u32,
}

impl Default for CallbackHandlerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            url: String::new(),
            public_key: None,
            timeout_seconds: 30,
            enabled: true,
            max_retries: 3,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CallbackError {
    #[error("Handler not found: {0}")]
    HandlerNotFound(String),
    #[error("Handler disabled: {0}")]
    HandlerDisabled(String),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("Timeout")]
    Timeout,
    #[error("JTI mismatch")]
    JtiMismatch,
    #[error("Invalid audience")]
    InvalidAudience,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Max retries exceeded")]
    MaxRetriesExceeded,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl CallbackError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::HttpError(_) | Self::Timeout)
    }
}

pub struct CallbackGateway {
    http_client: reqwest::Client,
    handlers: HashMap<String, CallbackHandlerConfig>,
    max_retries: u32,
}

impl CallbackGateway {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
            handlers: HashMap::new(),
            max_retries: 3,
        }
    }

    pub fn with_handler(mut self, config: CallbackHandlerConfig) -> Self {
        self.handlers.insert(config.id.clone(), config);
        self
    }

    pub fn register_handler(&mut self, config: CallbackHandlerConfig) {
        self.handlers.insert(config.id.clone(), config);
    }

    pub fn remove_handler(&mut self, handler_id: &str) {
        self.handlers.remove(handler_id);
    }

    pub async fn invoke(
        &self,
        handler_id: &str,
        transaction: &TransactionDetails,
        policy_context: &PolicyContext,
    ) -> std::result::Result<CallbackResult, CallbackError> {
        let handler = self
            .handlers
            .get(handler_id)
            .ok_or_else(|| CallbackError::HandlerNotFound(handler_id.to_string()))?;

        if !handler.enabled {
            return Err(CallbackError::HandlerDisabled(handler_id.to_string()));
        }

        let request = CallbackRequest {
            iss: "warden".into(),
            aud: handler_id.into(),
            iat: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 60,
            jti: Uuid::new_v4().to_string(),
            request_type: "transaction_authorization".into(),
            transaction: transaction.clone(),
            policy_context: policy_context.clone(),
            callback_config: CallbackConfig::default(),
        };

        let request_json = serde_json::to_string(&request)
            .map_err(|e| CallbackError::SerializationError(e.to_string()))?;

        let mut attempts = 0;
        let max_retries = handler.max_retries.min(self.max_retries);
        let mut last_error = None;

        while attempts < max_retries {
            let start = std::time::Instant::now();

            match self
                .send_request(handler, &request_json, &request.jti)
                .await
            {
                Ok(response) => {
                    return Ok(CallbackResult {
                        decision: response.decision,
                        reason: response.reason,
                        metadata: response.metadata,
                        handler_id: handler_id.into(),
                        latency_ms: start.elapsed().as_millis() as u64,
                    });
                }
                Err(e) if e.is_retryable() => {
                    last_error = Some(e);
                    attempts += 1;

                    let delay = Duration::from_millis(100 * 2u64.pow(attempts));
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error.unwrap_or(CallbackError::MaxRetriesExceeded))
    }

    async fn send_request(
        &self,
        handler: &CallbackHandlerConfig,
        request_json: &str,
        expected_jti: &str,
    ) -> std::result::Result<CallbackResponse, CallbackError> {
        let timeout = Duration::from_secs(handler.timeout_seconds as u64);

        let response = self
            .http_client
            .post(&handler.url)
            .header("Content-Type", "application/json")
            .header("X-Warden-Request-Id", expected_jti)
            .body(request_json.to_string())
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    CallbackError::Timeout
                } else {
                    CallbackError::HttpError(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            return Err(CallbackError::HttpError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| CallbackError::HttpError(e.to_string()))?;

        let callback_response: CallbackResponse = serde_json::from_str(&response_text)
            .map_err(|e| CallbackError::SerializationError(e.to_string()))?;

        if callback_response.jti != expected_jti {
            return Err(CallbackError::JtiMismatch);
        }

        if callback_response.aud != "warden" {
            return Err(CallbackError::InvalidAudience);
        }

        Ok(callback_response)
    }

    pub fn list_handlers(&self) -> Vec<&CallbackHandlerConfig> {
        self.handlers.values().collect()
    }

    pub fn get_handler(&self, id: &str) -> Option<&CallbackHandlerConfig> {
        self.handlers.get(id)
    }
}

impl Default for CallbackGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackRuleConfig {
    pub handler: String,
    pub on_approve: CallbackAction,
    pub on_reject: CallbackAction,
    pub on_timeout: CallbackAction,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallbackAction {
    Allow,
    Deny,
    RequireApproval,
}

impl Default for CallbackRuleConfig {
    fn default() -> Self {
        Self {
            handler: String::new(),
            on_approve: CallbackAction::Allow,
            on_reject: CallbackAction::Deny,
            on_timeout: CallbackAction::RequireApproval,
            timeout_seconds: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_decision_serialization() {
        let approve = CallbackDecision::Approve;
        let json = serde_json::to_string(&approve).unwrap();
        assert_eq!(json, "\"APPROVE\"");

        let reject = CallbackDecision::Reject;
        let json = serde_json::to_string(&reject).unwrap();
        assert_eq!(json, "\"REJECT\"");
    }

    #[test]
    fn test_callback_error_retryable() {
        assert!(CallbackError::Timeout.is_retryable());
        assert!(CallbackError::HttpError("connection failed".into()).is_retryable());
        assert!(!CallbackError::JtiMismatch.is_retryable());
        assert!(!CallbackError::InvalidAudience.is_retryable());
    }

    #[test]
    fn test_callback_handler_config_default() {
        let config = CallbackHandlerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.max_retries, 3);
    }
}
