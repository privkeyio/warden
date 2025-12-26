#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::pattern::matches_pattern;
use crate::policy::{Action, ApprovalConfig, PolicyDecision, Rule};
use crate::store::{AddressListStore, PolicyStore};
use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub id: Uuid,
    pub source_wallet: String,
    pub destination: String,
    pub amount_sats: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TransactionRequest {
    pub fn new(source_wallet: String, destination: String, amount_sats: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_wallet,
            destination,
            amount_sats,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }
}

pub struct EvaluationContext<'a> {
    pub transaction: &'a TransactionRequest,
    whitelist_store: Arc<dyn AddressListStore>,
    blacklist_store: Arc<dyn AddressListStore>,
}

impl<'a> EvaluationContext<'a> {
    pub fn new(
        transaction: &'a TransactionRequest,
        whitelist_store: Arc<dyn AddressListStore>,
        blacklist_store: Arc<dyn AddressListStore>,
    ) -> Self {
        Self {
            transaction,
            whitelist_store,
            blacklist_store,
        }
    }

    pub async fn address_in_whitelist(&self, list_name: &str, address: &str) -> Result<bool> {
        self.whitelist_store.contains(list_name, address).await
    }

    pub async fn address_in_blacklist(&self, list_name: &str, address: &str) -> Result<bool> {
        self.blacklist_store.contains(list_name, address).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTraceEntry {
    pub rule_id: String,
    pub matched: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub decision: PolicyDecisionSerde,
    pub policy_id: Uuid,
    pub policy_version: String,
    pub evaluated_at: DateTime<Utc>,
    pub evaluation_time_us: u64,
    pub rules_evaluated: u32,
    pub trace: Vec<RuleTraceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecisionSerde {
    Allow {
        rule_id: String,
        reason: String,
    },
    Deny {
        rule_id: String,
        reason: String,
    },
    RequireApproval {
        rule_id: String,
        approval_config: ApprovalConfig,
    },
}

impl From<PolicyDecision> for PolicyDecisionSerde {
    fn from(d: PolicyDecision) -> Self {
        match d {
            PolicyDecision::Allow { rule_id, reason } => {
                PolicyDecisionSerde::Allow { rule_id, reason }
            }
            PolicyDecision::Deny { rule_id, reason } => {
                PolicyDecisionSerde::Deny { rule_id, reason }
            }
            PolicyDecision::RequireApproval {
                rule_id,
                approval_config,
            } => PolicyDecisionSerde::RequireApproval {
                rule_id,
                approval_config,
            },
        }
    }
}

pub struct PolicyEvaluator {
    policy_store: Arc<dyn PolicyStore>,
    whitelist_store: Arc<dyn AddressListStore>,
    blacklist_store: Arc<dyn AddressListStore>,
}

impl PolicyEvaluator {
    pub fn new(
        policy_store: Arc<dyn PolicyStore>,
        whitelist_store: Arc<dyn AddressListStore>,
        blacklist_store: Arc<dyn AddressListStore>,
    ) -> Self {
        Self {
            policy_store,
            whitelist_store,
            blacklist_store,
        }
    }

    pub async fn evaluate(&self, request: &TransactionRequest) -> Result<EvaluationResult> {
        let start = Instant::now();
        let mut trace = Vec::new();

        let policy = self
            .policy_store
            .get_active_policy(&request.source_wallet)
            .await?
            .ok_or_else(|| Error::NoPolicyFound(request.source_wallet.clone()))?;

        let context = EvaluationContext::new(
            request,
            Arc::clone(&self.whitelist_store),
            Arc::clone(&self.blacklist_store),
        );

        for rule in &policy.rules {
            let match_result = self.evaluate_rule(rule, &context).await?;

            trace.push(RuleTraceEntry {
                rule_id: rule.id.clone(),
                matched: match_result.is_match(),
                details: match_result.details(),
            });

            if match_result.is_match() {
                return Ok(EvaluationResult {
                    decision: self.rule_to_decision(rule)?.into(),
                    policy_id: policy.id,
                    policy_version: policy.version.clone(),
                    evaluated_at: Utc::now(),
                    evaluation_time_us: start.elapsed().as_micros() as u64,
                    rules_evaluated: trace.len() as u32,
                    trace,
                });
            }
        }

        Ok(EvaluationResult {
            decision: self
                .default_to_decision(&policy.default_action, &policy.id.to_string())
                .into(),
            policy_id: policy.id,
            policy_version: policy.version.clone(),
            evaluated_at: Utc::now(),
            evaluation_time_us: start.elapsed().as_micros() as u64,
            rules_evaluated: trace.len() as u32,
            trace,
        })
    }

    async fn evaluate_rule(
        &self,
        rule: &Rule,
        context: &EvaluationContext<'_>,
    ) -> Result<MatchResult> {
        if rule.conditions.is_empty() {
            return Ok(MatchResult::Match("empty conditions (matches all)".into()));
        }

        if let Some(ref patterns) = rule.conditions.source_wallets {
            let matched = patterns
                .iter()
                .any(|p| matches_pattern(p, &context.transaction.source_wallet));
            if !matched {
                return Ok(MatchResult::NoMatch(
                    "source_wallet pattern mismatch".into(),
                ));
            }
        }

        if let Some(ref dest) = rule.conditions.destination {
            if !self.check_destination(dest, context).await? {
                return Ok(MatchResult::NoMatch("destination condition failed".into()));
            }
        }

        if let Some(ref amount) = rule.conditions.amount {
            if !amount.matches(context.transaction.amount_sats) {
                let detail = if let Some(min) = amount.min_sats {
                    if context.transaction.amount_sats < min {
                        format!(
                            "amount {} below min {}",
                            context.transaction.amount_sats, min
                        )
                    } else {
                        format!(
                            "amount {} above max {}",
                            context.transaction.amount_sats,
                            amount.max_sats.unwrap_or(0)
                        )
                    }
                } else {
                    format!(
                        "amount {} above max {}",
                        context.transaction.amount_sats,
                        amount.max_sats.unwrap_or(0)
                    )
                };
                return Ok(MatchResult::NoMatch(detail));
            }
        }

        if let Some(ref time) = rule.conditions.time_window {
            if !time.matches(&context.transaction.timestamp) {
                return Ok(MatchResult::NoMatch("outside allowed time window".into()));
            }
        }

        Ok(MatchResult::Match("all conditions met".into()))
    }

    async fn check_destination(
        &self,
        dest: &crate::policy::DestinationCondition,
        context: &EvaluationContext<'_>,
    ) -> Result<bool> {
        if let Some(ref addresses) = dest.addresses {
            if !addresses.contains(&context.transaction.destination) {
                return Ok(false);
            }
        }

        if let Some(ref whitelist) = dest.in_whitelist {
            if !context
                .address_in_whitelist(whitelist, &context.transaction.destination)
                .await?
            {
                return Ok(false);
            }
        }

        if let Some(ref blacklist) = dest.in_blacklist {
            if !context
                .address_in_blacklist(blacklist, &context.transaction.destination)
                .await?
            {
                return Ok(false);
            }
        }

        if let Some(ref blacklist) = dest.not_in_blacklist {
            if context
                .address_in_blacklist(blacklist, &context.transaction.destination)
                .await?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn rule_to_decision(&self, rule: &Rule) -> Result<PolicyDecision> {
        match &rule.action {
            Action::Allow => Ok(PolicyDecision::Allow {
                rule_id: rule.id.clone(),
                reason: rule.description.clone().unwrap_or_else(|| "allowed".into()),
            }),
            Action::Deny => Ok(PolicyDecision::Deny {
                rule_id: rule.id.clone(),
                reason: rule.description.clone().unwrap_or_else(|| "denied".into()),
            }),
            Action::RequireApproval => match rule.approval.clone() {
                Some(approval_config) => Ok(PolicyDecision::RequireApproval {
                    rule_id: rule.id.clone(),
                    approval_config,
                }),
                None => Err(Error::Evaluation(format!(
                    "rule '{}' has REQUIRE_APPROVAL action but no approval config",
                    rule.id
                ))),
            },
        }
    }

    fn default_to_decision(&self, action: &Action, policy_id: &str) -> PolicyDecision {
        match action {
            Action::Allow => PolicyDecision::Allow {
                rule_id: "default".into(),
                reason: format!("default action for policy {}", policy_id),
            },
            Action::Deny => PolicyDecision::Deny {
                rule_id: "default".into(),
                reason: format!("default action for policy {}", policy_id),
            },
            Action::RequireApproval => PolicyDecision::Deny {
                rule_id: "default".into(),
                reason: "default REQUIRE_APPROVAL treated as DENY without explicit config".into(),
            },
        }
    }
}

enum MatchResult {
    Match(String),
    NoMatch(String),
}

impl MatchResult {
    fn is_match(&self) -> bool {
        matches!(self, MatchResult::Match(_))
    }

    fn details(&self) -> String {
        match self {
            MatchResult::Match(s) => s.clone(),
            MatchResult::NoMatch(s) => s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_request() {
        let tx = TransactionRequest::new("treasury-hot-1".into(), "bc1qtest".into(), 1_000_000);
        assert_eq!(tx.source_wallet, "treasury-hot-1");
        assert_eq!(tx.amount_sats, 1_000_000);
    }
}
