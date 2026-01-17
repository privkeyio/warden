#![forbid(unsafe_code)]

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Allow,
    #[default]
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub default_action: Action,
    #[serde(skip)]
    pub content_hash: Option<String>,
    #[serde(skip)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub is_active: bool,
}

impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let mut policy: Policy = serde_yaml::from_str(yaml)?;
        policy.compute_hash(yaml);
        policy.created_at = Some(Utc::now());
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let mut policy: Policy = serde_json::from_str(json)?;
        policy.compute_hash(json);
        policy.created_at = Some(Utc::now());
        policy.validate()?;
        Ok(policy)
    }

    fn compute_hash(&mut self, content: &str) {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        self.content_hash = Some(hex::encode(hasher.finalize()));
    }

    pub fn validate(&self) -> Result<()> {
        if self.version.is_empty() {
            return Err(Error::PolicyValidation("version is required".into()));
        }
        if self.name.is_empty() {
            return Err(Error::PolicyValidation("name is required".into()));
        }
        if self.name.len() > 128 {
            return Err(Error::PolicyValidation(
                "name must be 128 chars or less".into(),
            ));
        }
        if self.rules.is_empty() {
            return Err(Error::PolicyValidation(
                "at least one rule is required".into(),
            ));
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub conditions: Conditions,
    pub action: Action,
    #[serde(default)]
    pub approval: Option<ApprovalConfig>,
}

impl Rule {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::PolicyValidation("rule id is required".into()));
        }
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(Error::PolicyValidation(format!(
                "rule id '{}' must be lowercase alphanumeric with hyphens",
                self.id
            )));
        }
        if self.conditions.is_empty() && self.action != Action::RequireApproval {
            return Err(Error::PolicyValidation(format!(
                "rule '{}' has empty conditions which would match all transactions",
                self.id
            )));
        }
        if self.action == Action::RequireApproval && self.approval.is_none() {
            return Err(Error::PolicyValidation(format!(
                "rule '{}' requires approval config for REQUIRE_APPROVAL action",
                self.id
            )));
        }
        if let Some(ref approval) = self.approval {
            approval.validate()?;
        }
        if let Some(ref amount) = self.conditions.amount {
            amount.validate()?;
        }
        if let Some(ref time) = self.conditions.time_window {
            time.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    #[serde(default)]
    pub source_wallets: Option<Vec<String>>,
    #[serde(default)]
    pub destination: Option<DestinationCondition>,
    #[serde(default)]
    pub amount: Option<AmountCondition>,
    #[serde(default)]
    pub time_window: Option<TimeCondition>,
}

impl Conditions {
    pub fn is_empty(&self) -> bool {
        self.source_wallets.is_none()
            && self.destination.is_none()
            && self.amount.is_none()
            && self.time_window.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestinationCondition {
    #[serde(default)]
    pub addresses: Option<Vec<String>>,
    #[serde(default)]
    pub in_whitelist: Option<String>,
    #[serde(default)]
    pub in_blacklist: Option<String>,
    #[serde(default)]
    pub not_in_blacklist: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AmountCondition {
    #[serde(default)]
    pub min_sats: Option<u64>,
    #[serde(default)]
    pub max_sats: Option<u64>,
}

impl AmountCondition {
    pub fn validate(&self) -> Result<()> {
        if let (Some(min), Some(max)) = (self.min_sats, self.max_sats) {
            if min > max {
                return Err(Error::PolicyValidation(
                    "amount min_sats cannot exceed max_sats".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn matches(&self, amount_sats: u64) -> bool {
        if let Some(min) = self.min_sats {
            if amount_sats < min {
                return false;
            }
        }
        if let Some(max) = self.max_sats {
            if amount_sats > max {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeCondition {
    #[serde(default)]
    pub days_of_week: Option<Vec<DayOfWeek>>,
    #[serde(default)]
    pub hours_utc: Option<HourRange>,
}

impl TimeCondition {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref hours) = self.hours_utc {
            if hours.start > 23 || hours.end > 23 {
                return Err(Error::PolicyValidation("hour values must be 0-23".into()));
            }
        }
        Ok(())
    }

    pub fn matches(&self, timestamp: &DateTime<Utc>) -> bool {
        if let Some(ref days) = self.days_of_week {
            let weekday = timestamp.weekday();
            let day = match weekday {
                chrono::Weekday::Mon => DayOfWeek::Mon,
                chrono::Weekday::Tue => DayOfWeek::Tue,
                chrono::Weekday::Wed => DayOfWeek::Wed,
                chrono::Weekday::Thu => DayOfWeek::Thu,
                chrono::Weekday::Fri => DayOfWeek::Fri,
                chrono::Weekday::Sat => DayOfWeek::Sat,
                chrono::Weekday::Sun => DayOfWeek::Sun,
            };
            if !days.contains(&day) {
                return false;
            }
        }
        if let Some(ref hours) = self.hours_utc {
            let hour = timestamp.hour();
            if hours.start <= hours.end {
                if hour < hours.start || hour > hours.end {
                    return false;
                }
            } else if hour < hours.start && hour > hours.end {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DayOfWeek {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HourRange {
    pub start: u32,
    pub end: u32,
}

/// Configuration for multi-signature approval requirements.
///
/// When multiple groups are specified in `from_groups`, the approval uses OR semantics:
/// the quorum must be satisfied entirely within a single group. Approvals cannot be
/// mixed across groups to meet the threshold.
///
/// For example, with `quorum: 2` and `from_groups: ["treasury", "executives"]`:
/// - 2 approvals from "treasury" members -> satisfied
/// - 2 approvals from "executives" members -> satisfied
/// - 1 approval from "treasury" + 1 from "executives" -> NOT satisfied
///
/// To allow mixing approvals across groups, use `RequirementNode::k_of` directly
/// when constructing the workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalConfig {
    pub quorum: u32,
    pub from_groups: Vec<String>,
    #[serde(default = "default_timeout_hours")]
    pub timeout_hours: u32,
}

fn default_timeout_hours() -> u32 {
    24
}

impl ApprovalConfig {
    pub fn validate(&self) -> Result<()> {
        if self.quorum == 0 {
            return Err(Error::PolicyValidation("quorum must be at least 1".into()));
        }
        if self.from_groups.is_empty() {
            return Err(Error::PolicyValidation(
                "from_groups cannot be empty".into(),
            ));
        }
        if self.timeout_hours == 0 || self.timeout_hours > 168 {
            return Err(Error::PolicyValidation(
                "timeout_hours must be between 1 and 168".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
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

impl PolicyDecision {
    pub fn rule_id(&self) -> &str {
        match self {
            PolicyDecision::Allow { rule_id, .. } => rule_id,
            PolicyDecision::Deny { rule_id, .. } => rule_id,
            PolicyDecision::RequireApproval { rule_id, .. } => rule_id,
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_condition_matches() {
        let condition = AmountCondition {
            min_sats: Some(100_000),
            max_sats: Some(1_000_000),
        };
        assert!(!condition.matches(50_000));
        assert!(condition.matches(100_000));
        assert!(condition.matches(500_000));
        assert!(condition.matches(1_000_000));
        assert!(!condition.matches(1_000_001));
    }

    #[test]
    fn test_policy_from_yaml() {
        let yaml = r#"
version: "1.0"
name: "test-policy"
rules:
  - id: "allow-small"
    conditions:
      amount:
        max_sats: 100000
    action: ALLOW
default_action: DENY
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.default_action, Action::Deny);
    }

    #[test]
    fn test_rule_validation_empty_conditions() {
        let rule = Rule {
            id: "test".into(),
            description: None,
            conditions: Conditions::default(),
            action: Action::Allow,
            approval: None,
        };
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("empty conditions"));
    }

    #[test]
    fn test_rule_validation_require_approval_without_config() {
        let rule = Rule {
            id: "test".into(),
            description: None,
            conditions: Conditions {
                amount: Some(AmountCondition {
                    max_sats: Some(100_000),
                    min_sats: None,
                }),
                ..Conditions::default()
            },
            action: Action::RequireApproval,
            approval: None,
        };
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("requires approval config"));
    }
}
