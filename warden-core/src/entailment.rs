#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crate::policy::{
    Action, AmountCondition, Conditions, DayOfWeek, DestinationCondition, HourRange, Policy, Rule,
    TimeCondition,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPolicy {
    pub rules: Vec<SemanticRule>,
    pub default_action: SemanticAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticRule {
    pub id: String,
    pub condition: NormalizedCondition,
    pub action: SemanticAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticAction {
    Allow,
    Deny,
    RequireApproval,
}

impl From<&Action> for SemanticAction {
    fn from(action: &Action) -> Self {
        match action {
            Action::Allow => SemanticAction::Allow,
            Action::Deny => SemanticAction::Deny,
            Action::RequireApproval => SemanticAction::RequireApproval,
        }
    }
}

impl SemanticAction {
    /// Returns true if this action grants a permission (Allow or RequireApproval).
    /// Both Allow and RequireApproval are considered permission tiers that can
    /// enable requests to proceed, unlike Deny which blocks them.
    pub fn is_permission_tier(self) -> bool {
        matches!(
            self,
            SemanticAction::Allow | SemanticAction::RequireApproval
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedCondition {
    True,
    False,
    AmountRange {
        min: Option<u64>,
        max: Option<u64>,
    },
    SourceWallet {
        patterns: BTreeSet<String>,
    },
    AddressIn {
        list: String,
    },
    AddressNotIn {
        list: String,
    },
    AddressExact {
        addresses: BTreeSet<String>,
    },
    TimeWindow {
        days: Option<BTreeSet<DayOfWeek>>,
        hours: Option<NormalizedHourRange>,
    },
    And(Vec<NormalizedCondition>),
    Or(Vec<NormalizedCondition>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHourRange {
    pub start: u32,
    pub end: u32,
}

impl From<&HourRange> for NormalizedHourRange {
    fn from(hr: &HourRange) -> Self {
        Self {
            start: hr.start,
            end: hr.end,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntailmentResult {
    Entails,
    DoesNotEntail { reason: String },
    Unknown { reason: String },
}

impl EntailmentResult {
    pub fn is_entailed(&self) -> bool {
        matches!(self, EntailmentResult::Entails)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counterexample {
    pub description: String,
    pub amount_sats: Option<u64>,
    pub source_wallet: Option<String>,
    pub destination: Option<String>,
    pub time_description: Option<String>,
}

impl Policy {
    pub fn to_semantic(&self) -> SemanticPolicy {
        let rules = self
            .rules
            .iter()
            .map(|r| SemanticRule {
                id: r.id.clone(),
                condition: normalize_conditions(&r.conditions),
                action: SemanticAction::from(&r.action),
            })
            .collect();

        SemanticPolicy {
            rules,
            default_action: SemanticAction::from(&self.default_action),
        }
    }
}

impl Rule {
    pub fn to_semantic(&self) -> SemanticRule {
        SemanticRule {
            id: self.id.clone(),
            condition: normalize_conditions(&self.conditions),
            action: SemanticAction::from(&self.action),
        }
    }
}

fn normalize_conditions(cond: &Conditions) -> NormalizedCondition {
    let mut parts = Vec::new();

    if let Some(ref wallets) = cond.source_wallets {
        if !wallets.is_empty() {
            parts.push(NormalizedCondition::SourceWallet {
                patterns: wallets.iter().cloned().collect(),
            });
        }
    }

    if let Some(ref dest) = cond.destination {
        parts.extend(normalize_destination(dest));
    }

    if let Some(ref amount) = cond.amount {
        parts.push(normalize_amount(amount));
    }

    if let Some(ref time) = cond.time_window {
        parts.push(normalize_time(time));
    }

    match parts.len() {
        0 => NormalizedCondition::True,
        1 => parts.into_iter().next().expect("length checked"),
        _ => NormalizedCondition::And(parts),
    }
}

fn normalize_destination(dest: &DestinationCondition) -> Vec<NormalizedCondition> {
    let mut parts = Vec::new();

    if let Some(ref addresses) = dest.addresses {
        if !addresses.is_empty() {
            parts.push(NormalizedCondition::AddressExact {
                addresses: addresses.iter().cloned().collect(),
            });
        }
    }

    if let Some(ref whitelist) = dest.in_whitelist {
        parts.push(NormalizedCondition::AddressIn {
            list: whitelist.clone(),
        });
    }

    if let Some(ref blacklist) = dest.in_blacklist {
        parts.push(NormalizedCondition::AddressIn {
            list: blacklist.clone(),
        });
    }

    if let Some(ref blacklist) = dest.not_in_blacklist {
        parts.push(NormalizedCondition::AddressNotIn {
            list: blacklist.clone(),
        });
    }

    parts
}

fn normalize_amount(amount: &AmountCondition) -> NormalizedCondition {
    NormalizedCondition::AmountRange {
        min: amount.min_sats,
        max: amount.max_sats,
    }
}

fn normalize_time(time: &TimeCondition) -> NormalizedCondition {
    NormalizedCondition::TimeWindow {
        days: time
            .days_of_week
            .as_ref()
            .map(|d| d.iter().copied().collect()),
        hours: time.hours_utc.as_ref().map(NormalizedHourRange::from),
    }
}

impl SemanticPolicy {
    pub fn entails(&self, other: &SemanticPolicy) -> EntailmentResult {
        // Check all rules that grant permissions (Allow or RequireApproval)
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.action.is_permission_tier() {
                let covered = self.is_permission_tier_covered_by(rule, other);
                if !covered {
                    return EntailmentResult::DoesNotEntail {
                        reason: format!(
                            "rule '{}' (index {}) grants permissions not covered by other policy",
                            rule.id, i
                        ),
                    };
                }
            }
        }

        // Check if default action grants permissions
        if self.default_action.is_permission_tier() && !self.default_covered_by(other) {
            return EntailmentResult::DoesNotEntail {
                reason: "default action permits requests not covered by other policy".into(),
            };
        }

        EntailmentResult::Entails
    }

    /// Checks if a rule granting permissions is covered by the other policy.
    /// A permission-granting rule (Allow or RequireApproval) is covered if the
    /// other policy has a default permission tier or has a permission-granting
    /// rule with a superset condition.
    fn is_permission_tier_covered_by(&self, rule: &SemanticRule, other: &SemanticPolicy) -> bool {
        other.default_action.is_permission_tier()
            || other.rules.iter().any(|other_rule| {
                other_rule.action.is_permission_tier()
                    && rule.condition.is_subset_of(&other_rule.condition)
            })
    }

    /// Checks if the default permission action is covered by the other policy.
    fn default_covered_by(&self, other: &SemanticPolicy) -> bool {
        other.default_action.is_permission_tier()
    }

    /// Returns counterexamples showing requests that would be permitted by this
    /// policy but not by the other policy. Includes both Allow and RequireApproval
    /// actions as permission-granting.
    pub fn difference(&self, other: &SemanticPolicy) -> Vec<Counterexample> {
        let mut examples = Vec::new();

        for rule in &self.rules {
            if rule.action.is_permission_tier() && !self.is_permission_tier_covered_by(rule, other)
            {
                if let Some(ce) = generate_counterexample(&rule.condition) {
                    examples.push(ce);
                }
            }
        }

        examples
    }

    pub fn find_redundant_rules(&self) -> Vec<RedundantRule> {
        let mut redundant = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            for (j, prior) in self.rules.iter().enumerate().take(i) {
                if prior.condition.is_superset_of(&rule.condition) {
                    redundant.push(RedundantRule {
                        rule_id: rule.id.clone(),
                        rule_index: i,
                        shadowed_by_id: prior.id.clone(),
                        shadowed_by_index: j,
                    });
                    break;
                }
            }
        }

        redundant
    }

    pub fn find_conflicts(&self) -> Vec<PolicyConflict> {
        let mut conflicts = Vec::new();

        for (i, rule_a) in self.rules.iter().enumerate() {
            for (j, rule_b) in self.rules.iter().enumerate().skip(i + 1) {
                if rule_a.action != rule_b.action && rule_a.condition.overlaps(&rule_b.condition) {
                    conflicts.push(PolicyConflict {
                        rule_a_id: rule_a.id.clone(),
                        rule_a_index: i,
                        rule_b_id: rule_b.id.clone(),
                        rule_b_index: j,
                        action_a: rule_a.action,
                        action_b: rule_b.action,
                    });
                }
            }
        }

        conflicts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedundantRule {
    pub rule_id: String,
    pub rule_index: usize,
    pub shadowed_by_id: String,
    pub shadowed_by_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConflict {
    pub rule_a_id: String,
    pub rule_a_index: usize,
    pub rule_b_id: String,
    pub rule_b_index: usize,
    pub action_a: SemanticAction,
    pub action_b: SemanticAction,
}

impl NormalizedCondition {
    pub fn is_subset_of(&self, other: &NormalizedCondition) -> bool {
        match (self, other) {
            (_, NormalizedCondition::True) => true,
            (NormalizedCondition::False, _) => true,
            (NormalizedCondition::True, _) => false,

            (
                NormalizedCondition::AmountRange {
                    min: min1,
                    max: max1,
                },
                NormalizedCondition::AmountRange {
                    min: min2,
                    max: max2,
                },
            ) => {
                let lower_ok = match (min1, min2) {
                    (_, None) => true,
                    (None, Some(_)) => false,
                    (Some(a), Some(b)) => a >= b,
                };
                let upper_ok = match (max1, max2) {
                    (_, None) => true,
                    (None, Some(_)) => false,
                    (Some(a), Some(b)) => a <= b,
                };
                lower_ok && upper_ok
            }

            (
                NormalizedCondition::SourceWallet { patterns: p1 },
                NormalizedCondition::SourceWallet { patterns: p2 },
            ) => {
                if p2.iter().any(|p| p == "*") {
                    return true;
                }
                p1.iter().all(|p| p2.contains(p) || pattern_covered(p, p2))
            }

            (
                NormalizedCondition::AddressExact { addresses: a1 },
                NormalizedCondition::AddressExact { addresses: a2 },
            ) => a1.is_subset(a2),

            (
                NormalizedCondition::AddressIn { list: l1 },
                NormalizedCondition::AddressIn { list: l2 },
            ) => l1 == l2,

            (
                NormalizedCondition::AddressNotIn { list: l1 },
                NormalizedCondition::AddressNotIn { list: l2 },
            ) => l1 == l2,

            (
                NormalizedCondition::TimeWindow {
                    days: d1,
                    hours: h1,
                },
                NormalizedCondition::TimeWindow {
                    days: d2,
                    hours: h2,
                },
            ) => {
                let days_ok = match (d1, d2) {
                    (_, None) => true,
                    (None, Some(_)) => false,
                    (Some(a), Some(b)) => a.is_subset(b),
                };
                let hours_ok = match (h1, h2) {
                    (_, None) => true,
                    (None, Some(_)) => false,
                    (Some(a), Some(b)) => hour_range_subset(a, b),
                };
                days_ok && hours_ok
            }

            // And-vs-And: all conjuncts in self must be covered by some conjunct in other
            (NormalizedCondition::And(a_parts), NormalizedCondition::And(b_parts)) => a_parts
                .iter()
                .all(|p| b_parts.iter().any(|q| p.is_subset_of(q))),

            (NormalizedCondition::And(parts), other) => parts.iter().any(|p| p.is_subset_of(other)),

            (cond, NormalizedCondition::And(parts)) => parts.iter().all(|p| cond.is_subset_of(p)),

            (NormalizedCondition::Or(parts), other) => parts.iter().all(|p| p.is_subset_of(other)),

            (cond, NormalizedCondition::Or(parts)) => parts.iter().any(|p| cond.is_subset_of(p)),

            _ => false,
        }
    }

    pub fn is_superset_of(&self, other: &NormalizedCondition) -> bool {
        other.is_subset_of(self)
    }

    pub fn overlaps(&self, other: &NormalizedCondition) -> bool {
        match (self, other) {
            (NormalizedCondition::False, _) | (_, NormalizedCondition::False) => false,
            (NormalizedCondition::True, _) | (_, NormalizedCondition::True) => true,

            (
                NormalizedCondition::AmountRange {
                    min: min1,
                    max: max1,
                },
                NormalizedCondition::AmountRange {
                    min: min2,
                    max: max2,
                },
            ) => {
                let low1 = min1.unwrap_or(0);
                let high1 = max1.unwrap_or(u64::MAX);
                let low2 = min2.unwrap_or(0);
                let high2 = max2.unwrap_or(u64::MAX);
                low1 <= high2 && low2 <= high1
            }

            (
                NormalizedCondition::SourceWallet { patterns: p1 },
                NormalizedCondition::SourceWallet { patterns: p2 },
            ) => {
                if p1.iter().any(|p| p == "*") || p2.iter().any(|p| p == "*") {
                    return true;
                }
                p1.iter()
                    .any(|a| p2.iter().any(|b| patterns_may_overlap(a, b)))
            }

            (
                NormalizedCondition::AddressExact { addresses: a1 },
                NormalizedCondition::AddressExact { addresses: a2 },
            ) => !a1.is_disjoint(a2),

            (
                NormalizedCondition::AddressIn { list: l1 },
                NormalizedCondition::AddressIn { list: l2 },
            ) => l1 == l2,

            (
                NormalizedCondition::TimeWindow {
                    days: d1,
                    hours: h1,
                },
                NormalizedCondition::TimeWindow {
                    days: d2,
                    hours: h2,
                },
            ) => {
                let days_overlap = match (d1, d2) {
                    (None, _) | (_, None) => true,
                    (Some(a), Some(b)) => !a.is_disjoint(b),
                };
                let hours_overlap = match (h1, h2) {
                    (None, _) | (_, None) => true,
                    (Some(a), Some(b)) => hour_ranges_overlap(a, b),
                };
                days_overlap && hours_overlap
            }

            (NormalizedCondition::And(parts), other) | (other, NormalizedCondition::And(parts)) => {
                parts.iter().all(|p| p.overlaps(other))
            }

            (NormalizedCondition::Or(parts), other) | (other, NormalizedCondition::Or(parts)) => {
                parts.iter().any(|p| p.overlaps(other))
            }

            _ => true,
        }
    }
}

fn hour_range_subset(inner: &NormalizedHourRange, outer: &NormalizedHourRange) -> bool {
    let outer_wraps = outer.start > outer.end;
    let inner_wraps = inner.start > inner.end;

    match (outer_wraps, inner_wraps) {
        // Neither wraps: simple containment check
        (false, false) => inner.start >= outer.start && inner.end <= outer.end,
        // Outer wraps but inner doesn't: inner must fit entirely in one segment
        (true, false) => {
            (inner.start >= outer.start && inner.end >= outer.start)
                || (inner.start <= outer.end && inner.end <= outer.end)
        }
        // Both wrap: inner must be contained within outer's wrapped range
        (true, true) => inner.start >= outer.start && inner.end <= outer.end,
        // Inner wraps but outer doesn't: impossible to be a subset
        (false, true) => false,
    }
}

fn hour_ranges_overlap(a: &NormalizedHourRange, b: &NormalizedHourRange) -> bool {
    let a_hours = expand_hour_range(a);
    let b_hours = expand_hour_range(b);
    a_hours.iter().any(|h| b_hours.contains(h))
}

fn expand_hour_range(hr: &NormalizedHourRange) -> BTreeSet<u32> {
    if hr.start <= hr.end {
        (hr.start..=hr.end).collect()
    } else {
        (hr.start..=23).chain(0..=hr.end).collect()
    }
}

fn pattern_covered(pattern: &str, set: &BTreeSet<String>) -> bool {
    set.iter().any(|p| pattern_matches(p, pattern))
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    pattern == value
}

fn patterns_may_overlap(a: &str, b: &str) -> bool {
    if a == "*" || b == "*" {
        return true;
    }

    let a_suffix_wild = a.strip_suffix('*');
    let b_suffix_wild = b.strip_suffix('*');
    let a_prefix_wild = a.strip_prefix('*');
    let b_prefix_wild = b.strip_prefix('*');

    match (a_suffix_wild, b_suffix_wild, a_prefix_wild, b_prefix_wild) {
        // Both are suffix wildcards: foo* vs bar*
        (Some(ap), Some(bp), _, _) => ap.starts_with(bp) || bp.starts_with(ap),
        // Both are prefix wildcards: *foo vs *bar
        (_, _, Some(as_), Some(bs)) => as_.ends_with(bs) || bs.ends_with(as_),
        // Suffix vs prefix wildcard: foo* vs *bar - may overlap if foo+bar is valid
        (Some(_), None, _, Some(_)) | (None, Some(_), Some(_), _) => true,
        // Suffix wildcard vs literal
        (Some(ap), None, _, _) => b.starts_with(ap),
        (None, Some(bp), _, _) => a.starts_with(bp),
        // Prefix wildcard vs literal
        (_, _, Some(as_), None) => b.ends_with(as_),
        (_, _, None, Some(bs)) => a.ends_with(bs),
        // Both literals
        _ => a == b,
    }
}

fn generate_counterexample(condition: &NormalizedCondition) -> Option<Counterexample> {
    let mut ce = Counterexample::default();

    match condition {
        NormalizedCondition::True => {
            ce.description = "any request".into();
        }
        NormalizedCondition::AmountRange { min, max } => {
            let amount = match (min, max) {
                (Some(m), _) => *m,
                (None, Some(m)) => *m,
                (None, None) => 1000,
            };
            ce.amount_sats = Some(amount);
            ce.description = format!("amount {} sats", amount);
        }
        NormalizedCondition::SourceWallet { patterns } => {
            if let Some(p) = patterns.first() {
                let wallet = p
                    .strip_suffix('*')
                    .map_or_else(|| p.clone(), |prefix| format!("{prefix}example"));
                ce.description = format!("source wallet '{wallet}'");
                ce.source_wallet = Some(wallet);
            }
        }
        NormalizedCondition::AddressExact { addresses } => {
            if let Some(addr) = addresses.first() {
                ce.description = format!("destination '{addr}'");
                ce.destination = Some(addr.clone());
            }
        }
        NormalizedCondition::AddressIn { list } => {
            ce.description = format!("address in list '{}'", list);
        }
        NormalizedCondition::TimeWindow { days, hours } => {
            let mut parts = Vec::new();
            if let Some(d) = days {
                parts.push(format!("days {d:?}"));
            }
            if let Some(h) = hours {
                parts.push(format!("hours {}-{}", h.start, h.end));
            }
            let joined = parts.join(", ");
            ce.description = format!("time window: {joined}");
            ce.time_description = Some(joined);
        }
        NormalizedCondition::And(parts) => {
            let mut descs = Vec::new();
            for p in parts {
                if let Some(sub) = generate_counterexample(p) {
                    ce.amount_sats = ce.amount_sats.or(sub.amount_sats);
                    ce.source_wallet = ce.source_wallet.or(sub.source_wallet);
                    ce.destination = ce.destination.or(sub.destination);
                    ce.time_description = ce.time_description.or(sub.time_description);
                    descs.push(sub.description);
                }
            }
            ce.description = descs.join(" AND ");
        }
        NormalizedCondition::Or(parts) => {
            if let Some(first) = parts.first() {
                return generate_counterexample(first);
            }
        }
        _ => {
            ce.description = format!("{:?}", condition);
        }
    }

    Some(ce)
}

pub fn validate_policy_upgrade(current: &Policy, proposed: &Policy) -> PolicyUpgradeValidation {
    let current_sem = current.to_semantic();
    let proposed_sem = proposed.to_semantic();

    let entailment = proposed_sem.entails(&current_sem);
    let expands_permissions = !entailment.is_entailed();

    let differences = if expands_permissions {
        proposed_sem.difference(&current_sem)
    } else {
        Vec::new()
    };

    let redundant_rules = proposed_sem.find_redundant_rules();
    let conflicts = proposed_sem.find_conflicts();

    PolicyUpgradeValidation {
        is_safe: !expands_permissions && conflicts.is_empty(),
        expands_permissions,
        entailment_result: entailment,
        expanded_permissions: differences,
        redundant_rules,
        conflicts,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUpgradeValidation {
    pub is_safe: bool,
    pub expands_permissions: bool,
    pub entailment_result: EntailmentResult,
    pub expanded_permissions: Vec<Counterexample>,
    pub redundant_rules: Vec<RedundantRule>,
    pub conflicts: Vec<PolicyConflict>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ApprovalConfig, Rule};

    fn make_policy(rules: Vec<Rule>, default: Action) -> Policy {
        Policy {
            id: uuid::Uuid::new_v4(),
            version: "1.0".into(),
            name: "test".into(),
            description: None,
            rules,
            default_action: default,
            content_hash: None,
            created_at: None,
            created_by: None,
            is_active: true,
        }
    }

    fn make_rule(id: &str, amount_max: Option<u64>, action: Action) -> Rule {
        Rule {
            id: id.into(),
            description: None,
            conditions: Conditions {
                amount: amount_max.map(|max| AmountCondition {
                    min_sats: None,
                    max_sats: Some(max),
                }),
                ..Default::default()
            },
            action: action.clone(),
            approval: if action == Action::RequireApproval {
                Some(ApprovalConfig {
                    quorum: 1,
                    from_groups: vec!["admin".into()],
                    timeout_hours: 24,
                })
            } else {
                None
            },
        }
    }

    #[test]
    fn test_amount_range_subset() {
        let narrow = NormalizedCondition::AmountRange {
            min: Some(100),
            max: Some(500),
        };
        let wide = NormalizedCondition::AmountRange {
            min: Some(0),
            max: Some(1000),
        };
        let unbounded = NormalizedCondition::AmountRange {
            min: None,
            max: None,
        };

        assert!(narrow.is_subset_of(&wide));
        assert!(narrow.is_subset_of(&unbounded));
        assert!(!wide.is_subset_of(&narrow));
        assert!(wide.is_subset_of(&unbounded));
    }

    #[test]
    fn test_policy_entailment_stricter() {
        let strict = make_policy(
            vec![make_rule("small", Some(1000), Action::Allow)],
            Action::Deny,
        );
        let permissive = make_policy(
            vec![make_rule("medium", Some(10000), Action::Allow)],
            Action::Deny,
        );

        let strict_sem = strict.to_semantic();
        let permissive_sem = permissive.to_semantic();

        assert!(strict_sem.entails(&permissive_sem).is_entailed());
        assert!(!permissive_sem.entails(&strict_sem).is_entailed());
    }

    #[test]
    fn test_policy_entailment_identical() {
        let policy = make_policy(
            vec![make_rule("allow-small", Some(5000), Action::Allow)],
            Action::Deny,
        );

        let sem = policy.to_semantic();
        assert!(sem.entails(&sem).is_entailed());
    }

    #[test]
    fn test_find_redundant_rules() {
        let policy = make_policy(
            vec![
                make_rule("wide", Some(10000), Action::Allow),
                make_rule("narrow", Some(5000), Action::Deny),
            ],
            Action::Deny,
        );

        let sem = policy.to_semantic();
        let redundant = sem.find_redundant_rules();

        assert_eq!(redundant.len(), 1);
        assert_eq!(redundant[0].rule_id, "narrow");
        assert_eq!(redundant[0].shadowed_by_id, "wide");
    }

    #[test]
    fn test_find_conflicts() {
        let rule1 = Rule {
            id: "allow-low".into(),
            description: None,
            conditions: Conditions {
                amount: Some(AmountCondition {
                    min_sats: None,
                    max_sats: Some(5000),
                }),
                ..Default::default()
            },
            action: Action::Allow,
            approval: None,
        };

        let rule2 = Rule {
            id: "deny-all".into(),
            description: None,
            conditions: Conditions {
                amount: Some(AmountCondition {
                    min_sats: None,
                    max_sats: Some(10000),
                }),
                ..Default::default()
            },
            action: Action::Deny,
            approval: None,
        };

        let policy = make_policy(vec![rule1, rule2], Action::Deny);
        let sem = policy.to_semantic();
        let conflicts = sem.find_conflicts();

        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].rule_a_id, "allow-low");
        assert_eq!(conflicts[0].rule_b_id, "deny-all");
    }

    #[test]
    fn test_source_wallet_patterns() {
        let specific = NormalizedCondition::SourceWallet {
            patterns: ["treasury-hot-1".into()].into_iter().collect(),
        };
        let wildcard = NormalizedCondition::SourceWallet {
            patterns: ["treasury-*".into()].into_iter().collect(),
        };
        let all = NormalizedCondition::SourceWallet {
            patterns: ["*".into()].into_iter().collect(),
        };

        assert!(specific.is_subset_of(&wildcard));
        assert!(specific.is_subset_of(&all));
        assert!(wildcard.is_subset_of(&all));
        assert!(!wildcard.is_subset_of(&specific));
    }

    #[test]
    fn test_time_window_subset() {
        let narrow = NormalizedCondition::TimeWindow {
            days: Some([DayOfWeek::Mon, DayOfWeek::Tue].into_iter().collect()),
            hours: Some(NormalizedHourRange { start: 9, end: 12 }),
        };
        let wide = NormalizedCondition::TimeWindow {
            days: Some(
                [
                    DayOfWeek::Mon,
                    DayOfWeek::Tue,
                    DayOfWeek::Wed,
                    DayOfWeek::Thu,
                    DayOfWeek::Fri,
                ]
                .into_iter()
                .collect(),
            ),
            hours: Some(NormalizedHourRange { start: 8, end: 17 }),
        };

        assert!(narrow.is_subset_of(&wide));
        assert!(!wide.is_subset_of(&narrow));
    }

    #[test]
    fn test_validate_policy_upgrade_safe() {
        let current = make_policy(
            vec![make_rule("allow-medium", Some(5000), Action::Allow)],
            Action::Deny,
        );
        let proposed = make_policy(
            vec![make_rule("allow-small", Some(1000), Action::Allow)],
            Action::Deny,
        );

        let validation = validate_policy_upgrade(&current, &proposed);
        assert!(validation.is_safe);
        assert!(!validation.expands_permissions);
    }

    #[test]
    fn test_validate_policy_upgrade_unsafe() {
        let current = make_policy(
            vec![make_rule("allow-small", Some(1000), Action::Allow)],
            Action::Deny,
        );
        let proposed = make_policy(
            vec![make_rule("allow-large", Some(10000), Action::Allow)],
            Action::Deny,
        );

        let validation = validate_policy_upgrade(&current, &proposed);
        assert!(!validation.is_safe);
        assert!(validation.expands_permissions);
        assert!(!validation.expanded_permissions.is_empty());
    }

    #[test]
    fn test_generate_counterexample() {
        let cond = NormalizedCondition::AmountRange {
            min: Some(1000),
            max: Some(5000),
        };
        let ce = generate_counterexample(&cond).unwrap();
        assert_eq!(ce.amount_sats, Some(1000));
    }

    #[test]
    fn test_and_condition_subset() {
        let and_cond = NormalizedCondition::And(vec![
            NormalizedCondition::AmountRange {
                min: Some(100),
                max: Some(500),
            },
            NormalizedCondition::SourceWallet {
                patterns: ["treasury-*".into()].into_iter().collect(),
            },
        ]);

        let amount_only = NormalizedCondition::AmountRange {
            min: Some(0),
            max: Some(1000),
        };

        assert!(and_cond.is_subset_of(&amount_only));
    }

    #[test]
    fn test_hour_range_wrap_around() {
        let night = NormalizedHourRange { start: 22, end: 6 };
        let expanded = expand_hour_range(&night);
        assert!(expanded.contains(&22));
        assert!(expanded.contains(&23));
        assert!(expanded.contains(&0));
        assert!(expanded.contains(&6));
        assert!(!expanded.contains(&12));
    }

    #[test]
    fn test_patterns_may_overlap() {
        assert!(patterns_may_overlap("*", "anything"));
        assert!(patterns_may_overlap("anything", "*"));
        assert!(patterns_may_overlap("foo*", "foobar"));
        assert!(patterns_may_overlap("foo*", "foo*"));
        assert!(patterns_may_overlap("*-hot", "*-hot"));
        assert!(patterns_may_overlap("treasury-*", "*-hot"));
        assert!(patterns_may_overlap("*-hot", "treasury-*"));
        assert!(!patterns_may_overlap("foo", "bar"));
        assert!(!patterns_may_overlap("*-hot", "*-cold"));
    }
}
