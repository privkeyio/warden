#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};
use tracing::debug;

use crate::evaluator::{EvaluationResult, PolicyDecisionSerde};

fn saturating_decrement(counter: &AtomicI64) -> i64 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some((v - 1).max(0))
        })
        .map(|prev| (prev - 1).max(0))
        .unwrap_or(0)
}

fn bucket_rule_id(rule_id: &str) -> &'static str {
    if rule_id.starts_with("builtin:") || rule_id.starts_with("system:") {
        return "builtin";
    }
    if rule_id == "default" || rule_id.starts_with("default:") || rule_id == "fallback" {
        return "default";
    }
    "custom"
}

fn map_denial_reason_to_label(reason: &str) -> &'static str {
    let reason_lower = reason.to_lowercase();

    if reason_lower.contains("default deny")
        || reason_lower.contains("no matching")
        || reason_lower.contains("no rule")
        || reason_lower.contains("not allowed")
    {
        return "default_deny";
    }

    if reason_lower.contains("denied by rule")
        || reason_lower.contains("rule denied")
        || reason_lower.contains("policy denied")
        || reason_lower.contains("rejected")
    {
        return "rule_denied";
    }

    if reason_lower.contains("exceed")
        || reason_lower.contains("limit")
        || reason_lower.contains("threshold")
        || reason_lower.contains("amount")
    {
        return "limit_exceeded";
    }

    if reason_lower.contains("rate") || reason_lower.contains("throttl") {
        return "rate_limited";
    }

    if reason_lower.contains("unauthorized")
        || reason_lower.contains("forbidden")
        || reason_lower.contains("permission")
    {
        return "unauthorized";
    }

    if reason_lower.contains("expir") || reason_lower.contains("timeout") {
        return "expired";
    }

    "other"
}

const METRIC_DECISIONS: &str = "warden_policy_decisions_total";
const METRIC_EVALUATION: &str = "warden_policy_evaluation_seconds";
const METRIC_RULES_EVALUATED: &str = "warden_policy_rules_evaluated_total";
const METRIC_DENIALS: &str = "warden_policy_denials_total";
const METRIC_WORKFLOW_PENDING: &str = "warden_workflow_approvals_pending";
const METRIC_SESSIONS_ACTIVE: &str = "warden_signing_sessions_active";

#[derive(Clone)]
pub struct PolicyMetrics {
    workflow_pending: Arc<AtomicI64>,
    sessions_active: Arc<AtomicI64>,
}

impl Default for PolicyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyMetrics {
    pub fn new() -> Self {
        Self {
            workflow_pending: Arc::new(AtomicI64::new(0)),
            sessions_active: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn record_decision(&self, result: &EvaluationResult) {
        let (outcome, rule_id, denial_reason) = match &result.decision {
            PolicyDecisionSerde::Allow { rule_id, .. } => ("allow", rule_id.as_str(), None),
            PolicyDecisionSerde::Deny { rule_id, reason } => {
                ("deny", rule_id.as_str(), Some(reason.as_str()))
            }
            PolicyDecisionSerde::RequireApproval { rule_id, .. } => {
                ("require_approval", rule_id.as_str(), None)
            }
        };

        let rule_bucket = bucket_rule_id(rule_id);
        counter!(METRIC_DECISIONS, "outcome" => outcome, "rule_bucket" => rule_bucket).increment(1);

        let latency_secs = result.evaluation_time_us as f64 / 1_000_000.0;
        histogram!(METRIC_EVALUATION).record(latency_secs);

        for trace in &result.trace {
            self.record_rule_evaluated(&trace.rule_id);
        }

        if let Some(reason) = denial_reason {
            self.record_denial(reason, rule_id);
        }
    }

    pub fn record_rule_evaluated(&self, rule_id: &str) {
        let rule_bucket = bucket_rule_id(rule_id);
        counter!(METRIC_RULES_EVALUATED, "rule_bucket" => rule_bucket).increment(1);
    }

    pub fn record_denial(&self, reason: &str, rule_id: &str) {
        let reason_label = map_denial_reason_to_label(reason);
        let rule_bucket = bucket_rule_id(rule_id);

        debug!(
            rule_id = rule_id,
            reason = reason,
            reason_label = reason_label,
            rule_bucket = rule_bucket,
            "Policy denial recorded"
        );

        counter!(METRIC_DENIALS, "reason_category" => reason_label, "rule_bucket" => rule_bucket)
            .increment(1);
    }

    pub fn workflow_started(&self) {
        let new_val = self.workflow_pending.fetch_add(1, Ordering::Relaxed) + 1;
        gauge!(METRIC_WORKFLOW_PENDING).set(new_val as f64);
    }

    pub fn workflow_completed(&self) {
        let new_val = saturating_decrement(&self.workflow_pending);
        gauge!(METRIC_WORKFLOW_PENDING).set(new_val as f64);
    }

    pub fn session_started(&self) {
        let new_val = self.sessions_active.fetch_add(1, Ordering::Relaxed) + 1;
        gauge!(METRIC_SESSIONS_ACTIVE).set(new_val as f64);
    }

    pub fn session_completed(&self) {
        let new_val = saturating_decrement(&self.sessions_active);
        gauge!(METRIC_SESSIONS_ACTIVE).set(new_val as f64);
    }

    pub fn pending_workflows(&self) -> i64 {
        self.workflow_pending.load(Ordering::Relaxed)
    }

    pub fn active_sessions(&self) -> i64 {
        self.sessions_active.load(Ordering::Relaxed)
    }
}

pub struct MetricsRecorder;

impl MetricsRecorder {
    pub fn install_prometheus(
        addr: std::net::SocketAddr,
    ) -> Result<(), metrics_exporter_prometheus::BuildError> {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr)
            .install()
    }

    pub fn install_prometheus_with_defaults() -> Result<(), metrics_exporter_prometheus::BuildError>
    {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 9090).into();
        Self::install_prometheus(addr)
    }
}

#[derive(Clone)]
pub struct LabeledMetrics {
    prefix: String,
}

impl LabeledMetrics {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub fn counter(&self, name: &str) -> Counter {
        counter!(format!("{}_{}", self.prefix, name))
    }

    pub fn gauge(&self, name: &str) -> Gauge {
        gauge!(format!("{}_{}", self.prefix, name))
    }

    pub fn histogram(&self, name: &str) -> Histogram {
        histogram!(format!("{}_{}", self.prefix, name))
    }

    pub fn record_latency(&self, name: &str, duration: Duration) {
        self.histogram(name).record(duration.as_secs_f64());
    }

    pub fn increment(&self, name: &str) {
        self.counter(name).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::RuleTraceEntry;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_result(decision: PolicyDecisionSerde) -> EvaluationResult {
        EvaluationResult {
            decision,
            policy_id: Uuid::new_v4(),
            policy_version: "1.0".into(),
            evaluated_at: Utc::now(),
            evaluation_time_us: 1500,
            rules_evaluated: 3,
            trace: vec![
                RuleTraceEntry {
                    rule_id: "rule-1".into(),
                    matched: false,
                    details: "no match".into(),
                },
                RuleTraceEntry {
                    rule_id: "rule-2".into(),
                    matched: true,
                    details: "matched".into(),
                },
            ],
        }
    }

    #[test]
    fn test_record_allow_decision() {
        let metrics = PolicyMetrics::new();
        let result = make_result(PolicyDecisionSerde::Allow {
            rule_id: "rule-2".into(),
            reason: "allowed by policy".into(),
        });
        metrics.record_decision(&result);
    }

    #[test]
    fn test_record_deny_decision() {
        let metrics = PolicyMetrics::new();
        let result = make_result(PolicyDecisionSerde::Deny {
            rule_id: "rule-1".into(),
            reason: "amount exceeded".into(),
        });
        metrics.record_decision(&result);
    }

    #[test]
    fn test_workflow_gauge() {
        let metrics = PolicyMetrics::new();
        assert_eq!(metrics.pending_workflows(), 0);

        metrics.workflow_started();
        metrics.workflow_started();
        assert_eq!(metrics.pending_workflows(), 2);

        metrics.workflow_completed();
        assert_eq!(metrics.pending_workflows(), 1);

        metrics.workflow_completed();
        assert_eq!(metrics.pending_workflows(), 0);
    }

    #[test]
    fn test_session_gauge() {
        let metrics = PolicyMetrics::new();
        assert_eq!(metrics.active_sessions(), 0);

        metrics.session_started();
        assert_eq!(metrics.active_sessions(), 1);

        metrics.session_completed();
        assert_eq!(metrics.active_sessions(), 0);
    }

    #[test]
    fn test_labeled_metrics() {
        let labeled = LabeledMetrics::new("warden");

        labeled.increment("test_counter");
        labeled.record_latency("test_latency", Duration::from_millis(100));
    }
}
