#![forbid(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::risk::RiskLevel;
use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirements {
    pub initial: ApprovalStage,
    pub degradation: Vec<DegradationStage>,
}

impl ApprovalRequirements {
    pub fn simple(quorum: u32, roles: Vec<String>) -> Self {
        Self {
            initial: ApprovalStage {
                roles,
                required: quorum,
            },
            degradation: vec![],
        }
    }

    pub fn with_degradation(
        initial_quorum: u32,
        initial_roles: Vec<String>,
        degradation: Vec<DegradationStage>,
    ) -> Self {
        Self {
            initial: ApprovalStage {
                roles: initial_roles,
                required: initial_quorum,
            },
            degradation,
        }
    }

    pub fn for_risk_level(level: RiskLevel) -> Option<Self> {
        match level {
            RiskLevel::Low => None,
            RiskLevel::Medium => Some(Self {
                initial: ApprovalStage {
                    roles: vec!["treasury".into(), "cfo".into()],
                    required: 2,
                },
                degradation: vec![DegradationStage {
                    after: Duration::hours(4),
                    roles: vec!["cfo".into()],
                    required: 1,
                }],
            }),
            RiskLevel::High | RiskLevel::Critical => Some(Self {
                initial: ApprovalStage {
                    roles: vec!["treasury".into(), "cfo".into(), "ceo".into()],
                    required: 3,
                },
                degradation: vec![
                    DegradationStage {
                        after: Duration::hours(4),
                        roles: vec!["cfo".into(), "ceo".into()],
                        required: 2,
                    },
                    DegradationStage {
                        after: Duration::hours(24),
                        roles: vec!["ceo".into()],
                        required: 1,
                    },
                ],
            }),
        }
    }

    pub fn current_stage(&self, created_at: DateTime<Utc>) -> CurrentStage {
        let elapsed = Utc::now() - created_at;

        for (i, stage) in self.degradation.iter().enumerate() {
            if elapsed < stage.after {
                if i == 0 {
                    return CurrentStage {
                        index: 0,
                        roles: self.initial.roles.clone(),
                        required: self.initial.required,
                        is_degraded: false,
                    };
                } else {
                    let prev = &self.degradation[i - 1];
                    return CurrentStage {
                        index: i as u32,
                        roles: prev.roles.clone(),
                        required: prev.required,
                        is_degraded: true,
                    };
                }
            }
        }

        if let Some(last) = self.degradation.last() {
            CurrentStage {
                index: self.degradation.len() as u32,
                roles: last.roles.clone(),
                required: last.required,
                is_degraded: true,
            }
        } else {
            CurrentStage {
                index: 0,
                roles: self.initial.roles.clone(),
                required: self.initial.required,
                is_degraded: false,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStage {
    pub roles: Vec<String>,
    pub required: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationStage {
    #[serde(with = "duration_serde")]
    pub after: Duration,
    pub roles: Vec<String>,
    pub required: u32,
}

#[derive(Debug, Clone)]
pub struct CurrentStage {
    pub index: u32,
    pub roles: Vec<String>,
    pub required: u32,
    pub is_degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub policy_id: Uuid,
    pub status: ApprovalStatus,
    pub requirements: ApprovalRequirements,
    pub approvals: Vec<Approval>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ApprovalRequest {
    pub fn new(
        transaction_id: Uuid,
        policy_id: Uuid,
        requirements: ApprovalRequirements,
        expires_in: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            transaction_id,
            policy_id,
            status: ApprovalStatus::Pending,
            requirements,
            approvals: vec![],
            created_at: now,
            expires_at: now + expires_in,
        }
    }

    pub fn current_stage(&self) -> CurrentStage {
        self.requirements.current_stage(self.created_at)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn approval_count(&self) -> u32 {
        self.approvals
            .iter()
            .filter(|a| a.decision == ApprovalDecision::Approve)
            .count() as u32
    }

    pub fn can_approve(&self, user_id: &str, user_roles: &[String]) -> bool {
        if self.status != ApprovalStatus::Pending {
            return false;
        }

        if self.is_expired() {
            return false;
        }

        if self.approvals.iter().any(|a| a.approver_id == user_id) {
            return false;
        }

        let stage = self.current_stage();
        user_roles.iter().any(|r| stage.roles.contains(r))
    }

    pub fn add_approval(&mut self, approval: Approval) -> ApprovalStatus {
        self.approvals.push(approval.clone());

        if approval.decision == ApprovalDecision::Reject {
            self.status = ApprovalStatus::Rejected;
            return self.status.clone();
        }

        let stage = self.current_stage();
        if self.approval_count() >= stage.required {
            self.status = ApprovalStatus::Approved;
        }

        self.status.clone()
    }

    pub fn check_expiration(&mut self) -> bool {
        if self.is_expired() && self.status == ApprovalStatus::Pending {
            self.status = ApprovalStatus::Expired;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: Uuid,
    pub approver_id: String,
    pub approver_role: String,
    pub decision: ApprovalDecision,
    pub comment: Option<String>,
    pub signature: Option<String>,
    pub degradation_stage: u32,
    pub created_at: DateTime<Utc>,
}

impl Approval {
    pub fn new(
        approver_id: String,
        approver_role: String,
        decision: ApprovalDecision,
        stage: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            approver_id,
            approver_role,
            decision,
            comment: None,
            signature: None,
            degradation_stage: stage,
            created_at: Utc::now(),
        }
    }

    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn with_signature(mut self, signature: String) -> Self {
        self.signature = Some(signature);
        self
    }
}

#[async_trait]
pub trait ApprovalStore: Send + Sync {
    async fn create(&self, request: ApprovalRequest) -> Result<ApprovalRequest>;
    async fn get(&self, id: &Uuid) -> Result<Option<ApprovalRequest>>;
    async fn get_by_transaction(&self, transaction_id: &Uuid) -> Result<Option<ApprovalRequest>>;
    async fn update(&self, request: ApprovalRequest) -> Result<ApprovalRequest>;
    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>>;
}

pub struct InMemoryApprovalStore {
    requests: RwLock<HashMap<Uuid, ApprovalRequest>>,
}

impl InMemoryApprovalStore {
    pub fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryApprovalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalStore for InMemoryApprovalStore {
    async fn create(&self, request: ApprovalRequest) -> Result<ApprovalRequest> {
        let mut requests = self.requests.write().expect("lock poisoned");
        requests.insert(request.id, request.clone());
        Ok(request)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<ApprovalRequest>> {
        let requests = self.requests.read().expect("lock poisoned");
        Ok(requests.get(id).cloned())
    }

    async fn get_by_transaction(&self, transaction_id: &Uuid) -> Result<Option<ApprovalRequest>> {
        let requests = self.requests.read().expect("lock poisoned");
        Ok(requests
            .values()
            .find(|r| &r.transaction_id == transaction_id)
            .cloned())
    }

    async fn update(&self, request: ApprovalRequest) -> Result<ApprovalRequest> {
        let mut requests = self.requests.write().expect("lock poisoned");
        requests.insert(request.id, request.clone());
        Ok(request)
    }

    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>> {
        let requests = self.requests.read().expect("lock poisoned");
        Ok(requests
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .cloned()
            .collect())
    }
}

mod duration_serde {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.num_seconds().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = i64::deserialize(deserializer)?;
        Ok(Duration::seconds(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_approval() {
        let reqs = ApprovalRequirements::simple(2, vec!["admin".into()]);
        let mut request =
            ApprovalRequest::new(Uuid::new_v4(), Uuid::new_v4(), reqs, Duration::hours(24));

        assert!(request.can_approve("user1", &["admin".into()]));
        assert!(!request.can_approve("user1", &["viewer".into()]));

        let approval1 = Approval::new("user1".into(), "admin".into(), ApprovalDecision::Approve, 0);
        request.add_approval(approval1);
        assert_eq!(request.status, ApprovalStatus::Pending);

        let approval2 = Approval::new("user2".into(), "admin".into(), ApprovalDecision::Approve, 0);
        request.add_approval(approval2);
        assert_eq!(request.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_degradation() {
        let reqs = ApprovalRequirements {
            initial: ApprovalStage {
                roles: vec!["treasury".into(), "cfo".into(), "ceo".into()],
                required: 3,
            },
            degradation: vec![
                DegradationStage {
                    after: Duration::hours(4),
                    roles: vec!["cfo".into(), "ceo".into()],
                    required: 2,
                },
                DegradationStage {
                    after: Duration::hours(24),
                    roles: vec!["ceo".into()],
                    required: 1,
                },
            ],
        };

        let stage = reqs.current_stage(Utc::now());
        assert_eq!(stage.required, 3);
        assert!(!stage.is_degraded);

        let five_hours_ago = Utc::now() - Duration::hours(5);
        let stage = reqs.current_stage(five_hours_ago);
        assert_eq!(stage.required, 2);
        assert!(stage.is_degraded);

        let two_days_ago = Utc::now() - Duration::days(2);
        let stage = reqs.current_stage(two_days_ago);
        assert_eq!(stage.required, 1);
        assert!(stage.is_degraded);
    }

    #[test]
    fn test_rejection() {
        let reqs = ApprovalRequirements::simple(2, vec!["admin".into()]);
        let mut request =
            ApprovalRequest::new(Uuid::new_v4(), Uuid::new_v4(), reqs, Duration::hours(24));

        let rejection = Approval::new("user1".into(), "admin".into(), ApprovalDecision::Reject, 0);
        request.add_approval(rejection);
        assert_eq!(request.status, ApprovalStatus::Rejected);
    }

    #[test]
    fn test_no_self_approve() {
        let reqs = ApprovalRequirements::simple(2, vec!["admin".into()]);
        let mut request =
            ApprovalRequest::new(Uuid::new_v4(), Uuid::new_v4(), reqs, Duration::hours(24));

        let approval1 = Approval::new("user1".into(), "admin".into(), ApprovalDecision::Approve, 0);
        request.add_approval(approval1);

        assert!(!request.can_approve("user1", &["admin".into()]));
        assert!(request.can_approve("user2", &["admin".into()]));
    }
}
