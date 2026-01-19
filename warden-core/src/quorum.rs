#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::approval::{Approval, ApprovalDecision};

pub type GroupId = String;

const MAX_NESTING_DEPTH: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequirementNode {
    Threshold {
        threshold: u32,
        group: GroupId,
    },
    All {
        requirements: Vec<RequirementNode>,
    },
    Any {
        requirements: Vec<RequirementNode>,
    },
    KOf {
        k: u32,
        requirements: Vec<RequirementNode>,
    },
}

impl RequirementNode {
    pub fn threshold(threshold: u32, group: impl Into<GroupId>) -> Self {
        Self::Threshold {
            threshold,
            group: group.into(),
        }
    }

    pub fn all(requirements: Vec<RequirementNode>) -> Self {
        Self::All { requirements }
    }

    pub fn any(requirements: Vec<RequirementNode>) -> Self {
        Self::Any { requirements }
    }

    pub fn k_of(k: u32, requirements: Vec<RequirementNode>) -> Self {
        Self::KOf { k, requirements }
    }

    pub fn validate(&self) -> Result<(), QuorumValidationError> {
        self.validate_with_depth(0)
    }

    fn validate_with_depth(&self, depth: usize) -> Result<(), QuorumValidationError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(QuorumValidationError::MaxNestingDepthExceeded {
                max: MAX_NESTING_DEPTH,
            });
        }

        match self {
            RequirementNode::Threshold { threshold, group } => {
                if *threshold == 0 {
                    return Err(QuorumValidationError::ZeroThreshold);
                }
                if group.is_empty() {
                    return Err(QuorumValidationError::EmptyGroup);
                }
            }
            RequirementNode::All { requirements } | RequirementNode::Any { requirements } => {
                if requirements.is_empty() {
                    return Err(QuorumValidationError::EmptyRequirements);
                }
                Self::check_duplicate_sibling_groups(requirements)?;
                for req in requirements {
                    req.validate_with_depth(depth + 1)?;
                }
            }
            RequirementNode::KOf { k, requirements } => {
                if *k == 0 {
                    return Err(QuorumValidationError::ZeroThreshold);
                }
                if requirements.is_empty() {
                    return Err(QuorumValidationError::EmptyRequirements);
                }
                if *k > requirements.len() as u32 {
                    return Err(QuorumValidationError::ThresholdExceedsRequirements {
                        k: *k,
                        count: requirements.len() as u32,
                    });
                }
                Self::check_duplicate_sibling_groups(requirements)?;
                for req in requirements {
                    req.validate_with_depth(depth + 1)?;
                }
            }
        }
        Ok(())
    }

    fn check_duplicate_sibling_groups(
        requirements: &[RequirementNode],
    ) -> Result<(), QuorumValidationError> {
        let mut seen_groups = HashSet::new();
        for req in requirements {
            if let RequirementNode::Threshold { group, .. } = req {
                if !seen_groups.insert(group.clone()) {
                    return Err(QuorumValidationError::DuplicateSiblingGroupId {
                        group_id: group.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn all_groups(&self) -> HashSet<GroupId> {
        let mut groups = HashSet::new();
        self.collect_groups(&mut groups);
        groups
    }

    pub fn minimum_approvals(&self) -> u32 {
        match self {
            RequirementNode::Threshold { threshold, .. } => *threshold,
            RequirementNode::All { requirements } => {
                requirements.iter().map(|r| r.minimum_approvals()).sum()
            }
            RequirementNode::Any { requirements } => requirements
                .iter()
                .map(|r| r.minimum_approvals())
                .min()
                .unwrap_or(0),
            RequirementNode::KOf { k, requirements } => {
                let mut mins: Vec<u32> =
                    requirements.iter().map(|r| r.minimum_approvals()).collect();
                mins.sort_unstable();
                mins.iter().take(*k as usize).sum()
            }
        }
    }

    fn collect_groups(&self, groups: &mut HashSet<GroupId>) {
        match self {
            RequirementNode::Threshold { group, .. } => {
                groups.insert(group.clone());
            }
            RequirementNode::All { requirements }
            | RequirementNode::Any { requirements }
            | RequirementNode::KOf { requirements, .. } => {
                for req in requirements {
                    req.collect_groups(groups);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumValidationError {
    ZeroThreshold,
    EmptyGroup,
    EmptyRequirements,
    ThresholdExceedsRequirements { k: u32, count: u32 },
    DuplicateSiblingGroupId { group_id: GroupId },
    MaxNestingDepthExceeded { max: usize },
}

impl std::fmt::Display for QuorumValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroThreshold => write!(f, "threshold cannot be zero"),
            Self::EmptyGroup => write!(f, "group id cannot be empty"),
            Self::EmptyRequirements => write!(f, "requirements list cannot be empty"),
            Self::ThresholdExceedsRequirements { k, count } => {
                write!(f, "k ({}) exceeds requirement count ({})", k, count)
            }
            Self::DuplicateSiblingGroupId { group_id } => {
                write!(f, "duplicate GroupId in sibling requirements: {}", group_id)
            }
            Self::MaxNestingDepthExceeded { max } => {
                write!(f, "nesting depth exceeds maximum of {}", max)
            }
        }
    }
}

impl std::error::Error for QuorumValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuorumStatus {
    Satisfied,
    Pending {
        collected: u32,
        required: u32,
        from_group: GroupId,
    },
    PendingMultiple {
        sub_statuses: Vec<QuorumStatus>,
        logic: String,
    },
    PendingKOf {
        satisfied: u32,
        required: u32,
        total: u32,
    },
}

impl QuorumStatus {
    pub fn is_satisfied(&self) -> bool {
        matches!(self, QuorumStatus::Satisfied)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingGroupInfo {
    pub group_id: GroupId,
    pub required: u32,
    pub collected: u32,
}

pub struct QuorumEvaluator;

impl QuorumEvaluator {
    pub fn new() -> Self {
        Self
    }

    #[allow(clippy::only_used_in_recursion)]
    pub fn evaluate(&self, requirement: &RequirementNode, approvals: &[Approval]) -> QuorumStatus {
        match requirement {
            RequirementNode::Threshold { threshold, group } => {
                let count = approvals
                    .iter()
                    .filter(|a| {
                        &a.approver_role == group && a.decision == ApprovalDecision::Approve
                    })
                    .count() as u32;

                if count >= *threshold {
                    QuorumStatus::Satisfied
                } else {
                    QuorumStatus::Pending {
                        collected: count,
                        required: *threshold,
                        from_group: group.clone(),
                    }
                }
            }

            RequirementNode::All { requirements } => {
                let statuses: Vec<_> = requirements
                    .iter()
                    .map(|r| self.evaluate(r, approvals))
                    .collect();

                if statuses.iter().all(|s| s.is_satisfied()) {
                    QuorumStatus::Satisfied
                } else {
                    QuorumStatus::PendingMultiple {
                        sub_statuses: statuses,
                        logic: "all".into(),
                    }
                }
            }

            RequirementNode::Any { requirements } => {
                let statuses: Vec<_> = requirements
                    .iter()
                    .map(|r| self.evaluate(r, approvals))
                    .collect();

                if statuses.iter().any(|s| s.is_satisfied()) {
                    QuorumStatus::Satisfied
                } else {
                    QuorumStatus::PendingMultiple {
                        sub_statuses: statuses,
                        logic: "any".into(),
                    }
                }
            }

            RequirementNode::KOf { k, requirements } => {
                let satisfied_count = requirements
                    .iter()
                    .filter(|r| self.evaluate(r, approvals).is_satisfied())
                    .count() as u32;

                if satisfied_count >= *k {
                    QuorumStatus::Satisfied
                } else {
                    QuorumStatus::PendingKOf {
                        satisfied: satisfied_count,
                        required: *k,
                        total: requirements.len() as u32,
                    }
                }
            }
        }
    }

    pub fn has_rejection<'a>(&self, approvals: &'a [Approval]) -> Option<&'a Approval> {
        approvals
            .iter()
            .find(|a| a.decision == ApprovalDecision::Reject)
    }

    pub fn pending_groups(
        &self,
        requirement: &RequirementNode,
        approvals: &[Approval],
    ) -> Vec<PendingGroupInfo> {
        let mut pending = Vec::new();
        let mut seen = HashSet::new();
        self.collect_pending_groups(requirement, approvals, &mut pending, &mut seen);
        pending
    }

    fn collect_pending_groups(
        &self,
        requirement: &RequirementNode,
        approvals: &[Approval],
        pending: &mut Vec<PendingGroupInfo>,
        seen: &mut HashSet<GroupId>,
    ) {
        match requirement {
            RequirementNode::Threshold { threshold, group } => {
                if seen.contains(group) {
                    return;
                }

                let collected = approvals
                    .iter()
                    .filter(|a| {
                        &a.approver_role == group && a.decision == ApprovalDecision::Approve
                    })
                    .count() as u32;

                if collected < *threshold {
                    seen.insert(group.clone());
                    pending.push(PendingGroupInfo {
                        group_id: group.clone(),
                        required: *threshold,
                        collected,
                    });
                }
            }
            RequirementNode::All { requirements } => {
                for req in requirements {
                    self.collect_pending_groups(req, approvals, pending, seen);
                }
            }
            RequirementNode::Any { requirements } => {
                let statuses: Vec<_> = requirements
                    .iter()
                    .map(|r| self.evaluate(r, approvals))
                    .collect();

                if !statuses.iter().any(|s| s.is_satisfied()) {
                    for req in requirements {
                        self.collect_pending_groups(req, approvals, pending, seen);
                    }
                }
            }
            RequirementNode::KOf { k, requirements } => {
                let satisfied = requirements
                    .iter()
                    .filter(|r| self.evaluate(r, approvals).is_satisfied())
                    .count() as u32;

                if satisfied < *k {
                    for req in requirements {
                        if !self.evaluate(req, approvals).is_satisfied() {
                            self.collect_pending_groups(req, approvals, pending, seen);
                        }
                    }
                }
            }
        }
    }
}

impl Default for QuorumEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_approval(approver: &str, role: &str, decision: ApprovalDecision) -> Approval {
        Approval {
            id: Uuid::new_v4(),
            approver_id: approver.into(),
            approver_role: role.into(),
            decision,
            comment: None,
            signature: None,
            degradation_stage: 0,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_simple_threshold() {
        let requirement = RequirementNode::threshold(2, "treasury-signers");
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(!status.is_satisfied());

        let approvals = vec![make_approval(
            "alice",
            "treasury-signers",
            ApprovalDecision::Approve,
        )];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(!status.is_satisfied());

        let approvals = vec![
            make_approval("alice", "treasury-signers", ApprovalDecision::Approve),
            make_approval("bob", "treasury-signers", ApprovalDecision::Approve),
        ];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(status.is_satisfied());
    }

    #[test]
    fn test_all_composition() {
        let requirement = RequirementNode::all(vec![
            RequirementNode::threshold(1, "finance-team"),
            RequirementNode::threshold(2, "security-team"),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![make_approval(
            "alice",
            "finance-team",
            ApprovalDecision::Approve,
        )];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(!status.is_satisfied());

        let approvals = vec![
            make_approval("alice", "finance-team", ApprovalDecision::Approve),
            make_approval("bob", "security-team", ApprovalDecision::Approve),
            make_approval("charlie", "security-team", ApprovalDecision::Approve),
        ];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(status.is_satisfied());
    }

    #[test]
    fn test_any_composition() {
        let requirement = RequirementNode::any(vec![
            RequirementNode::threshold(1, "ceo"),
            RequirementNode::all(vec![
                RequirementNode::threshold(1, "cfo"),
                RequirementNode::threshold(1, "cto"),
            ]),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![make_approval("alice", "ceo", ApprovalDecision::Approve)];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            make_approval("bob", "cfo", ApprovalDecision::Approve),
            make_approval("charlie", "cto", ApprovalDecision::Approve),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![make_approval("bob", "cfo", ApprovalDecision::Approve)];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    #[test]
    fn test_k_of() {
        let requirement = RequirementNode::k_of(
            2,
            vec![
                RequirementNode::threshold(1, "finance"),
                RequirementNode::threshold(1, "security"),
                RequirementNode::threshold(1, "compliance"),
            ],
        );
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![make_approval("alice", "finance", ApprovalDecision::Approve)];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            make_approval("alice", "finance", ApprovalDecision::Approve),
            make_approval("bob", "compliance", ApprovalDecision::Approve),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    #[test]
    fn test_rejection_detection() {
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![
            make_approval("alice", "treasury", ApprovalDecision::Approve),
            make_approval("bob", "treasury", ApprovalDecision::Reject),
        ];

        let rejection = evaluator.has_rejection(&approvals);
        assert!(rejection.is_some());
        assert_eq!(rejection.unwrap().approver_id, "bob");
    }

    #[test]
    fn test_pending_groups() {
        let requirement = RequirementNode::all(vec![
            RequirementNode::threshold(2, "treasury"),
            RequirementNode::threshold(1, "compliance"),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![make_approval(
            "alice",
            "treasury",
            ApprovalDecision::Approve,
        )];

        let pending = evaluator.pending_groups(&requirement, &approvals);
        assert_eq!(pending.len(), 2);

        let treasury = pending.iter().find(|p| p.group_id == "treasury").unwrap();
        assert_eq!(treasury.collected, 1);
        assert_eq!(treasury.required, 2);

        let compliance = pending.iter().find(|p| p.group_id == "compliance").unwrap();
        assert_eq!(compliance.collected, 0);
        assert_eq!(compliance.required, 1);
    }

    #[test]
    fn test_validation() {
        assert!(RequirementNode::threshold(0, "test").validate().is_err());
        assert!(RequirementNode::threshold(1, "").validate().is_err());
        assert!(RequirementNode::all(vec![]).validate().is_err());
        assert!(
            RequirementNode::k_of(3, vec![RequirementNode::threshold(1, "a")])
                .validate()
                .is_err()
        );
        assert!(RequirementNode::threshold(2, "treasury").validate().is_ok());
    }

    #[test]
    fn test_duplicate_sibling_group_validation() {
        // Duplicate GroupId in All should fail
        let duplicate_all = RequirementNode::all(vec![
            RequirementNode::threshold(2, "treasury"),
            RequirementNode::threshold(3, "treasury"),
        ]);
        let result = duplicate_all.validate();
        assert!(matches!(
            result,
            Err(QuorumValidationError::DuplicateSiblingGroupId { group_id }) if group_id == "treasury"
        ));

        // Duplicate GroupId in Any should fail
        let duplicate_any = RequirementNode::any(vec![
            RequirementNode::threshold(1, "security"),
            RequirementNode::threshold(2, "security"),
        ]);
        assert!(matches!(
            duplicate_any.validate(),
            Err(QuorumValidationError::DuplicateSiblingGroupId { .. })
        ));

        // Duplicate GroupId in KOf should fail
        let duplicate_kof = RequirementNode::k_of(
            2,
            vec![
                RequirementNode::threshold(1, "compliance"),
                RequirementNode::threshold(1, "compliance"),
                RequirementNode::threshold(1, "finance"),
            ],
        );
        assert!(matches!(
            duplicate_kof.validate(),
            Err(QuorumValidationError::DuplicateSiblingGroupId { .. })
        ));

        // Same GroupId at different nesting levels should be allowed
        let nested_same_group = RequirementNode::all(vec![
            RequirementNode::threshold(1, "treasury"),
            RequirementNode::any(vec![
                RequirementNode::threshold(2, "treasury"), // Different level, OK
                RequirementNode::threshold(1, "finance"),
            ]),
        ]);
        assert!(nested_same_group.validate().is_ok());

        // Different groups at same level should be allowed
        let different_groups = RequirementNode::all(vec![
            RequirementNode::threshold(1, "treasury"),
            RequirementNode::threshold(2, "finance"),
            RequirementNode::threshold(1, "compliance"),
        ]);
        assert!(different_groups.validate().is_ok());
    }

    #[test]
    fn test_all_groups() {
        let requirement = RequirementNode::all(vec![
            RequirementNode::threshold(1, "finance"),
            RequirementNode::any(vec![
                RequirementNode::threshold(1, "ceo"),
                RequirementNode::threshold(1, "cto"),
            ]),
        ]);

        let groups = requirement.all_groups();
        assert!(groups.contains("finance"));
        assert!(groups.contains("ceo"));
        assert!(groups.contains("cto"));
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn test_minimum_approvals() {
        assert_eq!(
            RequirementNode::threshold(3, "treasury").minimum_approvals(),
            3
        );

        let all_req = RequirementNode::all(vec![
            RequirementNode::threshold(2, "finance"),
            RequirementNode::threshold(1, "compliance"),
        ]);
        assert_eq!(all_req.minimum_approvals(), 3);

        let any_req = RequirementNode::any(vec![
            RequirementNode::threshold(5, "executive"),
            RequirementNode::threshold(2, "board"),
        ]);
        assert_eq!(any_req.minimum_approvals(), 2);

        let kof_req = RequirementNode::k_of(
            2,
            vec![
                RequirementNode::threshold(3, "security"),
                RequirementNode::threshold(1, "ops"),
                RequirementNode::threshold(2, "dev"),
            ],
        );
        assert_eq!(kof_req.minimum_approvals(), 3);

        let nested = RequirementNode::all(vec![
            RequirementNode::threshold(1, "initiator"),
            RequirementNode::any(vec![
                RequirementNode::threshold(3, "high_security"),
                RequirementNode::all(vec![
                    RequirementNode::threshold(1, "finance"),
                    RequirementNode::threshold(1, "compliance"),
                ]),
            ]),
        ]);
        assert_eq!(nested.minimum_approvals(), 3);
    }

    #[test]
    fn test_max_nesting_depth_validation() {
        fn build_nested(depth: usize) -> RequirementNode {
            if depth == 0 {
                RequirementNode::threshold(1, "leaf")
            } else {
                RequirementNode::all(vec![build_nested(depth - 1)])
            }
        }

        let valid = build_nested(MAX_NESTING_DEPTH);
        assert!(valid.validate().is_ok());

        let invalid = build_nested(MAX_NESTING_DEPTH + 1);
        assert!(matches!(
            invalid.validate(),
            Err(QuorumValidationError::MaxNestingDepthExceeded {
                max: MAX_NESTING_DEPTH
            })
        ));
    }
}
