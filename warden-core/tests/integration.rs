#![forbid(unsafe_code)]

use std::sync::Arc;
use warden_core::{
    Action, AddressListStore, AmountCondition, ApprovalConfig, Conditions, DestinationCondition,
    InMemoryAddressListStore, InMemoryPolicyStore, Policy, PolicyDecisionSerde, PolicyEvaluator,
    PolicyStore, Rule, TransactionRequest,
};

#[tokio::test]
async fn test_full_evaluation_flow() {
    let policy_store = Arc::new(InMemoryPolicyStore::new());
    let whitelist_store = Arc::new(InMemoryAddressListStore::new());
    let blacklist_store = Arc::new(InMemoryAddressListStore::new());

    whitelist_store
        .create_list("approved-vendors")
        .await
        .unwrap();
    whitelist_store
        .add_address("approved-vendors", "bc1qvendor123", Some("Vendor A"))
        .await
        .unwrap();

    blacklist_store.create_list("blocked").await.unwrap();
    blacklist_store
        .add_address("blocked", "bc1qbadactor", None)
        .await
        .unwrap();

    let policy = Policy {
        id: uuid::Uuid::new_v4(),
        version: "1.0".into(),
        name: "treasury-policy".into(),
        description: Some("Treasury spending controls".into()),
        rules: vec![
            Rule {
                id: "block-blacklisted".into(),
                description: Some("Block transfers to blacklisted addresses".into()),
                conditions: Conditions {
                    destination: Some(DestinationCondition {
                        in_blacklist: Some("blocked".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                action: Action::Deny,
                approval: None,
            },
            Rule {
                id: "allow-small-whitelisted".into(),
                description: Some("Auto-approve small transfers to whitelisted".into()),
                conditions: Conditions {
                    source_wallets: Some(vec!["treasury-*".into()]),
                    destination: Some(DestinationCondition {
                        in_whitelist: Some("approved-vendors".into()),
                        ..Default::default()
                    }),
                    amount: Some(AmountCondition {
                        max_sats: Some(10_000_000),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                action: Action::Allow,
                approval: None,
            },
            Rule {
                id: "require-approval-large".into(),
                description: Some("Require approval for large transfers".into()),
                conditions: Conditions {
                    amount: Some(AmountCondition {
                        min_sats: Some(100_000_000),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                action: Action::RequireApproval,
                approval: Some(ApprovalConfig {
                    quorum: 2,
                    from_groups: vec!["treasury-signers".into()],
                    timeout_hours: 24,
                }),
            },
        ],
        default_action: Action::Deny,
        content_hash: None,
        created_at: None,
        created_by: None,
        is_active: false,
    };

    policy_store.create(policy.clone()).await.unwrap();
    policy_store.activate(&policy.id).await.unwrap();

    let evaluator = PolicyEvaluator::new(
        Arc::clone(&policy_store) as Arc<dyn PolicyStore>,
        Arc::clone(&whitelist_store) as Arc<dyn warden_core::AddressListStore>,
        Arc::clone(&blacklist_store) as Arc<dyn warden_core::AddressListStore>,
    );

    let tx_blocked =
        TransactionRequest::new("treasury-hot-1".into(), "bc1qbadactor".into(), 1_000_000);
    let result = evaluator.evaluate(&tx_blocked).await.unwrap();
    assert!(
        matches!(result.decision, PolicyDecisionSerde::Deny { .. }),
        "Blacklisted address should be denied"
    );

    let tx_allowed =
        TransactionRequest::new("treasury-hot-1".into(), "bc1qvendor123".into(), 5_000_000);
    let result = evaluator.evaluate(&tx_allowed).await.unwrap();
    assert!(
        matches!(result.decision, PolicyDecisionSerde::Allow { .. }),
        "Small whitelisted transfer should be allowed"
    );

    let tx_approval = TransactionRequest::new(
        "treasury-hot-1".into(),
        "bc1qsomeaddress".into(),
        200_000_000,
    );
    let result = evaluator.evaluate(&tx_approval).await.unwrap();
    assert!(
        matches!(result.decision, PolicyDecisionSerde::RequireApproval { .. }),
        "Large transfer should require approval"
    );

    let tx_default_deny =
        TransactionRequest::new("treasury-hot-1".into(), "bc1qunknown".into(), 50_000_000);
    let result = evaluator.evaluate(&tx_default_deny).await.unwrap();
    assert!(
        matches!(result.decision, PolicyDecisionSerde::Deny { .. }),
        "Unknown medium transfer should be denied by default"
    );
}

#[tokio::test]
async fn test_wallet_pattern_matching() {
    let policy_store = Arc::new(InMemoryPolicyStore::new());
    let whitelist_store = Arc::new(InMemoryAddressListStore::new());
    let blacklist_store = Arc::new(InMemoryAddressListStore::new());

    let policy = Policy {
        id: uuid::Uuid::new_v4(),
        version: "1.0".into(),
        name: "wallet-pattern-test".into(),
        description: None,
        rules: vec![Rule {
            id: "treasury-only".into(),
            description: None,
            conditions: Conditions {
                source_wallets: Some(vec!["treasury-hot-*".into()]),
                ..Default::default()
            },
            action: Action::Allow,
            approval: None,
        }],
        default_action: Action::Deny,
        content_hash: None,
        created_at: None,
        created_by: None,
        is_active: false,
    };

    policy_store.create(policy.clone()).await.unwrap();
    policy_store.activate(&policy.id).await.unwrap();

    let evaluator = PolicyEvaluator::new(
        Arc::clone(&policy_store) as Arc<dyn PolicyStore>,
        Arc::clone(&whitelist_store) as Arc<dyn warden_core::AddressListStore>,
        Arc::clone(&blacklist_store) as Arc<dyn warden_core::AddressListStore>,
    );

    let tx_match = TransactionRequest::new("treasury-hot-1".into(), "bc1qtest".into(), 1000);
    let result = evaluator.evaluate(&tx_match).await.unwrap();
    assert!(matches!(result.decision, PolicyDecisionSerde::Allow { .. }));

    let tx_match2 = TransactionRequest::new("treasury-hot-prod".into(), "bc1qtest".into(), 1000);
    let result = evaluator.evaluate(&tx_match2).await.unwrap();
    assert!(matches!(result.decision, PolicyDecisionSerde::Allow { .. }));

    let tx_no_match = TransactionRequest::new("cold-storage".into(), "bc1qtest".into(), 1000);
    let result = evaluator.evaluate(&tx_no_match).await.unwrap();
    assert!(matches!(result.decision, PolicyDecisionSerde::Deny { .. }));
}

#[tokio::test]
async fn test_evaluation_trace() {
    let policy_store = Arc::new(InMemoryPolicyStore::new());
    let whitelist_store = Arc::new(InMemoryAddressListStore::new());
    let blacklist_store = Arc::new(InMemoryAddressListStore::new());

    let policy = Policy {
        id: uuid::Uuid::new_v4(),
        version: "1.0".into(),
        name: "trace-test".into(),
        description: None,
        rules: vec![
            Rule {
                id: "rule-1".into(),
                description: None,
                conditions: Conditions {
                    amount: Some(AmountCondition {
                        min_sats: Some(1_000_000),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                action: Action::Deny,
                approval: None,
            },
            Rule {
                id: "rule-2".into(),
                description: None,
                conditions: Conditions {
                    source_wallets: Some(vec!["*".into()]),
                    ..Default::default()
                },
                action: Action::Allow,
                approval: None,
            },
        ],
        default_action: Action::Deny,
        content_hash: None,
        created_at: None,
        created_by: None,
        is_active: false,
    };

    policy_store.create(policy.clone()).await.unwrap();
    policy_store.activate(&policy.id).await.unwrap();

    let evaluator = PolicyEvaluator::new(
        Arc::clone(&policy_store) as Arc<dyn PolicyStore>,
        Arc::clone(&whitelist_store) as Arc<dyn warden_core::AddressListStore>,
        Arc::clone(&blacklist_store) as Arc<dyn warden_core::AddressListStore>,
    );

    let tx = TransactionRequest::new("wallet".into(), "bc1qtest".into(), 500_000);
    let result = evaluator.evaluate(&tx).await.unwrap();

    assert!(!result.trace.is_empty(), "Trace should not be empty");
    assert_eq!(result.trace[0].rule_id, "rule-1");
    assert!(
        !result.trace[0].matched,
        "rule-1 should not match (amount too small)"
    );
    assert_eq!(result.trace[1].rule_id, "rule-2");
    assert!(result.trace[1].matched, "rule-2 should match (catch-all)");
}

mod approval_workflows {
    use chrono::Duration;
    use std::sync::Arc;
    use uuid::Uuid;
    use warden_core::{
        Action, AmountCondition, Approval, ApprovalConfig, ApprovalDecision, ApprovalWorkflow,
        ApproverGroup, Conditions, GroupMember, GroupStore, InMemoryAddressListStore,
        InMemoryGroupStore, InMemoryPolicyStore, InMemoryWorkflowStore, Policy,
        PolicyDecisionSerde, PolicyEvaluator, PolicyStore, QuorumEvaluator, QuorumStatus,
        RequirementNode, Rule, TransactionDetails, TransactionRequest, WorkflowStatus,
        WorkflowStore,
    };

    #[tokio::test]
    async fn test_simple_threshold_quorum() {
        let requirement = RequirementNode::threshold(2, "treasury-signers");
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(!status.is_satisfied());

        let approvals = vec![Approval::new(
            "alice".into(),
            "treasury-signers".into(),
            ApprovalDecision::Approve,
            0,
        )];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(!status.is_satisfied());
        if let QuorumStatus::Pending {
            collected,
            required,
            ..
        } = status
        {
            assert_eq!(collected, 1);
            assert_eq!(required, 2);
        } else {
            panic!("Expected Pending status");
        }

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "treasury-signers".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bob".into(),
                "treasury-signers".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(status.is_satisfied());
    }

    #[tokio::test]
    async fn test_and_composition() {
        let requirement = RequirementNode::all(vec![
            RequirementNode::threshold(1, "finance-team"),
            RequirementNode::threshold(2, "security-team"),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![Approval::new(
            "alice".into(),
            "finance-team".into(),
            ApprovalDecision::Approve,
            0,
        )];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "finance-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bob".into(),
                "security-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "finance-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bob".into(),
                "security-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "charlie".into(),
                "security-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    #[tokio::test]
    async fn test_or_composition() {
        let requirement = RequirementNode::any(vec![
            RequirementNode::threshold(1, "ceo"),
            RequirementNode::all(vec![
                RequirementNode::threshold(1, "cfo"),
                RequirementNode::threshold(1, "cto"),
            ]),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![Approval::new(
            "alice".into(),
            "ceo".into(),
            ApprovalDecision::Approve,
            0,
        )];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![Approval::new(
            "bob".into(),
            "cfo".into(),
            ApprovalDecision::Approve,
            0,
        )];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            Approval::new("bob".into(), "cfo".into(), ApprovalDecision::Approve, 0),
            Approval::new("charlie".into(), "cto".into(), ApprovalDecision::Approve, 0),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    #[tokio::test]
    async fn test_k_of_composition() {
        let requirement = RequirementNode::k_of(
            2,
            vec![
                RequirementNode::threshold(1, "finance"),
                RequirementNode::threshold(1, "security"),
                RequirementNode::threshold(1, "compliance"),
            ],
        );
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![Approval::new(
            "alice".into(),
            "finance".into(),
            ApprovalDecision::Approve,
            0,
        )];
        let status = evaluator.evaluate(&requirement, &approvals);
        assert!(!status.is_satisfied());
        if let QuorumStatus::PendingKOf {
            satisfied,
            required,
            total,
        } = status
        {
            assert_eq!(satisfied, 1);
            assert_eq!(required, 2);
            assert_eq!(total, 3);
        }

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "finance".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bob".into(),
                "compliance".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    #[tokio::test]
    async fn test_workflow_status_transitions() {
        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 100_000_000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        assert_eq!(workflow.status, WorkflowStatus::Pending);

        let approval1 = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval1);
        assert_eq!(workflow.status, WorkflowStatus::Pending);

        let approval2 = Approval::new(
            "bob".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval2);
        assert_eq!(workflow.status, WorkflowStatus::Approved);
    }

    #[tokio::test]
    async fn test_rejection_terminates_workflow() {
        let requirement = RequirementNode::threshold(3, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 100_000_000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let approval = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval);
        assert_eq!(workflow.status, WorkflowStatus::Pending);

        let rejection = Approval::new("bob".into(), "treasury".into(), ApprovalDecision::Reject, 0)
            .with_comment("Too risky".into());
        workflow.add_approval(rejection);
        assert_eq!(workflow.status, WorkflowStatus::Rejected);
        assert_eq!(workflow.rejected_by, Some("bob".into()));
        assert_eq!(workflow.rejection_reason, Some("Too risky".into()));
    }

    #[tokio::test]
    async fn test_self_approval_prevention() {
        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 100_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            Some("alice".into()),
            requirement,
            details,
            Duration::hours(24),
        );

        assert!(!workflow.can_approve("alice", &["treasury".into()]));
        assert!(workflow.can_approve("bob", &["treasury".into()]));
        assert!(!workflow.can_approve("charlie", &["finance".into()]));
    }

    #[tokio::test]
    async fn test_workflow_store_operations() {
        let store = Arc::new(InMemoryWorkflowStore::new());

        let requirement = RequirementNode::threshold(1, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 50_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let workflow_id = workflow.id;
        store.create_workflow(workflow).await.unwrap();

        let retrieved = store.get_workflow(&workflow_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, workflow_id);

        let pending = store.list_pending_workflows().await.unwrap();
        assert_eq!(pending.len(), 1);

        let approval = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        let updated = store
            .add_approval_to_workflow(&workflow_id, approval)
            .await
            .unwrap();
        assert_eq!(updated.status, WorkflowStatus::Approved);

        let pending_after = store.list_pending_workflows().await.unwrap();
        assert_eq!(pending_after.len(), 0);
    }

    #[tokio::test]
    async fn test_group_store_operations() {
        let store = Arc::new(InMemoryGroupStore::new());

        let group =
            ApproverGroup::new("treasury-signers").with_description("Treasury signing group");
        let created = store.create(group).await.unwrap();
        assert_eq!(created.name, "treasury-signers");

        let member1 = GroupMember::new("alice");
        store.add_member(&created.id, member1).await.unwrap();

        let member2 = GroupMember::new("bob").with_display_name("Bob Smith");
        store.add_member(&created.id, member2).await.unwrap();

        let retrieved = store
            .get_by_name("treasury-signers")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.members.len(), 2);

        let alice_groups = store.get_groups_for_approver("alice").await.unwrap();
        assert_eq!(alice_groups.len(), 1);
        assert_eq!(alice_groups[0].name, "treasury-signers");

        store.remove_member(&created.id, "alice").await.unwrap();
        let after_remove = store.get(&created.id).await.unwrap().unwrap();
        assert_eq!(after_remove.members.len(), 1);
    }

    #[tokio::test]
    async fn test_pending_groups_calculation() {
        let requirement = RequirementNode::all(vec![
            RequirementNode::threshold(2, "treasury"),
            RequirementNode::threshold(1, "compliance"),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
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

    #[tokio::test]
    async fn test_duplicate_approval_prevention() {
        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 100_000_000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let approval1 = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval1);
        assert!(workflow.can_approve("bob", &["treasury".into()]));
        assert!(!workflow.can_approve("alice", &["treasury".into()]));
    }

    #[tokio::test]
    async fn test_transaction_details() {
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 100_000_000);
        assert_eq!(details.amount_btc(), 1.0);

        let details_small = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 50_000);
        assert_eq!(details_small.amount_btc(), 0.0005);
    }

    #[tokio::test]
    async fn test_requirement_validation() {
        assert!(RequirementNode::threshold(0, "test").validate().is_err());
        assert!(RequirementNode::threshold(1, "").validate().is_err());
        assert!(RequirementNode::all(vec![]).validate().is_err());
        assert!(
            RequirementNode::k_of(3, vec![RequirementNode::threshold(1, "a")])
                .validate()
                .is_err()
        );
        assert!(RequirementNode::threshold(2, "treasury").validate().is_ok());

        let complex = RequirementNode::all(vec![
            RequirementNode::threshold(1, "finance"),
            RequirementNode::any(vec![
                RequirementNode::threshold(1, "ceo"),
                RequirementNode::k_of(
                    2,
                    vec![
                        RequirementNode::threshold(1, "cfo"),
                        RequirementNode::threshold(1, "cto"),
                        RequirementNode::threshold(1, "coo"),
                    ],
                ),
            ]),
        ]);
        assert!(complex.validate().is_ok());
    }

    #[tokio::test]
    async fn test_all_groups_extraction() {
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

    #[tokio::test]
    async fn test_expired_workflow_blocks_approval() {
        let requirement = RequirementNode::threshold(1, "treasury");
        let details = TransactionDetails::new("wallet1".into(), "bc1qdest".into(), 100_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::seconds(-1),
        );

        assert!(workflow.is_expired());
        assert!(!workflow.can_approve("alice", &["treasury".into()]));
    }

    #[tokio::test]
    async fn test_complex_nested_quorum() {
        let requirement = RequirementNode::all(vec![
            RequirementNode::threshold(1, "initiator"),
            RequirementNode::any(vec![
                RequirementNode::threshold(1, "executive"),
                RequirementNode::k_of(
                    2,
                    vec![
                        RequirementNode::threshold(1, "finance"),
                        RequirementNode::threshold(1, "legal"),
                        RequirementNode::threshold(1, "compliance"),
                    ],
                ),
            ]),
        ]);
        let evaluator = QuorumEvaluator::new();

        let approvals = vec![Approval::new(
            "alice".into(),
            "initiator".into(),
            ApprovalDecision::Approve,
            0,
        )];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "initiator".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bob".into(),
                "executive".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "initiator".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new("bob".into(), "finance".into(), ApprovalDecision::Approve, 0),
            Approval::new(
                "charlie".into(),
                "legal".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "initiator".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new("bob".into(), "finance".into(), ApprovalDecision::Approve, 0),
        ];
        assert!(!evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    /// SUCCESS CRITERIA 1: Approval workflows start automatically for REQUIRE_APPROVAL decisions
    #[tokio::test]
    async fn test_policy_triggers_approval_workflow() {
        let policy_store = Arc::new(InMemoryPolicyStore::new());
        let whitelist_store = Arc::new(InMemoryAddressListStore::new());
        let blacklist_store = Arc::new(InMemoryAddressListStore::new());
        let workflow_store = Arc::new(InMemoryWorkflowStore::new());
        let group_store = Arc::new(InMemoryGroupStore::new());

        let treasury_group = ApproverGroup::new("treasury-signers");
        group_store.create(treasury_group).await.unwrap();

        let policy = Policy {
            id: Uuid::new_v4(),
            version: "1.0".into(),
            name: "treasury-policy".into(),
            description: None,
            rules: vec![
                Rule {
                    id: "small-auto-approve".into(),
                    description: None,
                    conditions: Conditions {
                        amount: Some(AmountCondition {
                            max_sats: Some(1_000_000),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    action: Action::Allow,
                    approval: None,
                },
                Rule {
                    id: "large-require-approval".into(),
                    description: None,
                    conditions: Conditions {
                        amount: Some(AmountCondition {
                            min_sats: Some(1_000_001),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    action: Action::RequireApproval,
                    approval: Some(ApprovalConfig {
                        quorum: 2,
                        from_groups: vec!["treasury-signers".into()],
                        timeout_hours: 24,
                    }),
                },
            ],
            default_action: Action::Deny,
            content_hash: None,
            created_at: None,
            created_by: None,
            is_active: false,
        };

        policy_store.create(policy.clone()).await.unwrap();
        policy_store.activate(&policy.id).await.unwrap();

        let evaluator = PolicyEvaluator::new(
            policy_store.clone() as Arc<dyn PolicyStore>,
            whitelist_store.clone() as Arc<dyn warden_core::AddressListStore>,
            blacklist_store.clone() as Arc<dyn warden_core::AddressListStore>,
        );

        let small_tx = TransactionRequest::new("treasury".into(), "bc1dest".into(), 500_000);
        let result = evaluator.evaluate(&small_tx).await.unwrap();
        assert!(matches!(result.decision, PolicyDecisionSerde::Allow { .. }));

        let large_tx = TransactionRequest::new("treasury".into(), "bc1dest".into(), 5_000_000);
        let result = evaluator.evaluate(&large_tx).await.unwrap();

        match &result.decision {
            PolicyDecisionSerde::RequireApproval {
                rule_id,
                approval_config,
            } => {
                assert_eq!(rule_id, "large-require-approval");
                assert_eq!(approval_config.quorum, 2);
                assert_eq!(approval_config.from_groups, vec!["treasury-signers"]);

                let details = TransactionDetails::new(
                    large_tx.source_wallet.clone(),
                    large_tx.destination.clone(),
                    large_tx.amount_sats,
                );
                let workflow = ApprovalWorkflow::from_config(
                    large_tx.id,
                    result.policy_id,
                    rule_id.clone(),
                    Some("requester-user".into()),
                    approval_config,
                    details,
                );

                assert_eq!(workflow.status, WorkflowStatus::Pending);
                workflow_store
                    .create_workflow(workflow.clone())
                    .await
                    .unwrap();

                let pending = workflow_store.list_pending_workflows().await.unwrap();
                assert_eq!(pending.len(), 1);
                assert_eq!(pending[0].id, workflow.id);
            }
            _ => panic!("Expected RequireApproval decision"),
        }
    }

    /// SUCCESS CRITERIA 6 & 7: Approved/Rejected transactions properly recorded
    #[tokio::test]
    async fn test_full_approval_flow_to_completion() {
        let workflow_store = Arc::new(InMemoryWorkflowStore::new());
        let group_store = Arc::new(InMemoryGroupStore::new());

        let mut treasury_group = ApproverGroup::new("treasury-signers");
        treasury_group.add_member(GroupMember::new("alice"));
        treasury_group.add_member(GroupMember::new("bob"));
        treasury_group.add_member(GroupMember::new("charlie"));
        let _created_group = group_store.create(treasury_group).await.unwrap();

        let requirement = RequirementNode::threshold(2, "treasury-signers");
        let details = TransactionDetails::new("treasury".into(), "bc1dest".into(), 10_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            Some("requester".into()),
            requirement,
            details,
            Duration::hours(24),
        );
        let workflow_id = workflow.id;
        workflow_store.create_workflow(workflow).await.unwrap();

        assert!(!workflow_store
            .get_workflow(&workflow_id)
            .await
            .unwrap()
            .unwrap()
            .can_approve("requester", &["treasury-signers".into()]));

        let alice_groups = group_store.get_groups_for_approver("alice").await.unwrap();
        let alice_group_names: Vec<_> = alice_groups.iter().map(|g| g.name.clone()).collect();

        let workflow = workflow_store
            .get_workflow(&workflow_id)
            .await
            .unwrap()
            .unwrap();
        assert!(workflow.can_approve("alice", &alice_group_names));

        let approval1 = Approval::new(
            "alice".into(),
            "treasury-signers".into(),
            ApprovalDecision::Approve,
            0,
        );
        let updated = workflow_store
            .add_approval_to_workflow(&workflow_id, approval1)
            .await
            .unwrap();
        assert_eq!(updated.status, WorkflowStatus::Pending);
        assert_eq!(updated.approvals.len(), 1);

        let workflow = workflow_store
            .get_workflow(&workflow_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!workflow.can_approve("alice", &alice_group_names));

        let approval2 = Approval::new(
            "bob".into(),
            "treasury-signers".into(),
            ApprovalDecision::Approve,
            0,
        );
        let updated = workflow_store
            .add_approval_to_workflow(&workflow_id, approval2)
            .await
            .unwrap();

        assert_eq!(updated.status, WorkflowStatus::Approved);
        assert!(updated.completed_at.is_some());
        assert_eq!(updated.approvals.len(), 2);

        let pending = workflow_store.list_pending_workflows().await.unwrap();
        assert!(pending.is_empty());
    }

    /// SUCCESS CRITERIA 7: Rejected transactions properly recorded
    #[tokio::test]
    async fn test_rejection_flow() {
        let workflow_store = Arc::new(InMemoryWorkflowStore::new());

        let requirement = RequirementNode::threshold(2, "treasury-signers");
        let details = TransactionDetails::new("treasury".into(), "bc1dest".into(), 10_000_000);

        let workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );
        let workflow_id = workflow.id;
        workflow_store.create_workflow(workflow).await.unwrap();

        let approval1 = Approval::new(
            "alice".into(),
            "treasury-signers".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow_store
            .add_approval_to_workflow(&workflow_id, approval1)
            .await
            .unwrap();

        let rejection = Approval::new(
            "bob".into(),
            "treasury-signers".into(),
            ApprovalDecision::Reject,
            0,
        )
        .with_comment("Transaction looks suspicious".into());

        let updated = workflow_store
            .add_approval_to_workflow(&workflow_id, rejection)
            .await
            .unwrap();

        assert_eq!(updated.status, WorkflowStatus::Rejected);
        assert_eq!(updated.rejected_by, Some("bob".into()));
        assert_eq!(
            updated.rejection_reason,
            Some("Transaction looks suspicious".into())
        );
        assert!(updated.completed_at.is_some());
    }

    /// SUCCESS CRITERIA 8: Pending approvals queryable per approver
    #[tokio::test]
    async fn test_pending_approvals_per_approver() {
        let workflow_store = Arc::new(InMemoryWorkflowStore::new());
        let group_store = Arc::new(InMemoryGroupStore::new());

        let mut treasury_group = ApproverGroup::new("treasury");
        treasury_group.add_member(GroupMember::new("alice"));
        treasury_group.add_member(GroupMember::new("bob"));
        group_store.create(treasury_group).await.unwrap();

        let mut finance_group = ApproverGroup::new("finance");
        finance_group.add_member(GroupMember::new("charlie"));
        group_store.create(finance_group).await.unwrap();

        let treasury_workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            RequirementNode::threshold(1, "treasury"),
            TransactionDetails::new("wallet".into(), "dest".into(), 1_000_000),
            Duration::hours(24),
        );
        let treasury_wf_id = treasury_workflow.id;
        workflow_store
            .create_workflow(treasury_workflow)
            .await
            .unwrap();

        let finance_workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule2".into(),
            None,
            RequirementNode::threshold(1, "finance"),
            TransactionDetails::new("wallet".into(), "dest".into(), 2_000_000),
            Duration::hours(24),
        );
        let finance_wf_id = finance_workflow.id;
        workflow_store
            .create_workflow(finance_workflow)
            .await
            .unwrap();

        let alice_groups = group_store.get_groups_for_approver("alice").await.unwrap();
        let alice_group_names: Vec<_> = alice_groups.iter().map(|g| g.name.clone()).collect();
        let alice_pending = workflow_store
            .list_pending_for_approver("alice", &alice_group_names)
            .await
            .unwrap();
        assert_eq!(alice_pending.len(), 1);
        assert_eq!(alice_pending[0].id, treasury_wf_id);

        let charlie_groups = group_store
            .get_groups_for_approver("charlie")
            .await
            .unwrap();
        let charlie_group_names: Vec<_> = charlie_groups.iter().map(|g| g.name.clone()).collect();
        let charlie_pending = workflow_store
            .list_pending_for_approver("charlie", &charlie_group_names)
            .await
            .unwrap();
        assert_eq!(charlie_pending.len(), 1);
        assert_eq!(charlie_pending[0].id, finance_wf_id);

        let all_pending = workflow_store.list_pending_workflows().await.unwrap();
        assert_eq!(all_pending.len(), 2);
    }

    /// Verify defense in depth: duplicate approvals silently ignored
    #[tokio::test]
    async fn test_duplicate_approval_defense() {
        let requirement = RequirementNode::threshold(2, "treasury");
        let details = TransactionDetails::new("wallet".into(), "dest".into(), 1_000_000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let approval1 = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval1.clone());
        assert_eq!(workflow.approvals.len(), 1);

        workflow.add_approval(approval1);
        assert_eq!(workflow.approvals.len(), 1);

        let approval2 = Approval::new(
            "bob".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval2);
        assert_eq!(workflow.approvals.len(), 2);
        assert_eq!(workflow.status, WorkflowStatus::Approved);
    }

    /// Verify self-approval defense in add_approval
    #[tokio::test]
    async fn test_self_approval_defense_in_add_approval() {
        let requirement = RequirementNode::threshold(1, "treasury");
        let details = TransactionDetails::new("wallet".into(), "dest".into(), 1_000_000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            Some("alice".into()),
            requirement,
            details,
            Duration::hours(24),
        );

        let self_approval = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(self_approval);
        assert_eq!(workflow.approvals.len(), 0);
        assert_eq!(workflow.status, WorkflowStatus::Pending);

        let valid_approval = Approval::new(
            "bob".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(valid_approval);
        assert_eq!(workflow.approvals.len(), 1);
        assert_eq!(workflow.status, WorkflowStatus::Approved);
    }

    /// Verify approvals blocked after workflow completed
    #[tokio::test]
    async fn test_no_approval_after_completion() {
        let requirement = RequirementNode::threshold(1, "treasury");
        let details = TransactionDetails::new("wallet".into(), "dest".into(), 1_000_000);

        let mut workflow = ApprovalWorkflow::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "rule1".into(),
            None,
            requirement,
            details,
            Duration::hours(24),
        );

        let approval = Approval::new(
            "alice".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(approval);
        assert_eq!(workflow.status, WorkflowStatus::Approved);

        let late_approval = Approval::new(
            "bob".into(),
            "treasury".into(),
            ApprovalDecision::Approve,
            0,
        );
        workflow.add_approval(late_approval);
        assert_eq!(workflow.approvals.len(), 1);
    }

    /// Verify YAML config parsing matches spec examples
    #[tokio::test]
    async fn test_yaml_quorum_config_parsing() {
        let yaml = r#"
            type: all
            requirements:
              - type: threshold
                threshold: 1
                group: finance-team
              - type: threshold
                threshold: 2
                group: security-team
              - type: threshold
                threshold: 1
                group: compliance-bots
        "#;

        let requirement: RequirementNode = serde_yaml::from_str(yaml).unwrap();
        requirement.validate().unwrap();

        let groups = requirement.all_groups();
        assert!(groups.contains("finance-team"));
        assert!(groups.contains("security-team"));
        assert!(groups.contains("compliance-bots"));

        let evaluator = QuorumEvaluator::new();

        let approvals = vec![
            Approval::new(
                "alice".into(),
                "finance-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bob".into(),
                "security-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "charlie".into(),
                "security-team".into(),
                ApprovalDecision::Approve,
                0,
            ),
            Approval::new(
                "bot1".into(),
                "compliance-bots".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(evaluator.evaluate(&requirement, &approvals).is_satisfied());
    }

    /// Verify flexible quorum: CEO alone OR (CFO AND CTO)
    #[tokio::test]
    async fn test_flexible_quorum_from_spec() {
        let yaml = r#"
            type: any
            requirements:
              - type: threshold
                threshold: 1
                group: ceo
              - type: all
                requirements:
                  - type: threshold
                    threshold: 1
                    group: cfo
                  - type: threshold
                    threshold: 1
                    group: cto
        "#;

        let requirement: RequirementNode = serde_yaml::from_str(yaml).unwrap();
        requirement.validate().unwrap();

        let evaluator = QuorumEvaluator::new();

        let ceo_only = vec![Approval::new(
            "ceo-alice".into(),
            "ceo".into(),
            ApprovalDecision::Approve,
            0,
        )];
        assert!(evaluator.evaluate(&requirement, &ceo_only).is_satisfied());

        let cfo_cto = vec![
            Approval::new("cfo-bob".into(), "cfo".into(), ApprovalDecision::Approve, 0),
            Approval::new(
                "cto-charlie".into(),
                "cto".into(),
                ApprovalDecision::Approve,
                0,
            ),
        ];
        assert!(evaluator.evaluate(&requirement, &cfo_cto).is_satisfied());

        let cfo_only = vec![Approval::new(
            "cfo-bob".into(),
            "cfo".into(),
            ApprovalDecision::Approve,
            0,
        )];
        assert!(!evaluator.evaluate(&requirement, &cfo_only).is_satisfied());
    }
}

mod production_hardening {
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use warden_core::{
        ActorInfo, ActorType, AuditEventType, AuditLog, AuditQuery, BundleContents, BundleLoader,
        BundleManifest, BundleSignature, CallbackAction, CallbackGateway, CallbackHandlerConfig,
        CallbackRuleConfig, ChainVerification, ComplianceExporter, ComplianceProvider,
        EnclaveClient, EnclaveConfig, EnclaveDecision, EscalationAction, EscalationManager,
        EscalationPolicy, EscalationPolicyStore, EscalationStage, EvaluationRequest, ExpectedPcrs,
        FinalAction, Hash, InMemoryAuditStore, InMemoryBundleStore, InMemoryEscalationPolicyStore,
        MerkleTree, MockBundleSigner, MockComplianceProvider, MockEnclaveClient, PendingWorkflow,
        ResourceInfo, Secp256k1AuditSigner, TransactionRequest, WorkflowClient,
    };

    #[test]
    fn test_merkle_tree_construction_and_verification() {
        let files = vec![
            (
                "policies/treasury.yaml".to_string(),
                b"policy content 1".to_vec(),
            ),
            (
                "policies/operations.yaml".to_string(),
                b"policy content 2".to_vec(),
            ),
            (
                "data/whitelist.json".to_string(),
                b"[\"addr1\", \"addr2\"]".to_vec(),
            ),
        ];

        let tree = MerkleTree::build(&files);
        assert_eq!(tree.leaves().len(), 3);

        for (path, _) in &files {
            let proof = tree.prove(path).expect("Proof should exist");
            assert!(MerkleTree::verify(&tree.root(), &proof));
        }

        let missing_proof = tree.prove("nonexistent.yaml");
        assert!(missing_proof.is_none());
    }

    #[test]
    fn test_merkle_tree_tamper_detection() {
        let files = vec![
            ("a.yaml".to_string(), b"content a".to_vec()),
            ("b.yaml".to_string(), b"content b".to_vec()),
        ];

        let tree = MerkleTree::build(&files);
        let proof = tree.prove("a.yaml").unwrap();

        let tampered_root: Hash = [0u8; 32];
        assert!(!MerkleTree::verify(&tampered_root, &proof));

        assert!(MerkleTree::verify(&tree.root(), &proof));
    }

    #[tokio::test]
    async fn test_bundle_loader_signature_verification() {
        let store = InMemoryBundleStore::new();
        let signer = MockBundleSigner::new()
            .with_key("admin-key-1", b"secret1".to_vec())
            .with_key("admin-key-2", b"secret2".to_vec());

        let loader = BundleLoader::new(store, signer);

        let current = loader.current().await;
        assert!(current.is_none());
    }

    #[tokio::test]
    async fn test_audit_log_cryptographic_chaining() {
        let store = InMemoryAuditStore::new();
        let signer = Secp256k1AuditSigner::generate();
        let log = AuditLog::new(store, signer).await.unwrap();

        log.record(
            AuditEventType::SystemStarted {
                version: "1.0.0".into(),
            },
            None,
            ResourceInfo::system(),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::PolicyCreated {
                policy_id: "policy-1".into(),
                version: "1.0.0".into(),
            },
            Some(ActorInfo {
                actor_type: ActorType::User,
                id: "admin".into(),
                ip_address: Some("192.168.1.1".into()),
                user_agent: None,
            }),
            ResourceInfo::policy("policy-1"),
            serde_json::json!({"description": "Test policy"}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::TransactionSubmitted {
                transaction_id: "tx-123".into(),
            },
            None,
            ResourceInfo::transaction("tx-123"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let verification = log.verify_chain(1).await.unwrap();
        match verification {
            ChainVerification::Valid { events_checked, .. } => {
                assert_eq!(events_checked, 3);
            }
            _ => panic!("Chain should be valid"),
        }
    }

    #[tokio::test]
    async fn test_audit_query_filtering() {
        let store = InMemoryAuditStore::new();
        let signer = Secp256k1AuditSigner::generate();
        let log = AuditLog::new(store, signer).await.unwrap();

        log.record(
            AuditEventType::TransactionSubmitted {
                transaction_id: "tx-1".into(),
            },
            Some(ActorInfo {
                actor_type: ActorType::User,
                id: "alice".into(),
                ip_address: None,
                user_agent: None,
            }),
            ResourceInfo::transaction("tx-1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::TransactionSubmitted {
                transaction_id: "tx-2".into(),
            },
            Some(ActorInfo {
                actor_type: ActorType::User,
                id: "bob".into(),
                ip_address: None,
                user_agent: None,
            }),
            ResourceInfo::transaction("tx-2"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let alice_events = log
            .query(&AuditQuery {
                actor_id: Some("alice".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(alice_events.len(), 1);

        let tx1_events = log
            .query(&AuditQuery {
                resource_id: Some("tx-1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(tx1_events.len(), 1);
    }

    #[tokio::test]
    async fn test_compliance_exporter_soc2() {
        let store = InMemoryAuditStore::new();
        let signer = Secp256k1AuditSigner::generate();
        let log = AuditLog::new(store, signer).await.unwrap();

        log.record(
            AuditEventType::PolicyCreated {
                policy_id: "p1".into(),
                version: "1.0".into(),
            },
            None,
            ResourceInfo::policy("p1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::ApprovalReceived {
                transaction_id: "tx-1".into(),
                approver_id: "alice".into(),
                decision: "approve".into(),
            },
            None,
            ResourceInfo::transaction("tx-1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        log.record(
            AuditEventType::SigningFailed {
                transaction_id: "tx-2".into(),
                error: "timeout".into(),
            },
            None,
            ResourceInfo::transaction("tx-2"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let exporter = ComplianceExporter::new(log);
        let report = exporter
            .export_soc2(
                Utc::now() - Duration::hours(1),
                Utc::now() + Duration::hours(1),
            )
            .await
            .unwrap();

        assert!(!report.change_management.is_empty());
        assert!(!report.access_controls.is_empty());
        assert!(!report.incident_response.is_empty());
        assert_eq!(report.chain_verification.status, "valid");
    }

    #[test]
    fn test_callback_handler_config() {
        let config = CallbackHandlerConfig {
            id: "chainalysis-screening".into(),
            url: "https://compliance.example.com/callback".into(),
            public_key: Some("-----BEGIN PUBLIC KEY-----...".into()),
            timeout_seconds: 30,
            enabled: true,
            max_retries: 3,
        };

        assert!(config.enabled);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_callback_rule_config() {
        let config = CallbackRuleConfig {
            handler: "chainalysis-screening".into(),
            on_approve: CallbackAction::Allow,
            on_reject: CallbackAction::Deny,
            on_timeout: CallbackAction::RequireApproval,
            timeout_seconds: 30,
        };

        assert_eq!(config.on_approve, CallbackAction::Allow);
        assert_eq!(config.on_reject, CallbackAction::Deny);
        assert_eq!(config.on_timeout, CallbackAction::RequireApproval);
    }

    #[tokio::test]
    async fn test_callback_gateway_handler_registration() {
        let mut gateway = CallbackGateway::new();

        gateway.register_handler(CallbackHandlerConfig {
            id: "handler-1".into(),
            url: "https://handler1.example.com".into(),
            public_key: None,
            timeout_seconds: 30,
            enabled: true,
            max_retries: 3,
        });

        let handler = gateway.get_handler("handler-1");
        assert!(handler.is_some());

        let handlers = gateway.list_handlers();
        assert_eq!(handlers.len(), 1);

        gateway.remove_handler("handler-1");
        assert!(gateway.get_handler("handler-1").is_none());
    }

    #[tokio::test]
    async fn test_mock_compliance_provider_screening() {
        let provider = MockComplianceProvider::new()
            .with_risk_score("bc1q_risky_address", 0.95)
            .with_risk_score("bc1q_safe_address", 0.1);

        let risky = provider.screen_address("bc1q_risky_address").await.unwrap();
        assert!(risky.risk_score > 0.7);
        assert_eq!(risky.risk_category, Some("high_risk".into()));

        let safe = provider.screen_address("bc1q_safe_address").await.unwrap();
        assert!(safe.risk_score < 0.3);
        assert_eq!(safe.risk_category, Some("low_risk".into()));

        let unknown = provider.screen_address("bc1q_unknown").await.unwrap();
        assert!(unknown.risk_score < 0.5);
    }

    #[tokio::test]
    async fn test_mock_enclave_client_operations() {
        let client = MockEnclaveClient::new();

        let tx = TransactionRequest::new("wallet-1".into(), "bc1q_destination".into(), 1_000_000);

        let result = client
            .evaluate(EvaluationRequest {
                transaction: tx,
                policy_id: None,
            })
            .await
            .unwrap();

        assert_eq!(result.decision, EnclaveDecision::Allow);
        assert!(!result.policy_version.is_empty());

        let attestation = client.verify_attestation().await.unwrap();
        assert!(!attestation.enclave_pubkey.is_empty());
    }

    #[test]
    fn test_expected_pcrs_parsing() {
        let pcr0 = "0".repeat(96);
        let pcr1 = "1".repeat(96);
        let pcr2 = "2".repeat(96);

        let pcrs = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2).unwrap();
        assert_eq!(pcrs.pcr0[0], 0x00);
        assert_eq!(pcrs.pcr1[0], 0x11);
        assert_eq!(pcrs.pcr2[0], 0x22);
    }

    #[test]
    fn test_enclave_config_defaults() {
        let config = EnclaveConfig::default();
        assert_eq!(config.cid, 16);
        assert_eq!(config.port, 5000);
        assert!(config.expected_pcrs.is_none());
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_escalation_policy_stages() {
        let policy = EscalationPolicy::default();

        assert_eq!(policy.name, "default-escalation");
        assert_eq!(policy.stages.len(), 3);

        assert_eq!(policy.stages[0].stage, 1);
        assert_eq!(policy.stages[0].duration_hours, 4);

        assert_eq!(policy.stages[1].stage, 2);
        assert_eq!(policy.stages[1].duration_hours, 8);

        assert_eq!(policy.stages[2].stage, 3);
        assert_eq!(policy.stages[2].duration_hours, 24);

        match &policy.final_action {
            FinalAction::AutoReject { reason } => {
                assert!(reason.contains("timeout"));
            }
            _ => panic!("Expected AutoReject final action"),
        }
    }

    #[test]
    fn test_escalation_actions_serialization() {
        let reminder = EscalationAction::Reminder {
            channels: vec!["email".into(), "slack".into()],
            message: "Approval pending for {transaction_id}".into(),
        };
        let json = serde_json::to_string(&reminder).unwrap();
        assert!(json.contains("reminder"));

        let escalate = EscalationAction::Escalate {
            to_groups: vec!["managers".into()],
            add_to_approvers: true,
        };
        let json = serde_json::to_string(&escalate).unwrap();
        assert!(json.contains("escalate"));
    }

    #[tokio::test]
    async fn test_escalation_policy_store() {
        let store = InMemoryEscalationPolicyStore::new();

        let policy = EscalationPolicy::default();
        store.create(policy.clone()).await.unwrap();

        let retrieved = store.get(&policy.name).await.unwrap();
        assert_eq!(retrieved.name, policy.name);

        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);

        let updated = EscalationPolicy {
            name: policy.name.clone(),
            stages: vec![EscalationStage {
                stage: 1,
                duration_hours: 2,
                actions: vec![],
            }],
            final_action: FinalAction::Notify {
                channels: vec!["slack".into()],
                message: "Workflow expired".into(),
            },
        };
        store.update(updated).await.unwrap();

        let after_update = store.get(&policy.name).await.unwrap();
        assert_eq!(after_update.stages.len(), 1);
        assert_eq!(after_update.stages[0].duration_hours, 2);

        store.delete(&policy.name).await.unwrap();
        assert!(store.get(&policy.name).await.is_err());
    }

    struct MockWorkflowClient {
        workflows: tokio::sync::RwLock<Vec<PendingWorkflow>>,
    }

    impl MockWorkflowClient {
        fn new() -> Self {
            Self {
                workflows: tokio::sync::RwLock::new(vec![]),
            }
        }

        async fn add_workflow(&self, workflow: PendingWorkflow) {
            self.workflows.write().await.push(workflow);
        }
    }

    #[async_trait::async_trait]
    impl WorkflowClient for MockWorkflowClient {
        async fn list_pending_workflows(&self) -> warden_core::Result<Vec<PendingWorkflow>> {
            Ok(self.workflows.read().await.clone())
        }

        async fn add_approver_groups(
            &self,
            _workflow_id: &str,
            _groups: &[String],
        ) -> warden_core::Result<()> {
            Ok(())
        }

        async fn update_escalation_stage(
            &self,
            _workflow_id: &str,
            _stage: u32,
        ) -> warden_core::Result<()> {
            Ok(())
        }

        async fn reject_workflow(
            &self,
            _workflow_id: &str,
            _reason: &str,
        ) -> warden_core::Result<()> {
            Ok(())
        }

        async fn approve_workflow(
            &self,
            _workflow_id: &str,
            _reason: &str,
        ) -> warden_core::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_escalation_manager_initial_escalation() {
        let policy_store = InMemoryEscalationPolicyStore::new();
        let workflow_client = MockWorkflowClient::new();

        let policy = EscalationPolicy::default();
        policy_store.create(policy.clone()).await.unwrap();

        workflow_client
            .add_workflow(PendingWorkflow {
                id: Uuid::new_v4().to_string(),
                transaction_id: "tx-1".into(),
                created_at: Utc::now(),
                escalation_policy_id: policy.name.clone(),
                escalation_stage: 0,
                approvers: vec![],
            })
            .await;

        let manager = EscalationManager::<_, _, warden_core::LoggingSender>::new(
            policy_store,
            workflow_client,
        );

        let results = manager.process_escalations().await.unwrap();
        assert_eq!(results.escalated.len(), 1);
    }

    #[test]
    fn test_bundle_manifest_sufficient_signatures() {
        let manifest = BundleManifest {
            version: "1.0.0".into(),
            created_at: Utc::now(),
            created_by: "admin@example.com".into(),
            previous_version: None,
            previous_root_hash: None,
            contents: BundleContents {
                policies: vec!["policies/main.yaml".into()],
                whitelists: vec![],
                blacklists: vec![],
            },
            merkle_root: "abc123".into(),
            signatures: vec![
                BundleSignature {
                    signer: "admin-key-1".into(),
                    algorithm: "ES256".into(),
                    signature: "sig1".into(),
                    signed_at: Utc::now(),
                },
                BundleSignature {
                    signer: "admin-key-2".into(),
                    algorithm: "ES256".into(),
                    signature: "sig2".into(),
                    signed_at: Utc::now(),
                },
            ],
            required_signatures: 2,
            valid_signers: vec![
                "admin-key-1".into(),
                "admin-key-2".into(),
                "admin-key-3".into(),
            ],
        };

        assert!(manifest.has_sufficient_signatures());

        let insufficient = BundleManifest {
            required_signatures: 3,
            ..manifest.clone()
        };
        assert!(!insufficient.has_sufficient_signatures());
    }

    #[test]
    fn test_audit_event_types_comprehensive() {
        let events = vec![
            AuditEventType::PolicyCreated {
                policy_id: "p1".into(),
                version: "1.0".into(),
            },
            AuditEventType::PolicyActivated {
                policy_id: "p1".into(),
                version: "1.0".into(),
            },
            AuditEventType::PolicyDeactivated {
                policy_id: "p1".into(),
            },
            AuditEventType::BundleLoaded {
                version: "1.0".into(),
                merkle_root: "abc".into(),
            },
            AuditEventType::TransactionSubmitted {
                transaction_id: "tx1".into(),
            },
            AuditEventType::PolicyEvaluated {
                transaction_id: "tx1".into(),
                decision: "allow".into(),
                matched_rule: Some("rule1".into()),
                evaluation_time_us: 100,
            },
            AuditEventType::ApprovalWorkflowStarted {
                transaction_id: "tx1".into(),
                workflow_id: "wf1".into(),
            },
            AuditEventType::ApprovalReceived {
                transaction_id: "tx1".into(),
                approver_id: "alice".into(),
                decision: "approve".into(),
            },
            AuditEventType::ApprovalWorkflowCompleted {
                transaction_id: "tx1".into(),
                outcome: "approved".into(),
            },
            AuditEventType::CallbackInvoked {
                transaction_id: "tx1".into(),
                handler_id: "chainalysis".into(),
            },
            AuditEventType::CallbackCompleted {
                transaction_id: "tx1".into(),
                handler_id: "chainalysis".into(),
                decision: "approve".into(),
                latency_ms: 150,
            },
            AuditEventType::SigningInitiated {
                transaction_id: "tx1".into(),
                session_id: "sess1".into(),
            },
            AuditEventType::SigningCompleted {
                transaction_id: "tx1".into(),
                txid: "btc_txid".into(),
            },
            AuditEventType::SigningFailed {
                transaction_id: "tx1".into(),
                error: "timeout".into(),
            },
            AuditEventType::SystemStarted {
                version: "1.0".into(),
            },
            AuditEventType::ConfigurationChanged {
                key: "max_amount".into(),
            },
            AuditEventType::EnclaveAttestationVerified { pcr0: "abc".into() },
            AuditEventType::EscalationTriggered {
                transaction_id: "tx1".into(),
                stage: 2,
            },
        ];

        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            assert!(!json.is_empty());
            let _parsed: AuditEventType = serde_json::from_str(&json).unwrap();
        }
    }
}
