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
