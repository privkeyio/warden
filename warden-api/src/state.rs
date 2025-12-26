use std::sync::Arc;
use warden_core::{
    AddressListStore, ApprovalStore, BackendRegistry, InMemoryApprovalStore, PolicyEvaluator,
    PolicyStore,
};

#[derive(Clone)]
pub struct AppState {
    pub policy_store: Arc<dyn PolicyStore>,
    pub whitelist_store: Arc<dyn AddressListStore>,
    pub blacklist_store: Arc<dyn AddressListStore>,
    pub approval_store: Arc<dyn ApprovalStore>,
    pub evaluator: Arc<PolicyEvaluator>,
    pub backend_registry: Arc<BackendRegistry>,
}

impl AppState {
    pub fn new(
        policy_store: Arc<dyn PolicyStore>,
        whitelist_store: Arc<dyn AddressListStore>,
        blacklist_store: Arc<dyn AddressListStore>,
        backend_registry: Arc<BackendRegistry>,
    ) -> Self {
        let evaluator = Arc::new(PolicyEvaluator::new(
            Arc::clone(&policy_store),
            Arc::clone(&whitelist_store),
            Arc::clone(&blacklist_store),
        ));

        Self {
            policy_store,
            whitelist_store,
            blacklist_store,
            approval_store: Arc::new(InMemoryApprovalStore::new()),
            evaluator,
            backend_registry,
        }
    }
}
