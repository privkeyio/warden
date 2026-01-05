use std::sync::Arc;
use warden_core::{
    AddressListStore, ApprovalStore, BackendRegistry, EnclaveClient, GroupStore, PolicyEvaluator,
    PolicyStore, WorkflowStore,
};

use crate::auth::{AuthState, HasAuthState};

#[derive(Clone)]
pub struct AppState {
    pub policy_store: Arc<dyn PolicyStore>,
    pub whitelist_store: Arc<dyn AddressListStore>,
    pub blacklist_store: Arc<dyn AddressListStore>,
    pub approval_store: Arc<dyn ApprovalStore>,
    pub workflow_store: Arc<dyn WorkflowStore>,
    pub group_store: Arc<dyn GroupStore>,
    pub evaluator: Arc<PolicyEvaluator>,
    pub backend_registry: Arc<BackendRegistry>,
    pub enclave_client: Option<Arc<dyn EnclaveClient>>,
    pub auth_state: AuthState,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_store: Arc<dyn PolicyStore>,
        whitelist_store: Arc<dyn AddressListStore>,
        blacklist_store: Arc<dyn AddressListStore>,
        approval_store: Arc<dyn ApprovalStore>,
        workflow_store: Arc<dyn WorkflowStore>,
        group_store: Arc<dyn GroupStore>,
        backend_registry: Arc<BackendRegistry>,
        enclave_client: Option<Arc<dyn EnclaveClient>>,
        auth_state: AuthState,
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
            approval_store,
            workflow_store,
            group_store,
            evaluator,
            backend_registry,
            enclave_client,
            auth_state,
        }
    }
}

impl HasAuthState for AppState {
    fn auth_state(&self) -> &AuthState {
        &self.auth_state
    }
}
