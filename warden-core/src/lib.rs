#![forbid(unsafe_code)]

pub mod approval;
pub mod backend;
pub mod config;
pub mod error;
pub mod evaluator;
pub mod pattern;
pub mod policy;
pub mod risk;
pub mod store;
pub mod velocity;

pub use approval::{
    Approval, ApprovalDecision, ApprovalRequest, ApprovalRequirements, ApprovalStage,
    ApprovalStatus, ApprovalStore, CurrentStage, DegradationStage, InMemoryApprovalStore,
};
pub use backend::{
    BackendRegistry, HealthStatus, MockSigningBackend, SessionId, SessionStatus, SigningBackend,
    SigningPayload, SigningRequest, SigningSession, StubKeepBackend,
};
pub use config::Config;
pub use error::{Error, Result};
pub use evaluator::{
    EvaluationContext, EvaluationResult, PolicyDecisionSerde, PolicyEvaluator, RuleTraceEntry,
    TransactionRequest,
};
pub use pattern::{matches_pattern, validate_name};
pub use policy::{
    Action, AmountCondition, ApprovalConfig, Conditions, DestinationCondition, Policy,
    PolicyDecision, Rule, TimeCondition,
};
pub use risk::{RiskConfig, RiskEngine, RiskFactors, RiskLevel, RiskScore};
pub use store::{
    AddressEntry, AddressListStore, InMemoryAddressListStore, InMemoryPolicyStore, PolicyStore,
    RedbAddressListStore, RedbPolicyStore, RedbStorage,
};
pub use velocity::{
    InMemoryVelocityStore, VelocityCheck, VelocityLimits, VelocityStore, VelocityTracker,
    VelocityWindow, WindowType,
};
