#![forbid(unsafe_code)]

pub mod approval;
pub mod backend;
pub mod config;
pub mod error;
pub mod evaluator;
pub mod group;
pub mod notification;
pub mod pattern;
pub mod policy;
pub mod quorum;
pub mod risk;
pub mod store;
pub mod velocity;
pub mod workflow;

pub use approval::{
    Approval, ApprovalDecision, ApprovalRequest, ApprovalRequirements, ApprovalStage,
    ApprovalStatus, ApprovalStore, ApprovalWorkflow, CurrentStage, DegradationStage,
    InMemoryApprovalStore, InMemoryWorkflowStore, TransactionDetails, WorkflowStatus,
    WorkflowStore,
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
pub use group::{
    Approver, ApproverGroup, GroupMember, GroupStore, InMemoryGroupStore, NotificationChannel,
};
pub use notification::{
    ApprovalProgressNotification, ApprovalRequestNotification, ApprovalSummary, EmailConfig,
    EmailSender, InMemoryNotificationStore, LoggingSender, NostrConfig, NostrSender, Notification,
    NotificationError, NotificationRecord, NotificationSender, NotificationService,
    NotificationStatus, NotificationStore, RetryPolicy, SlackConfig, SlackSender,
    TimeoutNotification, WebhookSender, WorkflowCompleteNotification,
};
pub use pattern::{matches_pattern, validate_approver_id, validate_name};
pub use policy::{
    Action, AmountCondition, ApprovalConfig, Conditions, DestinationCondition, Policy,
    PolicyDecision, Rule, TimeCondition,
};
pub use quorum::{
    GroupId, PendingGroupInfo, QuorumEvaluator, QuorumStatus, QuorumValidationError,
    RequirementNode,
};
pub use risk::{RiskConfig, RiskEngine, RiskFactors, RiskLevel, RiskScore};
pub use store::{
    AddressEntry, AddressListStore, InMemoryAddressListStore, InMemoryPolicyStore, PolicyStore,
    RedbAddressListStore, RedbApprovalStore, RedbPolicyStore, RedbStorage,
};
pub use velocity::{
    InMemoryVelocityStore, VelocityCheck, VelocityLimits, VelocityStore, VelocityTracker,
    VelocityWindow, WindowType,
};
pub use workflow::{
    CompletionCallback, LoggingCallback, TimeoutChecker, WorkflowCompletionHandler,
};
