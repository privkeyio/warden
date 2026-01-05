#![forbid(unsafe_code)]

pub mod approval;
pub mod audit;
pub mod backend;
pub mod bundle;
pub mod callback;
pub mod compliance;
pub mod config;
pub mod enclave;
pub mod error;
pub mod escalation;
pub mod evaluator;
pub mod group;
pub mod notification;
pub mod pattern;
pub mod policy;
pub mod quorum;
pub mod risk;
pub mod secrets;
pub mod store;
pub mod velocity;
pub mod workflow;

pub use approval::{
    Approval, ApprovalDecision, ApprovalRequest, ApprovalRequirements, ApprovalStage,
    ApprovalStatus, ApprovalStore, ApprovalWorkflow, CurrentStage, DegradationStage,
    InMemoryApprovalStore, InMemoryWorkflowStore, TransactionDetails, WorkflowStatus,
    WorkflowStore,
};
#[cfg(any(test, feature = "mock"))]
pub use backend::MockSigningBackend;
pub use backend::{
    BackendRegistry, HealthStatus, SessionId, SessionStatus, SigningBackend, SigningPayload,
    SigningRequest, SigningSession, StubKeepBackend,
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

pub use audit::{
    ActorInfo, ActorType, AuditEvent, AuditEventType, AuditLog, AuditQuery, AuditStore,
    ChainVerification, ComplianceExporter, DateRange, EventId, InMemoryAuditStore, ResourceInfo,
    SOC2AuditReport,
};
pub use bundle::{
    BundleContents, BundleLoader, BundleManifest, BundleProof, BundleSignature, BundleSigner,
    BundleStore, Hash, InMemoryBundleStore, LoadedBundle, MerkleLeaf, MerkleProof, MerkleTree,
    MockBundleSigner, ProofElement, SigningPayload as BundleSigningPayload,
};
pub use callback::{
    CallbackAction, CallbackConfig, CallbackDecision, CallbackError, CallbackGateway,
    CallbackHandlerConfig, CallbackRequest, CallbackResponse, CallbackResult, CallbackRuleConfig,
    PolicyContext, TransactionDetails as CallbackTransactionDetails,
};
pub use compliance::{
    AlertSeverity as ComplianceAlertSeverity, ChainalysisClient, ChainalysisConfig,
    ComplianceAlert, ComplianceCallbackHandler, ComplianceError, ComplianceProvider,
    EllipticClient, EllipticConfig, ExposureCategory, ExposureInfo, MockComplianceProvider,
    ScreeningResult,
};
#[cfg(any(test, feature = "mock"))]
pub use enclave::MockEnclaveClient;
pub use enclave::{
    BundleData, EnclaveClient, EnclaveConfig, EnclaveDecision, EnclaveProxy, EnclaveRequest,
    EnclaveResponse, ErrorCode as EnclaveErrorCode, EvaluationRequest,
    EvaluationResult as EnclaveEvaluationResult, ExpectedPcrs, PcrConfig,
    SessionStatus as EnclaveSessionStatus, SigningInitRequest,
    SigningSession as EnclaveSigningSession, VerifiedAttestation, ENCLAVE_CID, VSOCK_PORT,
};
pub use escalation::{
    AlertSeverity, EscalationAction, EscalationManager, EscalationOutcome, EscalationPolicy,
    EscalationPolicyStore, EscalationResults, EscalationStage, FinalAction,
    InMemoryEscalationPolicyStore, PendingWorkflow, WorkflowClient,
};
pub use secrets::{
    AwsSecretsManagerConfig, AwsSecretsManagerProvider, CompositeSecretsProvider,
    EnvSecretsProvider, SecretRef, SecretValue, SecretsError, SecretsProvider, VaultConfig,
    VaultSecretsProvider,
};
