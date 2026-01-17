#![forbid(unsafe_code)]

pub mod approval;
pub mod audit;
pub mod backend;
pub mod bundle;
pub mod callback;
pub mod compliance;
pub mod config;
pub mod enclave;
pub mod entailment;
pub mod error;
pub mod escalation;
pub mod evaluator;
pub mod group;
pub mod heartbeat;
pub mod hierarchy;
pub mod lifecycle;
pub mod metrics;
pub mod notification;
pub mod pattern;
pub mod permit;
pub mod policy;
pub mod quorum;
pub mod retry;
pub mod risk;
pub mod secrets;
pub mod ssrf;
pub mod store;
pub mod task;
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
    BackendRegistry, HealthStatus, RetryingSigningBackend, SessionId, SessionStatus,
    SigningBackend, SigningPayload, SigningRequest, SigningSession, StubKeepBackend,
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
pub use retry::{ClassifyError, ErrorKind, RetryDecision, TieredRetryPolicy};
pub use risk::{RiskConfig, RiskEngine, RiskFactors, RiskLevel, RiskScore};
pub use store::{
    AddressEntry, AddressListStore, DbCipher, InMemoryAddressListStore, InMemoryPolicyStore,
    PolicyStore, RedbAddressListStore, RedbApprovalStore, RedbPolicyStore, RedbRevokedTokenStore,
    RedbStorage, RevokedToken, RevokedTokenStore,
};
pub use velocity::{
    InMemoryVelocityStore, VelocityCheck, VelocityLimits, VelocityStore, VelocityTracker,
    VelocityWindow, WindowType,
};
pub use workflow::{
    CompletionCallback, LoggingCallback, TimeoutChecker, WorkflowCompletionHandler,
};

pub use heartbeat::{
    HeartbeatChecker, HeartbeatConfig, HeartbeatDetails, HeartbeatTracker, WorkflowHeartbeat,
};

pub use audit::{
    ActorInfo, ActorType, AuditEvent, AuditEventType, AuditLog, AuditQuery, AuditSigner,
    AuditSignerConfig, AuditStore, ChainVerification, ComplianceExporter, DateRange, EventId,
    InMemoryAuditStore, ResourceInfo, Rfc3161Client, Rfc3161Token, SOC2AuditReport,
    Secp256k1AuditSigner, Signature as AuditSignature,
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
    RetryingComplianceProvider, ScreeningResult,
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
pub use lifecycle::{LifecycleComponent, ServiceLifecycle};
pub use permit::{
    ClosableOwnedPermit, ClosablePermitDealer, OwnedPermit, PermitDealer, QuotaError,
    SemaphoreSlotSupplier, SlotSupplier,
};
pub use secrets::{
    AwsSecretsManagerConfig, AwsSecretsManagerProvider, CompositeSecretsProvider,
    EnvSecretsProvider, SecretRef, SecretValue, SecretsError, SecretsProvider, VaultConfig,
    VaultSecretsProvider,
};
pub use ssrf::{SsrfError, SsrfPolicy};
pub use task::{CancellationToken, TaskHandle};

pub use metrics::{LabeledMetrics, MetricsRecorder, PolicyMetrics};

pub use hierarchy::{
    CycleError, EntityGraph, EntityId, EntityNode, HierarchyError, HierarchyValidator,
    RelationType, Role, RoleHierarchy, RoleId, TCNode, TransitiveClosure,
};

pub use entailment::{
    validate_policy_upgrade, Counterexample, EntailmentResult, NormalizedCondition,
    NormalizedHourRange, PolicyConflict, PolicyUpgradeValidation, RedundantRule, SemanticAction,
    SemanticPolicy, SemanticRule,
};
