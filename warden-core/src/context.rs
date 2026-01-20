#![forbid(unsafe_code)]

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

use crate::retry::TieredRetryPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRole {
    Admin,
    Approver,
    Viewer,
    Service,
}

impl ContextRole {
    pub fn is_admin(&self) -> bool {
        matches!(self, ContextRole::Admin)
    }
}

#[derive(Clone)]
pub struct RequestContext {
    user_id: String,
    role: ContextRole,
    audit_id: Uuid,
    trace_id: String,
}

impl std::fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContext")
            .field("user_id", &"<redacted>")
            .field("role", &self.role)
            .field("audit_id", &self.audit_id)
            .field("trace_id", &"<redacted>")
            .finish()
    }
}

impl RequestContext {
    pub fn new(user_id: impl Into<String>, role: ContextRole) -> Self {
        Self {
            user_id: user_id.into(),
            role,
            audit_id: Uuid::new_v4(),
            trace_id: Uuid::new_v4().to_string(),
        }
    }

    pub fn with_audit_id(mut self, audit_id: Uuid) -> Self {
        self.audit_id = audit_id;
        self
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = trace_id.into();
        self
    }

    pub fn service(service_name: impl Into<String>) -> Self {
        Self::new(service_name, ContextRole::Service)
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn role(&self) -> ContextRole {
        self.role
    }

    pub fn audit_id(&self) -> Uuid {
        self.audit_id
    }

    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }
}

#[derive(Debug, Clone)]
pub struct RetryOverride {
    pub policy: TieredRetryPolicy,
}

impl RetryOverride {
    pub fn new(policy: TieredRetryPolicy) -> Self {
        Self { policy }
    }
}

#[derive(Debug, Clone)]
pub struct TimeoutOverride {
    pub timeout: Duration,
}

impl TimeoutOverride {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn from_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    pub fn from_millis(millis: u64) -> Self {
        Self::new(Duration::from_millis(millis))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassError {
    AdminRequired,
}

impl std::fmt::Display for BypassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BypassError::AdminRequired => {
                write!(f, "bypass flags require admin role")
            }
        }
    }
}

impl std::error::Error for BypassError {}

#[derive(Debug, Clone, Default)]
pub struct BypassFlags {
    skip_rate_limit: bool,
    skip_audit: bool,
    skip_compliance: bool,
    admin_override: bool,
}

impl BypassFlags {
    pub fn none() -> Self {
        Self::default()
    }

    fn require_admin(ctx: &RequestContext) -> Result<(), BypassError> {
        if ctx.role().is_admin() {
            Ok(())
        } else {
            Err(BypassError::AdminRequired)
        }
    }

    pub fn for_admin(ctx: &RequestContext) -> Result<Self, BypassError> {
        Self::require_admin(ctx)?;
        Ok(Self {
            admin_override: true,
            ..Default::default()
        })
    }

    pub fn with_skip_rate_limit(mut self, ctx: &RequestContext) -> Result<Self, BypassError> {
        Self::require_admin(ctx)?;
        self.skip_rate_limit = true;
        Ok(self)
    }

    pub fn with_skip_audit(mut self, ctx: &RequestContext) -> Result<Self, BypassError> {
        Self::require_admin(ctx)?;
        self.skip_audit = true;
        Ok(self)
    }

    pub fn with_skip_compliance(mut self, ctx: &RequestContext) -> Result<Self, BypassError> {
        Self::require_admin(ctx)?;
        self.skip_compliance = true;
        Ok(self)
    }

    pub fn skip_rate_limit(&self) -> bool {
        self.skip_rate_limit
    }

    pub fn skip_audit(&self) -> bool {
        self.skip_audit
    }

    pub fn skip_compliance(&self) -> bool {
        self.skip_compliance
    }

    pub fn admin_override(&self) -> bool {
        self.admin_override
    }

    pub fn has_any(&self) -> bool {
        self.skip_rate_limit || self.skip_audit || self.skip_compliance || self.admin_override
    }
}

#[derive(Default)]
pub struct RequestExtensions {
    inner: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl RequestExtensions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) -> Option<T> {
        let old = self.inner.insert(TypeId::of::<T>(), Box::new(value))?;
        old.downcast().ok().map(|b| *b)
    }

    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.inner
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref())
    }

    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.inner
            .get_mut(&TypeId::of::<T>())
            .and_then(|b| b.downcast_mut())
    }

    pub fn remove<T: 'static>(&mut self) -> Option<T> {
        let boxed = self.inner.remove(&TypeId::of::<T>())?;
        boxed.downcast().ok().map(|b| *b)
    }

    pub fn contains<T: 'static>(&self) -> bool {
        self.inner.contains_key(&TypeId::of::<T>())
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn context(&self) -> Option<&RequestContext> {
        self.get::<RequestContext>()
    }

    pub fn retry_override(&self) -> Option<&RetryOverride> {
        self.get::<RetryOverride>()
    }

    pub fn timeout_override(&self) -> Option<&TimeoutOverride> {
        self.get::<TimeoutOverride>()
    }

    pub fn bypass_flags(&self) -> Option<&BypassFlags> {
        self.get::<BypassFlags>()
    }
}

impl std::fmt::Debug for RequestExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestExtensions")
            .field("len", &self.inner.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::RetryPolicy;

    #[test]
    fn test_request_context_new() {
        let ctx = RequestContext::new("user123", ContextRole::Admin);
        assert_eq!(ctx.user_id(), "user123");
        assert_eq!(ctx.role(), ContextRole::Admin);
        assert!(!ctx.trace_id().is_empty());
    }

    #[test]
    fn test_request_context_builder() {
        let audit_id = Uuid::new_v4();
        let ctx = RequestContext::new("user123", ContextRole::Approver)
            .with_audit_id(audit_id)
            .with_trace_id("trace-abc");
        assert_eq!(ctx.audit_id(), audit_id);
        assert_eq!(ctx.trace_id(), "trace-abc");
    }

    #[test]
    fn test_service_context() {
        let ctx = RequestContext::service("batch-processor");
        assert_eq!(ctx.user_id(), "batch-processor");
        assert_eq!(ctx.role(), ContextRole::Service);
    }

    #[test]
    fn test_extensions_insert_get() {
        let mut ext = RequestExtensions::new();
        let ctx = RequestContext::new("user", ContextRole::Viewer);
        ext.insert(ctx);

        let retrieved = ext.get::<RequestContext>().unwrap();
        assert_eq!(retrieved.user_id(), "user");
    }

    #[test]
    fn test_extensions_replace() {
        let mut ext = RequestExtensions::new();
        ext.insert(TimeoutOverride::from_secs(10));
        let old = ext.insert(TimeoutOverride::from_secs(20));

        assert!(old.is_some());
        assert_eq!(old.unwrap().timeout, Duration::from_secs(10));
        assert_eq!(
            ext.get::<TimeoutOverride>().unwrap().timeout,
            Duration::from_secs(20)
        );
    }

    #[test]
    fn test_extensions_remove() {
        let mut ext = RequestExtensions::new();
        let admin_ctx = RequestContext::new("admin", ContextRole::Admin);
        ext.insert(BypassFlags::for_admin(&admin_ctx).unwrap());

        assert!(ext.contains::<BypassFlags>());
        let removed = ext.remove::<BypassFlags>();
        assert!(removed.is_some());
        assert!(!ext.contains::<BypassFlags>());
    }

    #[test]
    fn test_extensions_convenience_methods() {
        let mut ext = RequestExtensions::new();
        ext.insert(RequestContext::new("user", ContextRole::Admin));
        ext.insert(TimeoutOverride::from_secs(30));
        ext.insert(BypassFlags::none());
        ext.insert(RetryOverride::new(TieredRetryPolicy::default()));

        assert!(ext.context().is_some());
        assert!(ext.timeout_override().is_some());
        assert!(ext.bypass_flags().is_some());
        assert!(ext.retry_override().is_some());
    }

    #[test]
    fn test_bypass_flags_builder_admin() {
        let admin_ctx = RequestContext::new("admin", ContextRole::Admin);
        let flags = BypassFlags::none()
            .with_skip_rate_limit(&admin_ctx)
            .unwrap()
            .with_skip_audit(&admin_ctx)
            .unwrap();
        assert!(flags.skip_rate_limit());
        assert!(flags.skip_audit());
        assert!(!flags.skip_compliance());
        assert!(!flags.admin_override());
    }

    #[test]
    fn test_bypass_flags_requires_admin() {
        let viewer_ctx = RequestContext::new("viewer", ContextRole::Viewer);
        assert!(BypassFlags::for_admin(&viewer_ctx).is_err());
        assert!(BypassFlags::none()
            .with_skip_rate_limit(&viewer_ctx)
            .is_err());
        assert!(BypassFlags::none().with_skip_audit(&viewer_ctx).is_err());
        assert!(BypassFlags::none()
            .with_skip_compliance(&viewer_ctx)
            .is_err());
    }

    #[test]
    fn test_bypass_flags_for_admin() {
        let admin_ctx = RequestContext::new("admin", ContextRole::Admin);
        let flags = BypassFlags::for_admin(&admin_ctx).unwrap();
        assert!(flags.admin_override());
        assert!(!flags.skip_rate_limit());
        assert!(!flags.skip_audit());
        assert!(!flags.skip_compliance());
        assert!(flags.has_any());
    }

    #[test]
    fn test_retry_override() {
        let policy = TieredRetryPolicy::default().with_standard(RetryPolicy::aggressive());
        let override_ = RetryOverride::new(policy);
        assert_eq!(override_.policy.standard.maximum_attempts, 5);
    }

    #[test]
    fn test_extensions_clear() {
        let mut ext = RequestExtensions::new();
        ext.insert(RequestContext::new("user", ContextRole::Admin));
        ext.insert(TimeoutOverride::from_secs(30));
        assert_eq!(ext.len(), 2);

        ext.clear();
        assert!(ext.is_empty());
    }

    #[test]
    fn test_debug_redacts_pii() {
        let ctx = RequestContext::new("sensitive-user-id", ContextRole::Admin)
            .with_trace_id("sensitive-trace-id");
        let debug_output = format!("{:?}", ctx);
        assert!(
            !debug_output.contains("sensitive-user-id"),
            "Debug output should not contain user_id: {}",
            debug_output
        );
        assert!(
            !debug_output.contains("sensitive-trace-id"),
            "Debug output should not contain trace_id: {}",
            debug_output
        );
        assert!(
            debug_output.contains("<redacted>"),
            "Debug output should contain <redacted>: {}",
            debug_output
        );
    }

    #[test]
    fn test_context_role_is_admin() {
        assert!(ContextRole::Admin.is_admin());
        assert!(!ContextRole::Approver.is_admin());
        assert!(!ContextRole::Viewer.is_admin());
        assert!(!ContextRole::Service.is_admin());
    }
}
