use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Serialize)]
struct AuthErrorResponse {
    error: String,
    code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Approver,
    Viewer,
}

impl Role {
    pub fn can_access(&self, required: Role) -> bool {
        match required {
            Role::Viewer => true,
            Role::Approver => matches!(self, Role::Admin | Role::Approver),
            Role::Admin => matches!(self, Role::Admin),
        }
    }
}

pub const DEFAULT_ISSUER: &str = "warden";
pub const DEFAULT_AUDIENCE: &str = "warden-api";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub jti: String,
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub role: Role,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
}

impl Claims {
    pub fn new(subject: String, role: Role, expires_in: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            jti: Uuid::new_v4().to_string(),
            sub: subject,
            iss: DEFAULT_ISSUER.to_string(),
            aud: DEFAULT_AUDIENCE.to_string(),
            role,
            iat: now,
            nbf: now,
            exp: now + expires_in.as_secs(),
        }
    }

    pub fn with_audience(mut self, audience: &str) -> Self {
        self.aud = audience.to_string();
        self
    }
}

#[derive(Clone)]
pub struct JwtConfig {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtConfig {
    pub fn new(secret: &[u8]) -> Self {
        Self::with_audience(secret, DEFAULT_AUDIENCE)
    }

    pub fn with_audience(secret: &[u8], audience: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[DEFAULT_ISSUER]);
        validation.set_audience(&[audience]);
        validation.leeway = 30;
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            validation,
        }
    }

    pub fn encode(&self, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&Header::new(Algorithm::HS256), claims, &self.encoding_key)
    }

    pub fn decode(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        decode::<Claims>(token, &self.decoding_key, &self.validation).map(|data| data.claims)
    }
}

pub struct TokenBlacklist {
    entries: RwLock<HashMap<String, u64>>,
    store: Option<Arc<dyn warden_core::RevokedTokenStore>>,
}

impl Default for TokenBlacklist {
    fn default() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            store: None,
        }
    }
}

impl TokenBlacklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_store(store: Arc<dyn warden_core::RevokedTokenStore>) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            store: Some(store),
        }
    }

    pub async fn load_from_store(&self) -> Result<usize, String> {
        let store = match &self.store {
            Some(s) => s,
            None => return Ok(0),
        };

        let tokens = store
            .list_valid()
            .await
            .map_err(|e| format!("failed to load revoked tokens: {}", e))?;

        let mut entries = self.entries.write();
        let count = tokens.len();
        for token in tokens {
            entries.insert(token.jti, token.exp);
        }
        Ok(count)
    }

    pub fn revoke(&self, jti: String, exp: u64) {
        self.entries.write().insert(jti.clone(), exp);

        if let Some(store) = &self.store {
            let store = Arc::clone(store);
            tokio::spawn(async move {
                if let Err(e) = store.revoke(&jti, exp).await {
                    tracing::error!(jti = %jti, error = %e, "failed to persist token revocation");
                }
            });
        }
    }

    pub fn is_revoked(&self, jti: &str) -> bool {
        self.entries.read().contains_key(jti)
    }

    pub fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.entries.write().retain(|_, exp| *exp > now);

        if let Some(store) = &self.store {
            let store = Arc::clone(store);
            tokio::spawn(async move {
                if let Err(e) = store.cleanup_expired().await {
                    tracing::error!(error = %e, "failed to cleanup expired tokens from store");
                }
            });
        }
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Spawns a background task that periodically syncs revoked tokens from the
    /// persistent store. This ensures revocations from other nodes are visible
    /// to this instance.
    ///
    /// Returns a `JoinHandle` that can be used to abort the task on shutdown.
    pub fn start_sync_task(self: &Arc<Self>, interval: Duration) -> Option<tokio::task::JoinHandle<()>> {
        let store = self.store.as_ref()?;
        let store = Arc::clone(store);
        let blacklist = Arc::clone(self);

        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                match store.list_valid().await {
                    Ok(tokens) => {
                        let mut entries = blacklist.entries.write();
                        let mut added = 0usize;
                        for token in tokens {
                            if entries.insert(token.jti, token.exp).is_none() {
                                added += 1;
                            }
                        }
                        if added > 0 {
                            tracing::debug!(added, "Synced new revoked tokens from store");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to sync revoked tokens from store");
                    }
                }
            }
        }))
    }
}

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    ExpiredToken,
    ReplayedToken,
    RevokedToken,
    InsufficientPermissions,
    RateLimited,
    InternalError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "MISSING_TOKEN",
                "Authorization header required",
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "INVALID_TOKEN",
                "Invalid or malformed token",
            ),
            AuthError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                "EXPIRED_TOKEN",
                "Token has expired",
            ),
            AuthError::ReplayedToken => (
                StatusCode::UNAUTHORIZED,
                "REPLAYED_TOKEN",
                "Token has already been used",
            ),
            AuthError::RevokedToken => (
                StatusCode::UNAUTHORIZED,
                "REVOKED_TOKEN",
                "Token has been revoked",
            ),
            AuthError::InsufficientPermissions => (
                StatusCode::FORBIDDEN,
                "INSUFFICIENT_PERMISSIONS",
                "Insufficient permissions for this action",
            ),
            AuthError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "Too many requests",
            ),
            AuthError::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal server error",
            ),
        };
        (
            status,
            Json(AuthErrorResponse {
                error: message.to_string(),
                code: code.to_string(),
            }),
        )
            .into_response()
    }
}

pub struct AuthenticatedUser {
    pub subject: String,
    pub role: Role,
}

pub trait HasAuthState {
    fn auth_state(&self) -> &AuthState;
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: HasAuthState + Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = state.auth_state();

        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingToken)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        let claims = auth_state
            .jwt_config
            .decode(token)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                _ => AuthError::InvalidToken,
            })?;

        if auth_state.is_token_revoked(&claims.jti) {
            return Err(AuthError::RevokedToken);
        }

        auth_state.validate_jti(&claims.jti, claims.exp)?;

        Ok(AuthenticatedUser {
            subject: claims.sub,
            role: claims.role,
        })
    }
}

pub struct AdminUser {
    pub subject: String,
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: HasAuthState + Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if !user.role.can_access(Role::Admin) {
            return Err(AuthError::InsufficientPermissions);
        }
        Ok(AdminUser {
            subject: user.subject,
        })
    }
}

pub struct ApproverUser {
    pub subject: String,
}

impl<S> FromRequestParts<S> for ApproverUser
where
    S: HasAuthState + Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if !user.role.can_access(Role::Approver) {
            return Err(AuthError::InsufficientPermissions);
        }
        Ok(ApproverUser {
            subject: user.subject,
        })
    }
}

pub struct ViewerUser {
    pub subject: String,
}

impl<S> FromRequestParts<S> for ViewerUser
where
    S: HasAuthState + Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if !user.role.can_access(Role::Viewer) {
            return Err(AuthError::InsufficientPermissions);
        }
        Ok(ViewerUser {
            subject: user.subject,
        })
    }
}

pub struct JtiCache {
    entries: RwLock<HashMap<String, u64>>,
    max_entries: usize,
}

impl JtiCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn check_and_insert(&self, jti: &str, exp: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut entries = self.entries.write();

        if entries.len() > self.max_entries / 2 {
            entries.retain(|_, &mut exp_time| exp_time > now);
        }

        if entries.contains_key(jti) {
            return false;
        }

        if entries.len() >= self.max_entries {
            return false;
        }

        entries.insert(jti.to_string(), exp);
        true
    }

    pub fn contains(&self, jti: &str) -> bool {
        self.entries.read().contains_key(jti)
    }
}

impl Clone for JtiCache {
    fn clone(&self) -> Self {
        let entries = self.entries.read().clone();
        Self {
            entries: RwLock::new(entries),
            max_entries: self.max_entries,
        }
    }
}

#[derive(Clone)]
pub struct AuthState {
    pub jwt_config: Arc<JwtConfig>,
    pub rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    pub jti_cache: Arc<JtiCache>,
    pub token_blacklist: Arc<TokenBlacklist>,
}

impl AuthState {
    pub fn new(jwt_secret: &[u8], requests_per_second: u32) -> Self {
        Self::build(
            Arc::new(JwtConfig::new(jwt_secret)),
            requests_per_second,
            TokenBlacklist::new(),
        )
    }

    pub fn with_persistent_blacklist(
        jwt_secret: &[u8],
        requests_per_second: u32,
        store: Arc<dyn warden_core::RevokedTokenStore>,
    ) -> Self {
        Self::build(
            Arc::new(JwtConfig::new(jwt_secret)),
            requests_per_second,
            TokenBlacklist::with_store(store),
        )
    }

    pub fn with_config(jwt_config: Arc<JwtConfig>, requests_per_second: u32) -> Self {
        Self::build(jwt_config, requests_per_second, TokenBlacklist::new())
    }

    fn build(
        jwt_config: Arc<JwtConfig>,
        requests_per_second: u32,
        blacklist: TokenBlacklist,
    ) -> Self {
        let rps = NonZeroU32::new(requests_per_second.max(1)).expect("max(1) guarantees non-zero");
        let quota = Quota::per_second(rps);
        Self {
            jwt_config,
            rate_limiter: Arc::new(RateLimiter::direct(quota)),
            jti_cache: Arc::new(JtiCache::new(10000)),
            token_blacklist: Arc::new(blacklist),
        }
    }

    pub async fn load_blacklist(&self) -> Result<usize, String> {
        self.token_blacklist.load_from_store().await
    }

    /// Starts a background task that periodically syncs revoked tokens from the
    /// persistent store. This ensures revocations from other nodes are visible.
    ///
    /// Returns a `JoinHandle` if a persistent store is configured, `None` otherwise.
    pub fn start_blacklist_sync(&self, interval: Duration) -> Option<tokio::task::JoinHandle<()>> {
        self.token_blacklist.start_sync_task(interval)
    }

    pub fn check_rate_limit(&self) -> Result<(), AuthError> {
        self.rate_limiter
            .check()
            .map_err(|_| AuthError::RateLimited)
    }

    pub fn validate_jti(&self, jti: &str, exp: u64) -> Result<(), AuthError> {
        if !self.jti_cache.check_and_insert(jti, exp) {
            return Err(AuthError::ReplayedToken);
        }
        Ok(())
    }

    pub fn revoke_token(&self, jti: String, exp: u64) {
        self.token_blacklist.revoke(jti, exp);
    }

    pub fn is_token_revoked(&self, jti: &str) -> bool {
        self.token_blacklist.is_revoked(jti)
    }

    pub fn cleanup_blacklist(&self) {
        self.token_blacklist.cleanup_expired();
    }

    pub fn generate_token(
        &self,
        subject: String,
        role: Role,
        expires_in: Duration,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = Claims::new(subject, role, expires_in);
        self.jwt_config.encode(&claims)
    }
}

pub async fn rate_limit_middleware<S: HasAuthState>(
    axum::extract::State(state): axum::extract::State<S>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<Response, AuthError> {
    state.auth_state().check_rate_limit()?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_hierarchy() {
        assert!(Role::Admin.can_access(Role::Admin));
        assert!(Role::Admin.can_access(Role::Approver));
        assert!(Role::Admin.can_access(Role::Viewer));

        assert!(!Role::Approver.can_access(Role::Admin));
        assert!(Role::Approver.can_access(Role::Approver));
        assert!(Role::Approver.can_access(Role::Viewer));

        assert!(!Role::Viewer.can_access(Role::Admin));
        assert!(!Role::Viewer.can_access(Role::Approver));
        assert!(Role::Viewer.can_access(Role::Viewer));
    }

    #[test]
    fn test_jwt_encode_decode() {
        let config = JwtConfig::new(b"test-secret-key-32-bytes-long!!");
        let claims = Claims::new(
            "user123".to_string(),
            Role::Admin,
            Duration::from_secs(3600),
        );
        let token = config.encode(&claims).unwrap();
        let decoded = config.decode(&token).unwrap();
        assert_eq!(decoded.sub, "user123");
        assert_eq!(decoded.role, Role::Admin);
        assert_eq!(decoded.iss, DEFAULT_ISSUER);
        assert_eq!(decoded.aud, DEFAULT_AUDIENCE);
        assert!(!decoded.jti.is_empty());
        assert!(decoded.nbf <= decoded.exp);
    }

    #[test]
    fn test_jwt_unique_jti() {
        let claims1 = Claims::new("user1".to_string(), Role::Admin, Duration::from_secs(3600));
        let claims2 = Claims::new("user1".to_string(), Role::Admin, Duration::from_secs(3600));
        assert_ne!(claims1.jti, claims2.jti);
    }

    #[test]
    fn test_jti_cache_replay_prevention() {
        let cache = JtiCache::new(100);
        let jti = "test-jti-12345";
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        assert!(cache.check_and_insert(jti, exp));
        assert!(!cache.check_and_insert(jti, exp));
        assert!(cache.contains(jti));
    }

    #[test]
    fn test_auth_state_jti_validation() {
        let state = AuthState::new(b"test-secret-32-chars-minimum!!!", 10);
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        assert!(state.validate_jti("unique-jti-1", exp).is_ok());
        assert!(matches!(
            state.validate_jti("unique-jti-1", exp),
            Err(AuthError::ReplayedToken)
        ));
    }

    #[test]
    fn test_auth_state_zero_rate_limit_does_not_panic() {
        let _state = AuthState::new(b"test-secret-32-chars-minimum!!!", 0);
    }

    #[test]
    fn test_token_blacklist_revoke_and_check() {
        let blacklist = TokenBlacklist::new();
        let jti = "test-jti-123";
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        assert!(!blacklist.is_revoked(jti));
        blacklist.revoke(jti.to_string(), exp);
        assert!(blacklist.is_revoked(jti));
    }

    #[test]
    fn test_token_blacklist_cleanup_expired() {
        let blacklist = TokenBlacklist::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        blacklist.revoke("expired".to_string(), now - 100);
        blacklist.revoke("valid".to_string(), now + 3600);

        assert_eq!(blacklist.len(), 2);
        blacklist.cleanup_expired();
        assert_eq!(blacklist.len(), 1);
        assert!(!blacklist.is_revoked("expired"));
        assert!(blacklist.is_revoked("valid"));
    }

    #[test]
    fn test_auth_state_revoke_token() {
        let state = AuthState::new(b"test-secret-32-chars-minimum!!!", 100);
        let token = state
            .generate_token("user".to_string(), Role::Admin, Duration::from_secs(3600))
            .unwrap();
        let claims = state.jwt_config.decode(&token).unwrap();

        assert!(!state.is_token_revoked(&claims.jti));
        state.revoke_token(claims.jti.clone(), claims.exp);
        assert!(state.is_token_revoked(&claims.jti));
    }
}
