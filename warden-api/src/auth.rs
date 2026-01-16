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
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: Role,
    pub exp: u64,
    pub iat: u64,
}

impl Claims {
    pub fn new(subject: String, role: Role, expires_in: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            sub: subject,
            role,
            iat: now,
            exp: now + expires_in.as_secs(),
        }
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
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
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

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    ExpiredToken,
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

#[derive(Clone)]
pub struct AuthState {
    pub jwt_config: Arc<JwtConfig>,
    pub rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl AuthState {
    pub fn new(jwt_secret: &[u8], requests_per_second: u32) -> Self {
        let jwt_config = Arc::new(JwtConfig::new(jwt_secret));
        // Ensure rate limit is at least 1 to prevent panic
        let rps = NonZeroU32::new(requests_per_second.max(1)).expect("max(1) guarantees non-zero");
        let quota = Quota::per_second(rps);
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        Self {
            jwt_config,
            rate_limiter,
        }
    }

    pub fn with_config(jwt_config: Arc<JwtConfig>, requests_per_second: u32) -> Self {
        // Ensure rate limit is at least 1 to prevent panic
        let rps = NonZeroU32::new(requests_per_second.max(1)).expect("max(1) guarantees non-zero");
        let quota = Quota::per_second(rps);
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        Self {
            jwt_config,
            rate_limiter,
        }
    }

    pub fn check_rate_limit(&self) -> Result<(), AuthError> {
        self.rate_limiter
            .check()
            .map_err(|_| AuthError::RateLimited)
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
    }

    #[test]
    fn test_auth_state_zero_rate_limit_does_not_panic() {
        // Should not panic with zero rate limit (uses max(1))
        let _state = AuthState::new(b"test-secret-32-chars-minimum!!!", 0);
    }
}
