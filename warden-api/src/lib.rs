#![forbid(unsafe_code)]

pub mod auth;
mod handlers;
mod routes;
mod state;

pub use auth::{AuthState, AuthorizedUser, Role, ROLE_ADMIN, ROLE_APPROVER, ROLE_VIEWER};
pub use routes::create_router;
pub use state::AppState;
