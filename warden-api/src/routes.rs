use axum::{
    http::{header, HeaderValue, Method},
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use crate::auth::rate_limit_middleware;
use crate::handlers;
use crate::state::AppState;

const MAX_BODY_SIZE: usize = 1024 * 1024;

fn cors_allowed_origins() -> AllowOrigin {
    match std::env::var("CORS_ALLOWED_ORIGINS") {
        Ok(origins) if origins.trim() == "*" => {
            tracing::warn!(
                "CORS configured to allow any origin (CORS_ALLOWED_ORIGINS=*). \
                 This should only be used in development."
            );
            AllowOrigin::any()
        }
        Ok(origins) if !origins.is_empty() => {
            let origins: Vec<HeaderValue> = origins
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if origins.is_empty() {
                tracing::warn!("CORS_ALLOWED_ORIGINS set but no valid origins parsed, denying all");
                AllowOrigin::list([])
            } else {
                tracing::info!("CORS configured with {} allowed origins", origins.len());
                AllowOrigin::list(origins)
            }
        }
        _ => {
            tracing::warn!(
                "CORS_ALLOWED_ORIGINS not set, CORS requests will be denied. \
                 Set CORS_ALLOWED_ORIGINS=* for development or specify allowed origins."
            );
            AllowOrigin::list([])
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
        .allow_origin(cors_allowed_origins());

    let api_router = Router::new()
        .nest("/v1", api_v1())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware::<AppState>,
        ));

    Router::new()
        .route("/health", get(handlers::health_check))
        .merge(api_router)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn api_v1() -> Router<AppState> {
    Router::new()
        .nest("/policies", policy_routes())
        .nest("/transactions", transaction_routes())
        .nest("/approvals", approval_routes())
        .nest("/workflows", workflow_routes())
        .nest("/groups", group_routes())
        .nest("/whitelists", whitelist_routes())
        .nest("/blacklists", blacklist_routes())
}

fn policy_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::list_policies))
        .route("/", post(handlers::create_policy))
        .route("/evaluate", post(handlers::evaluate_policy))
        .route("/{id}", get(handlers::get_policy))
        .route("/{id}", put(handlers::update_policy))
        .route("/{id}", delete(handlers::delete_policy))
        .route("/{id}/activate", post(handlers::activate_policy))
        .route("/{id}/deactivate", post(handlers::deactivate_policy))
}

fn transaction_routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", post(handlers::authorize_transaction))
        .route(
            "/{id}/approval-status",
            get(handlers::get_transaction_approval_status),
        )
        .route("/{id}/approve", post(handlers::approve_transaction))
        .route("/{id}/reject", post(handlers::reject_transaction))
}

fn approval_routes() -> Router<AppState> {
    Router::new().route("/pending", get(handlers::list_pending_approvals))
}

fn workflow_routes() -> Router<AppState> {
    Router::new()
        .route("/{id}", get(handlers::get_workflow_status))
        .route("/{id}/approve", post(handlers::submit_approval))
        .route("/{id}/reject", post(handlers::submit_rejection))
        .route("/{id}/cancel", post(handlers::cancel_workflow))
}

fn group_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::list_groups))
        .route("/", post(handlers::create_group))
        .route("/{id}", get(handlers::get_group))
        .route("/{id}/members", post(handlers::add_group_member))
        .route(
            "/{id}/members/{approver_id}",
            delete(handlers::remove_group_member),
        )
}

fn whitelist_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::list_whitelists))
        .route("/", post(handlers::create_whitelist))
        .route("/{name}", get(handlers::get_whitelist))
        .route("/{name}/addresses", post(handlers::add_whitelist_address))
        .route(
            "/{name}/addresses/{address}",
            delete(handlers::remove_whitelist_address),
        )
}

fn blacklist_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::list_blacklists))
        .route("/", post(handlers::create_blacklist))
        .route("/{name}", get(handlers::get_blacklist))
        .route("/{name}/addresses", post(handlers::add_blacklist_address))
        .route(
            "/{name}/addresses/{address}",
            delete(handlers::remove_blacklist_address),
        )
}
