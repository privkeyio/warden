use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub backends: Vec<BackendHealth>,
}

#[derive(Serialize)]
pub struct BackendHealth {
    pub id: String,
    pub status: warden_core::HealthStatus,
}

pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let mut backends = Vec::new();

    for id in state.backend_registry.list() {
        if let Some(backend) = state.backend_registry.get(&id) {
            let status =
                backend
                    .health_check()
                    .await
                    .unwrap_or(warden_core::HealthStatus::Unavailable {
                        reason: "Health check failed".into(),
                    });
            backends.push(BackendHealth { id, status });
        }
    }

    let (status_code, overall) = if backends
        .iter()
        .all(|b| matches!(b.status, warden_core::HealthStatus::Healthy))
    {
        (StatusCode::OK, "healthy")
    } else if backends
        .iter()
        .any(|b| matches!(b.status, warden_core::HealthStatus::Healthy))
    {
        (StatusCode::OK, "degraded")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unhealthy")
    };

    (
        status_code,
        Json(HealthResponse {
            status: overall.into(),
            backends,
        }),
    )
}
