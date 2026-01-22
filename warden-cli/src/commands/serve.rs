use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use warden_core::{EnclaveClient, EnclaveConfig, EnclaveProxy, PcrConfig, TimeoutChecker};

use crate::Stores;

#[allow(clippy::too_many_arguments)]
pub async fn handle_serve_command(
    config: &warden_core::Config,
    stores: &Stores,
    host: String,
    port: u16,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    require_tls: bool,
    enable_enclave: bool,
    require_attestation: bool,
    pcr0: Option<String>,
    pcr1: Option<String>,
    pcr2: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_trimmed = host.trim();
    let is_localhost = matches!(host_trimmed, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    let has_tls = tls_cert.is_some() && tls_key.is_some();

    if require_tls && !has_tls && !is_localhost {
        eprintln!(
            "Error: TLS is required for non-localhost bindings. \
             Provide --tls-cert and --tls-key, or bind to localhost."
        );
        std::process::exit(1);
    }

    if tls_cert.is_some() != tls_key.is_some() {
        eprintln!("Error: Both --tls-cert and --tls-key must be provided together.");
        std::process::exit(1);
    }

    let enclave_client = setup_enclave(enable_enclave, require_attestation, pcr0, pcr1, pcr2)?;

    let timeout_checker = Arc::new(TimeoutChecker::new(Arc::clone(&stores.workflow_store)));
    let timeout_handle = Arc::clone(&timeout_checker).spawn();
    tracing::info!("Started workflow timeout checker");

    let auth_state = setup_auth_state(stores).await?;

    let state = warden_api::AppState::new(
        Arc::clone(&stores.policy_store),
        Arc::clone(&stores.whitelist_store),
        Arc::clone(&stores.blacklist_store),
        Arc::clone(&stores.approval_store),
        Arc::clone(&stores.workflow_store),
        Arc::clone(&stores.group_store),
        Arc::clone(&stores.backend_registry),
        enclave_client,
        auth_state,
    );
    let app = warden_api::create_router(state);
    let addr = format_bind_address(host_trimmed, port);

    let rate_limit = std::env::var("WARDEN_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    let result = if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        println!("Starting Warden API server on https://{}", addr);
        println!("Data directory: {}", config.data_dir.display());
        println!("Rate limit: {} requests/second", rate_limit);

        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;

        axum_server::bind_rustls(addr.parse::<std::net::SocketAddr>()?, tls_config)
            .serve(app.into_make_service())
            .await
    } else {
        if !is_localhost {
            if host_trimmed == "0.0.0.0" {
                eprintln!(
                    "Warning: Binding to 0.0.0.0 without TLS exposes the API on ALL network interfaces. \
                     This is insecure for production. Use --require-tls to enforce TLS."
                );
            } else {
                eprintln!(
                    "Warning: Running without TLS on non-localhost address. \
                     Use --require-tls to enforce TLS."
                );
            }
        }
        println!("Starting Warden API server on http://{}", addr);
        println!("Data directory: {}", config.data_dir.display());
        println!("Rate limit: {} requests/second", rate_limit);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await
    };
    timeout_handle.abort();
    result?;
    Ok(())
}

fn setup_enclave(
    enable_enclave: bool,
    require_attestation: bool,
    pcr0: Option<String>,
    pcr1: Option<String>,
    pcr2: Option<String>,
) -> Result<Option<Arc<dyn EnclaveClient>>, Box<dyn std::error::Error>> {
    if !enable_enclave {
        return Ok(None);
    }

    if require_attestation {
        let has_all_pcrs = pcr0.is_some() && pcr1.is_some() && pcr2.is_some();
        if !has_all_pcrs {
            eprintln!(
                "Error: --require-attestation requires valid PCR configuration.\n\
                 Please provide --pcr0, --pcr1, and --pcr2 with valid 96-character hex values."
            );
            std::process::exit(1);
        }

        let pcr0_val = pcr0.as_ref().unwrap();
        let pcr1_val = pcr1.as_ref().unwrap();
        let pcr2_val = pcr2.as_ref().unwrap();

        for (name, val) in [("pcr0", pcr0_val), ("pcr1", pcr1_val), ("pcr2", pcr2_val)] {
            if val.len() != 96 || !val.chars().all(|c| c.is_ascii_hexdigit()) {
                eprintln!(
                    "Error: --{} must be exactly 96 hexadecimal characters (48 bytes). Got {} characters.",
                    name,
                    val.len()
                );
                std::process::exit(1);
            }
        }

        let enclave_config = EnclaveConfig {
            expected_pcrs: Some(PcrConfig {
                pcr0: pcr0_val.clone(),
                pcr1: pcr1_val.clone(),
                pcr2: pcr2_val.clone(),
            }),
            ..EnclaveConfig::default()
        };

        let proxy = EnclaveProxy::new(enclave_config).unwrap_or_else(|e| {
            eprintln!("Error: Failed to initialize enclave: {}", e);
            std::process::exit(1);
        });

        tracing::info!("Enclave enabled with PCR attestation verification");
        Ok(Some(Arc::new(proxy) as Arc<dyn EnclaveClient>))
    } else {
        tracing::warn!(
            "Enclave enabled WITHOUT attestation verification - this is insecure for production use"
        );
        let enclave_config = EnclaveConfig::default();
        let proxy = EnclaveProxy::new(enclave_config).unwrap_or_else(|e| {
            eprintln!("Error: Failed to initialize enclave: {}", e);
            std::process::exit(1);
        });
        Ok(Some(Arc::new(proxy) as Arc<dyn EnclaveClient>))
    }
}

async fn setup_auth_state(
    stores: &Stores,
) -> Result<warden_api::AuthState, Box<dyn std::error::Error>> {
    let jwt_secret = match std::env::var("WARDEN_JWT_SECRET") {
        Ok(secret) if secret.len() >= 32 => secret,
        Ok(secret) => {
            eprintln!("Error: WARDEN_JWT_SECRET must be at least 32 characters");
            eprintln!("       Current length: {} characters", secret.len());
            std::process::exit(1);
        }
        Err(_) => {
            if std::env::var("WARDEN_INSECURE_DEV").is_ok() {
                let mut random_bytes = [0u8; 32];
                getrandom::getrandom(&mut random_bytes).expect("failed to generate random secret");
                let random_secret = hex::encode(random_bytes);
                tracing::warn!("WARNING: Running with randomly generated JWT secret!");
                tracing::warn!("Tokens will be invalidated on restart.");
                tracing::warn!("DO NOT USE IN PRODUCTION. Set WARDEN_JWT_SECRET.");
                random_secret
            } else {
                eprintln!("Error: WARDEN_JWT_SECRET environment variable is required");
                eprintln!("       Set a secret of at least 32 characters");
                eprintln!("       For development only, set WARDEN_INSECURE_DEV=1");
                std::process::exit(1);
            }
        }
    };

    let rate_limit = std::env::var("WARDEN_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    let auth_state = match &stores.revoked_token_store {
        Some(store) => {
            let state = warden_api::AuthState::with_persistent_blacklist(
                jwt_secret.as_bytes(),
                rate_limit,
                Arc::clone(store),
            );
            let count = state
                .load_blacklist()
                .await
                .map_err(|e| format!("Failed to load revoked tokens from store: {}", e))?;
            if count > 0 {
                tracing::info!(count, "Loaded revoked tokens from persistent store");
            }

            let sync_interval = Duration::from_secs(30);
            if let Some(handle) = state.start_blacklist_sync(sync_interval) {
                tracing::info!(
                    interval_secs = sync_interval.as_secs(),
                    "Started blacklist sync task"
                );
                drop(handle);
            }

            state
        }
        None => warden_api::AuthState::new(jwt_secret.as_bytes(), rate_limit),
    };

    Ok(auth_state)
}

fn format_bind_address(host: &str, port: u16) -> String {
    if host.starts_with('[') && host.ends_with(']') {
        format!("{}:{}", host, port)
    } else if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}
