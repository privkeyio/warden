#![forbid(unsafe_code)]

mod commands;

use clap::{Parser, Subcommand};
use commands::{
    handle_approval_action, handle_group_action, handle_list_action, handle_serve_command,
    ApprovalAction, GroupAction, ListAction,
};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "mock")]
use warden_core::MockSigningBackend;
use warden_core::{
    AddressListStore, ApprovalStore, BackendRegistry, Config, GroupStore, InMemoryAddressListStore,
    InMemoryApprovalStore, InMemoryGroupStore, InMemoryPolicyStore, InMemoryWorkflowStore, Policy,
    PolicyEvaluator, PolicyStore, RedbStorage, RevokedTokenStore, TransactionRequest,
    WorkflowStore,
};

#[derive(Parser)]
#[command(name = "warden")]
#[command(about = "Warden Policy Engine CLI", version)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[arg(long, global = true)]
    memory: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    Evaluate {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        trace: bool,
    },
    Whitelist {
        #[command(subcommand)]
        action: ListAction,
    },
    Blacklist {
        #[command(subcommand)]
        action: ListAction,
    },
    Approval {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value = "3000")]
        port: u16,
        #[arg(long, help = "Path to TLS certificate PEM file")]
        tls_cert: Option<PathBuf>,
        #[arg(long, help = "Path to TLS private key PEM file")]
        tls_key: Option<PathBuf>,
        #[arg(
            long,
            help = "Require TLS for non-localhost bindings (exits if TLS not configured)"
        )]
        require_tls: bool,
        #[arg(long, help = "Enable enclave-based signing (requires Nitro Enclave)")]
        enable_enclave: bool,
        #[arg(
            long,
            help = "Require PCR attestation verification (mandatory for production)"
        )]
        require_attestation: bool,
        #[arg(long, help = "Expected PCR0 value (96 hex chars)")]
        pcr0: Option<String>,
        #[arg(long, help = "Expected PCR1 value (96 hex chars)")]
        pcr1: Option<String>,
        #[arg(long, help = "Expected PCR2 value (96 hex chars)")]
        pcr2: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    List,
    Get {
        id: String,
    },
    Create {
        #[arg(short, long)]
        file: PathBuf,
    },
    Validate {
        #[arg(short, long)]
        file: PathBuf,
    },
    Activate {
        id: String,
    },
    Deactivate {
        id: String,
    },
    Explain {
        id: String,
    },
}

pub(crate) struct Stores {
    pub(crate) policy_store: Arc<dyn PolicyStore>,
    pub(crate) whitelist_store: Arc<dyn AddressListStore>,
    pub(crate) blacklist_store: Arc<dyn AddressListStore>,
    pub(crate) approval_store: Arc<dyn ApprovalStore>,
    pub(crate) workflow_store: Arc<dyn WorkflowStore>,
    pub(crate) group_store: Arc<dyn GroupStore>,
    pub(crate) backend_registry: Arc<BackendRegistry>,
    pub(crate) revoked_token_store: Option<Arc<dyn RevokedTokenStore>>,
    _storage: Option<RedbStorage>,
}

impl Stores {
    fn new_memory() -> Self {
        let backend_registry = Arc::new(BackendRegistry::new());
        #[cfg(feature = "mock")]
        backend_registry.register(Arc::new(MockSigningBackend::new()));

        Self {
            policy_store: Arc::new(InMemoryPolicyStore::new()),
            whitelist_store: Arc::new(InMemoryAddressListStore::new()),
            blacklist_store: Arc::new(InMemoryAddressListStore::new()),
            approval_store: Arc::new(InMemoryApprovalStore::new()),
            workflow_store: Arc::new(InMemoryWorkflowStore::new()),
            group_store: Arc::new(InMemoryGroupStore::new()),
            backend_registry,
            revoked_token_store: None,
            _storage: None,
        }
    }

    fn new_redb(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.ensure_data_dir()?;
        let storage = RedbStorage::open(config.db_path())?;

        let backend_registry = Arc::new(BackendRegistry::new());
        #[cfg(feature = "mock")]
        backend_registry.register(Arc::new(MockSigningBackend::new()));

        let revoked_token_store: Arc<dyn RevokedTokenStore> =
            Arc::new(storage.revoked_token_store());

        Ok(Self {
            policy_store: Arc::new(storage.policy_store()),
            whitelist_store: Arc::new(storage.address_list_store()),
            blacklist_store: Arc::new(storage.address_list_store()),
            approval_store: Arc::new(storage.approval_store()),
            workflow_store: Arc::new(storage.workflow_store()),
            group_store: Arc::new(storage.group_store()),
            backend_registry,
            revoked_token_store: Some(revoked_token_store),
            _storage: Some(storage),
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let config = match cli.data_dir {
        Some(ref data_dir) => Config::default().with_data_dir(data_dir.clone()),
        None => Config::new()?,
    };

    let stores = if cli.memory {
        Stores::new_memory()
    } else {
        Stores::new_redb(&config)?
    };

    match cli.command {
        Commands::Policy { action } => handle_policy_action(action, &stores).await?,
        Commands::Evaluate {
            wallet,
            destination,
            amount,
            trace,
        } => handle_evaluate(&stores, wallet, destination, amount, trace).await?,
        Commands::Whitelist { action } => {
            handle_list_action(action, &stores.whitelist_store).await?
        }
        Commands::Blacklist { action } => {
            handle_list_action(action, &stores.blacklist_store).await?
        }
        Commands::Approval { action } => {
            handle_approval_action(action, &stores.workflow_store, &stores.group_store).await?
        }
        Commands::Group { action } => handle_group_action(action, &stores.group_store).await?,
        Commands::Serve {
            host,
            port,
            tls_cert,
            tls_key,
            require_tls,
            enable_enclave,
            require_attestation,
            pcr0,
            pcr1,
            pcr2,
        } => {
            handle_serve_command(
                &config,
                &stores,
                host,
                port,
                tls_cert,
                tls_key,
                require_tls,
                enable_enclave,
                require_attestation,
                pcr0,
                pcr1,
                pcr2,
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_evaluate(
    stores: &Stores,
    wallet: String,
    destination: String,
    amount: u64,
    trace: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let evaluator = PolicyEvaluator::new(
        Arc::clone(&stores.policy_store),
        Arc::clone(&stores.whitelist_store),
        Arc::clone(&stores.blacklist_store),
    );

    let request = TransactionRequest::new(wallet, destination, amount);

    match evaluator.evaluate(&request).await {
        Ok(result) => {
            println!("Evaluation Result:");
            println!("  Decision: {:?}", result.decision);
            println!("  Policy: {} v{}", result.policy_id, result.policy_version);
            println!("  Evaluation time: {}us", result.evaluation_time_us);

            if trace {
                println!("\nTrace:");
                for entry in &result.trace {
                    println!(
                        "  [{}] {}: {}",
                        if entry.matched { "MATCH" } else { "NO MATCH" },
                        entry.rule_id,
                        entry.details
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("Evaluation failed: {}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn handle_policy_action(
    action: PolicyAction,
    stores: &Stores,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        PolicyAction::List => {
            let policies = stores.policy_store.list().await?;
            if policies.is_empty() {
                println!("No policies found");
            } else {
                for p in policies {
                    println!(
                        "{} {} v{} [{}]",
                        p.id,
                        p.name,
                        p.version,
                        if p.is_active { "active" } else { "inactive" }
                    );
                }
            }
        }
        PolicyAction::Get { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            if let Some(policy) = stores.policy_store.get(&uuid).await? {
                println!("{}", serde_yaml::to_string(&policy)?);
            } else {
                eprintln!("Policy not found: {}", id);
            }
        }
        PolicyAction::Create { file } => {
            let content = std::fs::read_to_string(&file)?;
            let policy = Policy::from_yaml(&content)?;
            let created = stores.policy_store.create(policy).await?;
            println!(
                "Created policy: {} v{} (id: {})",
                created.name, created.version, created.id
            );
        }
        PolicyAction::Validate { file } => {
            let content = std::fs::read_to_string(&file)?;
            match Policy::from_yaml(&content) {
                Ok(policy) => {
                    println!("Policy syntax valid");
                    println!("  Name: {}", policy.name);
                    println!("  Version: {}", policy.version);
                    println!("  Rules: {}", policy.rules.len());
                    for rule in &policy.rules {
                        if let Some(ref dest) = rule.conditions.destination {
                            if let Some(ref wl) = dest.in_whitelist {
                                println!("  References whitelist: {}", wl);
                            }
                            if let Some(ref bl) = dest.in_blacklist {
                                println!("  References blacklist: {}", bl);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Validation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        PolicyAction::Activate { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            stores.policy_store.activate(&uuid).await?;
            println!("Activated policy: {}", id);
        }
        PolicyAction::Deactivate { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            stores.policy_store.deactivate(&uuid).await?;
            println!("Deactivated policy: {}", id);
        }
        PolicyAction::Explain { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            if let Some(policy) = stores.policy_store.get(&uuid).await? {
                println!("Policy: {} (v{})", policy.name, policy.version);
                if let Some(desc) = &policy.description {
                    println!("Description: {}", desc);
                }
                println!("\nRules ({}):", policy.rules.len());
                for (i, rule) in policy.rules.iter().enumerate() {
                    println!("  {}. {} [{:?}]", i + 1, rule.id, rule.action);
                    if let Some(desc) = &rule.description {
                        println!("     {}", desc);
                    }
                }
                println!("\nDefault action: {:?}", policy.default_action);
            } else {
                eprintln!("Policy not found: {}", id);
            }
        }
    }
    Ok(())
}
