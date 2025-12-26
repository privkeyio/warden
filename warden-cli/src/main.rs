#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use warden_core::{
    AddressListStore, BackendRegistry, Config, InMemoryAddressListStore, InMemoryPolicyStore,
    MockSigningBackend, Policy, PolicyEvaluator, PolicyStore, RedbStorage, TransactionRequest,
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
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value = "3000")]
        port: u16,
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

#[derive(Subcommand)]
enum ListAction {
    List,
    Create {
        name: String,
    },
    Add {
        name: String,
        address: String,
        #[arg(long)]
        label: Option<String>,
    },
    Remove {
        name: String,
        address: String,
    },
}

struct Stores {
    policy_store: Arc<dyn PolicyStore>,
    whitelist_store: Arc<dyn AddressListStore>,
    blacklist_store: Arc<dyn AddressListStore>,
    backend_registry: Arc<BackendRegistry>,
    _storage: Option<RedbStorage>,
}

impl Stores {
    fn new_memory() -> Self {
        let backend_registry = Arc::new(BackendRegistry::new());
        backend_registry.register(Arc::new(MockSigningBackend::new()));

        Self {
            policy_store: Arc::new(InMemoryPolicyStore::new()),
            whitelist_store: Arc::new(InMemoryAddressListStore::new()),
            blacklist_store: Arc::new(InMemoryAddressListStore::new()),
            backend_registry,
            _storage: None,
        }
    }

    fn new_redb(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.ensure_data_dir()?;
        let storage = RedbStorage::open(config.db_path())?;

        let backend_registry = Arc::new(BackendRegistry::new());
        backend_registry.register(Arc::new(MockSigningBackend::new()));

        Ok(Self {
            policy_store: Arc::new(storage.policy_store()),
            whitelist_store: Arc::new(storage.address_list_store()),
            blacklist_store: Arc::new(storage.address_list_store()),
            backend_registry,
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
        Commands::Policy { action } => match action {
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
                        println!("✓ Policy syntax valid");
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
                        eprintln!("✗ Validation failed: {}", e);
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
        },
        Commands::Evaluate {
            wallet,
            destination,
            amount,
            trace,
        } => {
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
                    println!("  Evaluation time: {}μs", result.evaluation_time_us);

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
        }
        Commands::Whitelist { action } => {
            handle_list_action(action, &stores.whitelist_store).await?
        }
        Commands::Blacklist { action } => {
            handle_list_action(action, &stores.blacklist_store).await?
        }
        Commands::Serve { host, port } => {
            let state = warden_api::AppState::new(
                stores.policy_store,
                stores.whitelist_store,
                stores.blacklist_store,
                stores.backend_registry,
            );
            let app = warden_api::create_router(state);
            let addr = format!("{}:{}", host, port);
            println!("Starting Warden API server on {}", addr);
            println!("Data directory: {}", config.data_dir.display());
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

async fn handle_list_action(
    action: ListAction,
    store: &Arc<dyn AddressListStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ListAction::List => {
            let names = store.list_names().await?;
            if names.is_empty() {
                println!("No lists found");
            } else {
                for name in names {
                    let entries = store.list_addresses(&name).await?;
                    println!("{} ({} entries)", name, entries.len());
                }
            }
        }
        ListAction::Create { name } => {
            store.create_list(&name).await?;
            println!("Created list: {}", name);
        }
        ListAction::Add {
            name,
            address,
            label,
        } => {
            store.add_address(&name, &address, label.as_deref()).await?;
            println!("Added {} to {}", address, name);
        }
        ListAction::Remove { name, address } => {
            store.remove_address(&name, &address).await?;
            println!("Removed {} from {}", address, name);
        }
    }
    Ok(())
}
