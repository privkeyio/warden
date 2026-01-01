#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use warden_core::{
    AddressListStore, ApprovalDecision, ApprovalStore, ApproverGroup, BackendRegistry, Config,
    GroupMember, GroupStore, InMemoryAddressListStore, InMemoryApprovalStore, InMemoryGroupStore,
    InMemoryPolicyStore, InMemoryWorkflowStore, MockSigningBackend, Policy, PolicyEvaluator,
    PolicyStore, RedbStorage, TimeoutChecker, TransactionRequest, WorkflowStore,
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

#[derive(Subcommand)]
enum ApprovalAction {
    List,
    Get {
        id: String,
    },
    Approve {
        #[arg(long)]
        workflow: String,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        comment: Option<String>,
    },
    Reject {
        #[arg(long)]
        workflow: String,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum GroupAction {
    List,
    Get {
        name: String,
    },
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    AddMember {
        group: String,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        display_name: Option<String>,
    },
    RemoveMember {
        group: String,
        approver: String,
    },
}

struct Stores {
    policy_store: Arc<dyn PolicyStore>,
    whitelist_store: Arc<dyn AddressListStore>,
    blacklist_store: Arc<dyn AddressListStore>,
    approval_store: Arc<dyn ApprovalStore>,
    workflow_store: Arc<dyn WorkflowStore>,
    group_store: Arc<dyn GroupStore>,
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
            approval_store: Arc::new(InMemoryApprovalStore::new()),
            workflow_store: Arc::new(InMemoryWorkflowStore::new()),
            group_store: Arc::new(InMemoryGroupStore::new()),
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
            approval_store: Arc::new(storage.approval_store()),
            workflow_store: Arc::new(storage.workflow_store()),
            group_store: Arc::new(storage.group_store()),
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
        } => {
            let is_localhost = host == "127.0.0.1" || host == "localhost" || host == "::1";
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

            let timeout_checker = Arc::new(TimeoutChecker::new(Arc::clone(&stores.workflow_store)));
            let timeout_handle = Arc::clone(&timeout_checker).spawn();
            tracing::info!("Started workflow timeout checker");

            let state = warden_api::AppState::new(
                stores.policy_store,
                stores.whitelist_store,
                stores.blacklist_store,
                stores.approval_store,
                stores.workflow_store,
                stores.group_store,
                stores.backend_registry,
            );
            let app = warden_api::create_router(state);
            let addr = format!("{}:{}", host, port);

            let result = if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
                println!("Starting Warden API server on https://{}", addr);
                println!("Data directory: {}", config.data_dir.display());

                let tls_config =
                    axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                        .await?;

                axum_server::bind_rustls(addr.parse()?, tls_config)
                    .serve(app.into_make_service())
                    .await
            } else {
                if !is_localhost {
                    if host == "0.0.0.0" {
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
                let listener = tokio::net::TcpListener::bind(&addr).await?;
                axum::serve(listener, app).await
            };

            timeout_handle.abort();
            result?;
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

async fn handle_approval_action(
    action: ApprovalAction,
    workflow_store: &Arc<dyn WorkflowStore>,
    group_store: &Arc<dyn GroupStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ApprovalAction::List => {
            let workflows = workflow_store.list_pending_workflows().await?;
            if workflows.is_empty() {
                println!("No pending workflows");
            } else {
                for w in workflows {
                    println!(
                        "{} [{}] {} sats -> {} (expires: {})",
                        w.id,
                        format!("{:?}", w.status).to_uppercase(),
                        w.transaction_details.amount_sats,
                        w.transaction_details.destination,
                        w.expires_at.format("%Y-%m-%d %H:%M UTC")
                    );
                }
            }
        }
        ApprovalAction::Get { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            if let Some(workflow) = workflow_store.get_workflow(&uuid).await? {
                println!("Workflow: {}", workflow.id);
                println!("Status: {:?}", workflow.status);
                println!("Transaction: {}", workflow.transaction_id);
                println!(
                    "Amount: {} sats ({:.8} BTC)",
                    workflow.transaction_details.amount_sats,
                    workflow.transaction_details.amount_btc()
                );
                println!("From: {}", workflow.transaction_details.source_wallet);
                println!("To: {}", workflow.transaction_details.destination);
                println!("Created: {}", workflow.created_at);
                println!("Expires: {}", workflow.expires_at);
                println!("\nApprovals ({}):", workflow.approvals.len());
                for a in &workflow.approvals {
                    println!(
                        "  {} ({}) - {:?} at {}",
                        a.approver_id, a.approver_role, a.decision, a.created_at
                    );
                }
                println!("\nQuorum Status: {:?}", workflow.quorum_status());
            } else {
                eprintln!("Workflow not found: {}", id);
            }
        }
        ApprovalAction::Approve {
            workflow,
            approver,
            role,
            comment,
        } => {
            let uuid = uuid::Uuid::parse_str(&workflow)?;
            let groups = group_store.get_groups_for_approver(&approver).await?;
            let group_names: Vec<_> = groups.iter().map(|g| g.name.clone()).collect();

            if let Some(w) = workflow_store.get_workflow(&uuid).await? {
                if !w.can_approve(&approver, &group_names) {
                    eprintln!("Approver {} is not authorized for this workflow", approver);
                    std::process::exit(1);
                }

                let required_groups = w.requirement.all_groups();
                let valid_role = if required_groups.contains(&role) && group_names.contains(&role) {
                    role.clone()
                } else {
                    group_names
                        .iter()
                        .find(|g| required_groups.contains(*g))
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "Approver {} has no valid role for this workflow. User groups: {:?}, required groups: {:?}",
                                approver, group_names, required_groups
                            )
                        })?
                };

                let mut approval = warden_core::Approval::new(
                    approver.clone(),
                    valid_role.clone(),
                    ApprovalDecision::Approve,
                    0,
                );
                if let Some(c) = comment {
                    approval = approval.with_comment(c);
                }

                let updated = workflow_store
                    .add_approval_to_workflow(&uuid, approval)
                    .await?;
                println!("Approval submitted by {} ({})", approver, valid_role);
                println!("Workflow status: {:?}", updated.status);
            } else {
                eprintln!("Workflow not found: {}", workflow);
            }
        }
        ApprovalAction::Reject {
            workflow,
            approver,
            role,
            reason,
        } => {
            let uuid = uuid::Uuid::parse_str(&workflow)?;
            let groups = group_store.get_groups_for_approver(&approver).await?;
            let group_names: Vec<_> = groups.iter().map(|g| g.name.clone()).collect();

            if let Some(w) = workflow_store.get_workflow(&uuid).await? {
                if !w.can_approve(&approver, &group_names) {
                    eprintln!("Approver {} is not authorized for this workflow", approver);
                    std::process::exit(1);
                }

                let required_groups = w.requirement.all_groups();
                let valid_role = if required_groups.contains(&role) && group_names.contains(&role) {
                    role.clone()
                } else {
                    group_names
                        .iter()
                        .find(|g| required_groups.contains(*g))
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "Approver {} has no valid role for this workflow. User groups: {:?}, required groups: {:?}",
                                approver, group_names, required_groups
                            )
                        })?
                };

                let mut rejection = warden_core::Approval::new(
                    approver.clone(),
                    valid_role.clone(),
                    ApprovalDecision::Reject,
                    0,
                );
                if let Some(r) = reason {
                    rejection = rejection.with_comment(r);
                }

                let updated = workflow_store
                    .add_approval_to_workflow(&uuid, rejection)
                    .await?;
                println!("Rejection submitted by {} ({})", approver, valid_role);
                println!("Workflow status: {:?}", updated.status);
            } else {
                eprintln!("Workflow not found: {}", workflow);
            }
        }
    }
    Ok(())
}

async fn handle_group_action(
    action: GroupAction,
    group_store: &Arc<dyn GroupStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        GroupAction::List => {
            let groups = group_store.list().await?;
            if groups.is_empty() {
                println!("No groups found");
            } else {
                for g in groups {
                    println!("{} ({} members)", g.name, g.members.len());
                }
            }
        }
        GroupAction::Get { name } => {
            if let Some(group) = group_store.get_by_name(&name).await? {
                println!("Group: {}", group.name);
                if let Some(desc) = &group.description {
                    println!("Description: {}", desc);
                }
                println!("Created: {}", group.created_at);
                println!("\nMembers ({}):", group.members.len());
                for m in &group.members {
                    let display = m
                        .display_name
                        .as_ref()
                        .map(|n| format!(" ({})", n))
                        .unwrap_or_default();
                    println!("  {}{} - added {}", m.approver_id, display, m.added_at);
                }
            } else {
                eprintln!("Group not found: {}", name);
            }
        }
        GroupAction::Create { name, description } => {
            let mut group = ApproverGroup::new(name.clone());
            if let Some(desc) = description {
                group = group.with_description(desc);
            }
            let created = group_store.create(group).await?;
            println!("Created group: {} (id: {})", created.name, created.id);
        }
        GroupAction::AddMember {
            group,
            approver,
            display_name,
        } => {
            if let Some(g) = group_store.get_by_name(&group).await? {
                let mut member = GroupMember::new(approver.clone());
                if let Some(name) = display_name {
                    member = member.with_display_name(name);
                }

                group_store.add_member(&g.id, member).await?;
                println!("Added {} to group {}", approver, group);
            } else {
                eprintln!("Group not found: {}", group);
            }
        }
        GroupAction::RemoveMember { group, approver } => {
            if let Some(g) = group_store.get_by_name(&group).await? {
                group_store.remove_member(&g.id, &approver).await?;
                println!("Removed {} from group {}", approver, group);
            } else {
                eprintln!("Group not found: {}", group);
            }
        }
    }
    Ok(())
}
