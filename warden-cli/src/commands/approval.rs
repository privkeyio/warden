use clap::Subcommand;
use std::sync::Arc;
use warden_core::{Approval, ApprovalDecision, ApprovalWorkflow, GroupStore, WorkflowStore};

#[derive(Subcommand)]
pub enum ApprovalAction {
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

pub async fn handle_approval_action(
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
            submit_decision(
                workflow_store,
                group_store,
                &workflow,
                &approver,
                &role,
                ApprovalDecision::Approve,
                comment,
            )
            .await?;
        }
        ApprovalAction::Reject {
            workflow,
            approver,
            role,
            reason,
        } => {
            submit_decision(
                workflow_store,
                group_store,
                &workflow,
                &approver,
                &role,
                ApprovalDecision::Reject,
                reason,
            )
            .await?;
        }
    }
    Ok(())
}

async fn submit_decision(
    workflow_store: &Arc<dyn WorkflowStore>,
    group_store: &Arc<dyn GroupStore>,
    workflow_id: &str,
    approver: &str,
    role: &str,
    decision: ApprovalDecision,
    comment: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let uuid = uuid::Uuid::parse_str(workflow_id)?;
    let groups = group_store.get_groups_for_approver(approver).await?;
    let group_names: Vec<_> = groups.iter().map(|g| g.name.clone()).collect();

    let Some(w) = workflow_store.get_workflow(&uuid).await? else {
        eprintln!("Workflow not found: {}", workflow_id);
        return Ok(());
    };

    if !w.can_approve(approver, &group_names) {
        eprintln!("Approver {} is not authorized for this workflow", approver);
        std::process::exit(1);
    }

    let valid_role = resolve_role(&w, role, &group_names, approver)?;

    let action_name = match decision {
        ApprovalDecision::Approve => "Approval",
        ApprovalDecision::Reject => "Rejection",
    };

    let mut approval = Approval::new(approver.to_string(), valid_role.clone(), decision, 0);
    if let Some(c) = comment {
        approval = approval.with_comment(c);
    }

    let updated = workflow_store
        .add_approval_to_workflow(&uuid, approval)
        .await?;

    println!("{} submitted by {} ({})", action_name, approver, valid_role);
    println!("Workflow status: {:?}", updated.status);
    Ok(())
}

fn resolve_role(
    workflow: &ApprovalWorkflow,
    requested_role: &str,
    group_names: &[String],
    approver: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let required_groups = workflow.requirement.all_groups();

    if required_groups.contains(&requested_role.to_string())
        && group_names.contains(&requested_role.to_string())
    {
        return Ok(requested_role.to_string());
    }

    group_names
        .iter()
        .find(|g| required_groups.contains(*g))
        .cloned()
        .ok_or_else(|| {
            format!(
                "Approver {} has no valid role for this workflow. User groups: {:?}, required groups: {:?}",
                approver, group_names, required_groups
            )
            .into()
        })
}
