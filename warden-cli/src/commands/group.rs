use clap::Subcommand;
use std::sync::Arc;
use warden_core::{ApproverGroup, GroupMember, GroupStore};

#[derive(Subcommand)]
pub enum GroupAction {
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

pub async fn handle_group_action(
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
