use clap::Subcommand;
use std::sync::Arc;
use warden_core::AddressListStore;

#[derive(Subcommand)]
pub enum ListAction {
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

pub async fn handle_list_action(
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
