//! Notification sender implementations.

mod email;
mod logging;
mod nostr;
mod slack;
mod webhook;

pub use email::{EmailConfig, EmailSender};
pub use logging::LoggingSender;
pub use nostr::{NostrConfig, NostrSender};
pub use slack::{SlackConfig, SlackSender};
pub use webhook::WebhookSender;
