//! UI-independent core of MicroClaw Code.
//!
//! - [`home`]: Code's own home directory and model configuration;
//! - [`project`] / [`trust`]: repository discovery, `.microclaw/project.yaml`
//!   and the per-user trust decisions that gate it;
//! - [`allow`]: per-project command allow rules (`always allow cargo test`);
//! - [`verify`] / [`git`]: running project checks and detecting changes;
//! - [`goal`]: the `/goal` loop shared by every front end;
//! - [`sessions`]: the per-project session index;
//! - [`memory`]: shared (`.microclaw/memory.md`) and private project memory;
//! - [`plugins`]: plugins in the Claude Code layout (`mccode plugin …`);
//! - [`remote`]: handing a task to a paired MicroClaw Server;
//! - [`driver`]: one user turn — agent run, approvals, verification and the
//!   fix loop — exchanged with front ends as [`driver::Control`] /
//!   [`driver::Update`] messages.
//!
//! The Agent Engine is reached only through `microclaw-sdk`.

pub mod allow;
pub mod commands;
pub mod driver;
pub mod env;
pub mod gate;
pub mod git;
pub mod goal;
pub mod home;
pub mod images;
pub mod import;
pub mod launch;
pub mod lsp;
pub mod memory;
pub mod plugins;
pub mod presets;
pub mod project;
pub mod prompt;
pub mod remote;
pub mod remote_notify;
pub mod rules;
pub mod session_lock;
pub mod sessions;
pub mod settings;
pub mod setup;
pub mod trust;
pub mod user_hooks;
pub mod verify;
pub mod worktree;
