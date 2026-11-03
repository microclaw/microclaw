//! UI-independent core of MicroClaw Code.
//!
//! - [`home`]: Code's own home directory and model configuration;
//! - [`project`] / [`trust`]: repository discovery, `.microclaw/project.yaml`
//!   and the per-user trust decisions that gate it;
//! - [`verify`] / [`git`]: running project checks and detecting changes;
//! - [`sessions`]: the per-project session index;
//! - [`driver`]: one user turn — agent run, approvals, verification and the
//!   fix loop — exchanged with front ends as [`driver::Control`] /
//!   [`driver::Update`] messages.
//!
//! The Agent Engine is reached only through `microclaw-sdk`.

pub mod driver;
pub mod git;
pub mod home;
pub mod project;
pub mod prompt;
pub mod sessions;
pub mod trust;
pub mod verify;
