//! Pure Rust SSH core primitives.
//!
//! This crate intentionally contains transport and protocol concerns only. UI,
//! terminal emulation, persistence, and platform credential stores belong in
//! higher-level crates.

mod auth;
mod channel;
mod config;
mod error;
mod host_key;
mod session;

pub use auth::{AuthMethod, SecretString};
pub use channel::{SshChannel, SshChannelEvent, SshChannelStream};
pub use config::SshConfig;
pub use error::{ErrorKind, SshError};
pub use host_key::{HostKeyDecision, HostKeyVerifier, KnownHostKeyVerifier};
pub use session::SshSession;

/// SSH key types used by the pinned `russh` protocol implementation.
pub use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
