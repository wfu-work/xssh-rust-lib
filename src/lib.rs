//! Pure Rust SSH library split into core, terminal, and SFTP modules.
//!
//! The modules share one crate and one version, while the optional `terminal`
//! and `sftp` features keep consumers able to build a core-only dependency.

pub mod core;

#[cfg(feature = "terminal")]
pub mod terminal;

#[cfg(feature = "sftp")]
pub mod sftp;

pub use core::{
    Algorithm, AuthMethod, CancellationToken, ErrorContext, ErrorKind, HashAlg, HostKeyDecision,
    HostKeyVerifier, KnownHostKeyVerifier, OperationContext, PrivateKey, PublicKey, SecretString,
    SshChannel, SshChannelEvent, SshChannelStream, SshConfig, SshError, SshSession,
};
