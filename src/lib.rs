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
    Algorithm, AuthMethod, AuthMethodKind, AuthenticationAttempt, AuthenticationObservation,
    AuthenticationPlan, CancellationToken, Certificate, ErrorContext, ErrorKind, HashAlg,
    HostKeyDecision, HostKeyObservation, HostKeyVerifier, KeyboardInteractiveChallenge,
    KeyboardInteractiveHandler, KeyboardInteractivePrompt, KnownHostEntry, KnownHostKeyVerifier,
    KnownHostMarker, KnownHosts, OperationContext, PrivateKey, PublicKey, RsaHashAlgorithm,
    SecretString, ServerAuthMethod, SshChannel, SshChannelEvent, SshChannelStream, SshConfig,
    SshError, SshSession, TofuHostKeyVerifier,
};
