//! SSH transport, authentication, host-key verification, and generic channels.

mod auth;
mod channel;
mod config;
mod error;
mod host_key;
mod operation;
mod session;

pub use auth::{AuthMethod, SecretString};
pub use channel::{SshChannel, SshChannelEvent, SshChannelStream};
pub use config::SshConfig;
pub use error::{ErrorContext, ErrorKind, SshError};
pub use host_key::{HostKeyDecision, HostKeyVerifier, KnownHostKeyVerifier};
pub use operation::{CancellationToken, OperationContext};
pub use session::SshSession;

/// SSH key types used by the pinned `russh` protocol implementation.
pub use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
