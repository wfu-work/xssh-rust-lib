//! SSH transport, authentication, host-key verification, and generic channels.

mod auth;
mod channel;
mod config;
mod error;
mod host_key;
mod operation;
mod session;
mod socks5;

pub use auth::{
    AuthMethod, AuthMethodKind, AuthenticationAttempt, AuthenticationObservation,
    AuthenticationPlan, KeyboardInteractiveChallenge, KeyboardInteractiveHandler,
    KeyboardInteractivePrompt, RsaHashAlgorithm, SecretString, ServerAuthMethod,
};
pub use channel::{
    SshChannel, SshChannelEvent, SshChannelStream, SshForwardedStreamlocalChannel,
    SshForwardedTcpipChannel, SshRemoteStreamlocalForward, SshRemoteTcpipForward,
};
pub use config::SshConfig;
pub use error::{ErrorContext, ErrorKind, SshError};
pub use host_key::{
    HostKeyDecision, HostKeyObservation, HostKeyVerifier, KnownHostEntry, KnownHostKeyVerifier,
    KnownHostMarker, KnownHosts, TofuHostKeyVerifier,
};
pub use operation::{CancellationToken, OperationContext};
pub use session::SshSession;
pub use socks5::{Socks5Authentication, Socks5Proxy, Socks5ProxyOptions};

/// SSH key types used by the pinned `russh` protocol implementation.
pub use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
