//! High-level SFTP operations for an authenticated `core::SshSession`.

mod client;
mod error;
mod types;

pub use client::SftpClient;
pub use error::SftpError;
pub use russh_sftp::client::fs::{File as SftpFile, Metadata};
pub use russh_sftp::protocol::OpenFlags;
pub use types::RemoteDirEntry;
