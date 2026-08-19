use russh_sftp::client::fs::Metadata;

/// A directory entry returned by [`crate::sftp::SftpClient::read_dir`].
#[derive(Clone, Debug)]
pub struct RemoteDirEntry {
    pub name: String,
    pub metadata: Metadata,
}
