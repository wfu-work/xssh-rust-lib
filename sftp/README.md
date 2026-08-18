# xssh-rust-sftp

`xssh-rust-sftp` 在已认证的 `xssh-rust-core::SshSession` 上启动 SFTP subsystem，并提供远程文件系统操作。

```rust,no_run
use xssh_rust_sftp::SftpClient;

# async fn run(session: &xssh_rust_core::SshSession) -> Result<(), Box<dyn std::error::Error>> {
let sftp = SftpClient::connect(session).await?;
sftp.write("/tmp/hello.txt", b"hello").await?;
let bytes = sftp.read("/tmp/hello.txt").await?;
assert_eq!(bytes, b"hello");
sftp.close().await?;
# Ok(())
# }
```

当前包封装文件读写、目录、元数据、存在性、删除、重命名和路径规范化。它不负责本地文件选择器、传输队列或 UI 进度展示。
