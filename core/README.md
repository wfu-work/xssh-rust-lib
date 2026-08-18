# xssh-rust-core

`xssh-rust-core` 是 xssh-rust-lib 的 SSH 传输和认证基础包。

它提供 `SshConfig`、`AuthMethod`、`HostKeyVerifier`、`SshSession` 和通用 `SshChannel`。主机密钥必须由调用者显式提供，未知密钥不会被自动接受。

```rust,no_run
use xssh_rust_core::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let config = SshConfig::new("server.example.com", "alice")?;
let verifier = KnownHostKeyVerifier::new();
let session = SshSession::connect(
    config,
    verifier,
    AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
).await?;
session.disconnect().await?;
# Ok(())
# }
```

core 不包含 GPUI、PTY、终端渲染、SFTP 或平台凭据存储。
