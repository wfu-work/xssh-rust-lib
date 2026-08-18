# xssh-rust-lib

`xssh-rust-lib` 是一个纯 Rust SSH/Core 依赖库，为 GPUI 桌面端、CLI、Tauri 或其他前端提供可复用的 SSH 传输基础。它不包含 UI、终端渲染或平台数据存储。

## 当前能力

- SSH TCP 连接和协议握手，基于固定版本 `russh 0.54.3`；
- 可配置连接超时、TCP_NODELAY 和 keepalive；
- 密码认证和 OpenSSH 私钥认证；
- 加密私钥在认证前解密，密码和 passphrase 使用 `zeroize` 包装，并且不会出现在 `Debug` 或 `Display` 输出中；
- 强制执行服务器主机密钥校验，不默认信任未知密钥；
- SHA-256 主机密钥指纹和严格的内存 known-hosts 校验器；
- 按配置、连接、握手、主机密钥、认证、通道和超时阶段分类的错误。

## 最小用法

```rust,no_run
use xssh_rust_lib::{AuthMethod, KnownHostKeyVerifier, PublicKey, SshConfig, SshSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SshConfig::new("server.example.com", "alice")?;

    // 生产环境应从受保护的 known-hosts 存储加载，而不是自动接受未知密钥。
    let server_key = PublicKey::from_openssh(&std::fs::read_to_string("server-key.pub")?)?;
    let mut verifier = KnownHostKeyVerifier::new();
    verifier.insert_key(&config.host, config.port, server_key.public_key());

    let session = SshSession::connect(
        config,
        verifier,
        AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
    )
    .await?;

    println!("connected: {}", !session.is_closed());
    session.disconnect().await?;
    Ok(())
}
```

上面的 `server-key.pub` 仅用于展示密钥类型；实际应用应加载服务器的公钥，而不是把服务器私钥放入客户端。应用也可以实现 `HostKeyVerifier`，将 `HostKeyDecision::Unknown` 交给用户确认，并把确认结果写入自己的加密存储。

## 设计边界

本批次只实现核心连接生命周期和认证基础层，暂不包含：

- GPUI 或其他 UI 框架；
- PTY、交互式 shell、终端 VT100 渲染；
- `exec`、SFTP、端口转发和代理链；
- SQLite、macOS Keychain、Windows Credential Manager 等平台存储。

这些功能会在后续独立的大功能提交中添加，并保持核心库不依赖具体桌面 UI 或存储实现。

## 安全约束

1. `SshSession::connect` 必须收到 `HostKeyVerifier`，未知或变更的服务器密钥会终止连接。
2. 不要在日志、错误文本或配置持久化中写入密码、私钥内容或 passphrase。
3. 不要在客户端自动接受未知主机密钥；应由上层 UI 明确展示指纹并获得用户确认。
4. 本库不负责密钥持久化。上层应用应使用系统密钥链或其他经过审计的加密存储。

## 开发检查

```bash
CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo fmt -- --check

CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo test --all-features

CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo build --all-features
```

首次构建可能需要下载 `ring` 等 Rust 加密依赖。核心库使用 MIT 许可证。
