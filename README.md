# xssh-rust-lib

`xssh-rust-lib` 现在是一个 Cargo workspace，由三个职责清晰、可独立复用的纯 Rust 包组成：

```text
xssh-rust-core       SSH 连接、认证、主机密钥、通用 channel
        ├── xssh-rust-terminal   PTY、交互式 shell、输入输出、窗口调整
        └── xssh-rust-sftp       SFTP subsystem、远程文件与目录操作
```

三个包都不依赖 GPUI。GPUI、CLI、Tauri 或其他前端只需要按功能选择依赖即可。

## 包结构

### `xssh-rust-core`

核心传输层，负责：

- SSH TCP 连接、握手超时和 keepalive；
- 密码与私钥认证；
- 服务器主机密钥指纹校验；
- 连接生命周期；
- 通用 SSH session channel 和异步字节流。

核心包不保存 SQLite、Keychain 或其他平台凭据，也不包含终端渲染。

### `xssh-rust-terminal`

基于 core channel 封装交互式终端：

- PTY 分配；
- 登录 shell 启动；
- 输入写入和输出事件读取；
- 窗口大小调整；
- EOF、退出状态、退出信号和关闭事件。

### `xssh-rust-sftp`

基于 SFTP subsystem 封装远程文件系统操作：

- 连接和关闭 SFTP subsystem；
- `read`、`write`、`exists`；
- 流式文件 `open`、`create` 和显式 `OpenFlags`；
- 创建、读取和删除目录；
- 元数据查询；
- 文件重命名和路径规范化。

## 最小依赖

```toml
[dependencies]
xssh-rust-core = "0.2"
xssh-rust-terminal = "0.2" # 需要交互式终端时添加
xssh-rust-sftp = "0.2"     # 需要文件传输时添加
```

先创建并认证 core 会话，再把同一个会话交给 terminal 或 sftp 包：

```rust,no_run
use xssh_rust_core::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};
use xssh_rust_terminal::{TerminalOptions, TerminalSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SshConfig::new("server.example.com", "alice")?;
    let verifier = KnownHostKeyVerifier::new();

    // 生产环境应从受保护的 known-hosts 存储加载指纹。
    let session = SshSession::connect(
        config,
        verifier,
        AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
    )
    .await?;

    let mut terminal = TerminalSession::open(&session, TerminalOptions::default()).await?;
    terminal.write(b"echo ready\n").await?;
    while let Some(event) = terminal.next_event().await {
        println!("{event:?}");
        if matches!(event, xssh_rust_terminal::TerminalEvent::Close) {
            break;
        }
    }

    session.disconnect().await?;
    Ok(())
}
```

SFTP 的使用方式相同：

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

## 安全边界

- core 默认拒绝未知或变更的服务器主机密钥；
- 密码和私钥 passphrase 使用 `zeroize` 包装，不应写入日志或持久化配置；
- known-hosts 持久化由上层应用负责，应使用系统密钥链或经过审计的加密存储；
- terminal 和 sftp 不绕过 core 的认证和主机密钥策略。

## 当前未包含

GPUI UI、VT100 渲染、SQLite、Keychain、Windows Credential Manager、SSH agent、端口转发和代理链不属于本批次。它们可以在上层应用或后续独立包中实现。

## 开发检查

```bash
CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo fmt -- --check

CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo test --workspace --all-features

CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

核心库使用 MIT 许可证。
