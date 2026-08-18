# xssh-rust-lib

`xssh-rust-lib` 是一个纯 Rust SSH 库，一个 package 内按源码目录划分为三个模块：

```text
xssh-rust-lib
└── src
    ├── core       SSH 连接、认证、主机密钥、通用 channel
    ├── terminal   PTY、交互式 shell、输入输出、窗口调整
    └── sftp       SFTP subsystem、远程文件与目录操作
```

三个模块共享同一个版本、Cargo 配置和错误类型。GPUI、CLI、Tauri 或其他前端只依赖一个 crate 即可。

## 模块职责

### `core`

- SSH TCP 连接、握手超时、认证超时、操作超时和 keepalive；
- 密码、私钥、键盘交互、SSH agent 和 OpenSSH 用户证书认证；
- 服务器主机密钥指纹校验；
- 连接生命周期；
- 通用 SSH session channel、direct-tcpip 端口转发和异步字节流；
- 可复用的 `CancellationToken`、`OperationContext` 和结构化 `SshError`。

### `terminal`

- PTY 分配；
- 登录 shell 启动；
- 输入写入和输出事件读取；
- 窗口大小调整；
- EOF、退出状态、退出信号和关闭事件。

该模块只负责 SSH PTY 协议，不负责 VT100/ANSI 解析和界面绘制。

### `sftp`

- SFTP subsystem 初始化和关闭；
- `read`、`write`、`exists`；
- 流式 `open`、`create` 和显式 `OpenFlags`；
- 创建、读取和删除目录；
- 元数据查询、重命名和路径规范化。

## Feature

默认启用 `terminal` 和 `sftp`：

```toml
[dependencies]
xssh-rust-lib = "0.3"
```

如果只需要 SSH core，可以关闭默认功能：

```toml
[dependencies]
xssh-rust-lib = { version = "0.3", default-features = false }
```

也可以按需启用：

```toml
xssh-rust-lib = { version = "0.3", default-features = false, features = ["terminal"] }
```

## 超时、截止时间与取消

`SshConfig` 默认分别为连接/握手 15 秒、认证 15 秒、普通操作 30 秒。旧的异步方法会自动使用这些默认值：

```rust,no_run
let mut config = SshConfig::new("server.example.com", "alice")?;
config.connect_timeout = std::time::Duration::from_secs(10);
config.authentication_timeout = std::time::Duration::from_secs(15);
config.operation_timeout = std::time::Duration::from_secs(30);
```

需要由 GPUI 任务或上层工作流取消单个连接/终端/SFTP 操作时，传入独立的 `OperationContext`。截止时间和取消信号同时生效，先触发的条件会返回 `ErrorKind::Timeout` 或 `ErrorKind::Cancelled`：

```rust,no_run
use std::time::Duration;
use xssh_rust_lib::{CancellationToken, OperationContext};

let cancellation = CancellationToken::new();
let context = OperationContext::with_timeout(Duration::from_secs(20))
    .with_cancellation(cancellation.clone());

let session = xssh_rust_lib::SshSession::connect_with_context(
    config,
    verifier,
    auth,
    context.clone(),
).await?;

// 取消当前工作流时调用；不会自动关闭整个 SSH session。
cancellation.cancel();
```

`SshSession::open_session_channel_with_context`、`TerminalSession::open_with_context`、
`SftpClient::connect_with_context` 以及各模块的 `*_with_context` 方法可用于覆盖单次操作的 context。
等待终端/channel 事件时，推荐使用返回 `Result` 的 `next_event_with_context`，这样可以区分正常关闭、超时和取消；
`SshChannelStream` 也提供 `read_with_context`、`write_with_context` 和 `flush_with_context`。

`SshError` 会保留错误源（如果底层库提供）、错误阶段、operation、host/port、远程 path 和 `is_retryable()` 标记；这些字段不包含密码或私钥内容，适合交给 GPUI 的状态层和日志层。

## 主机密钥、known_hosts 与 TOFU

`KnownHostKeyVerifier` 是严格的内存校验器，可以直接解析 OpenSSH
`known_hosts` 文本或文件：

```rust,no_run
use xssh_rust_lib::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let verifier = KnownHostKeyVerifier::from_path("/home/alice/.ssh/known_hosts")?;
let config = SshConfig::new("server.example.com", "alice")?;
let session = SshSession::connect(
    config,
    verifier,
    AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
)
.await?;
session.disconnect().await?;
# Ok(())
# }
```

解析和匹配支持普通主机、`[host]:port`、`*`/`?` 通配符、`!` 排除模式以及
OpenSSH `|1|salt|hmac` hashed host。`@revoked` 条目会返回
`HostKeyDecision::Revoked`；`@cert-authority` 会被保留为结构化 marker，但当前
库只验证直接提供的服务器公钥，不执行 SSH host certificate 的 CA 验证。

`KnownHostKeyVerifier::check` 返回 `HostKeyObservation`，其中包含 presented
fingerprint、匹配的 known_hosts 行号、期望指纹和 `Trusted`、`Unknown`、`Changed`
或 `Revoked` 决策，适合直接交给 GPUI 的信任确认状态层。`SshSession` 会拒绝
`Unknown`、`Changed` 和 `Revoked`；调用 `SshError::host_key_observation()` 可以直接
读取同一份结构化信息，无需解析错误字符串。

需要明确采用 trust-on-first-use 时，可以使用 `TofuHostKeyVerifier`：首次出现的
公钥会在内存中记录并接受，后续 changed/revoked key 仍会拒绝。连接成功后由上层
负责安全持久化快照，核心库不会直接写用户配置文件：

```rust,no_run
use xssh_rust_lib::{
    AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession, TofuHostKeyVerifier,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let verifier = TofuHostKeyVerifier::new(KnownHostKeyVerifier::new());
let retained_verifier = verifier.clone();
let session = SshSession::connect(
    SshConfig::new("server.example.com", "alice")?,
    verifier,
    AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
)
.await?;

let snapshot = retained_verifier.snapshot()?;
let known_hosts_text = snapshot.known_hosts().to_openssh();
// 由应用使用原子替换和 Keychain/权限控制保存 known_hosts_text。
let _ = known_hosts_text;
session.disconnect().await?;
# Ok(())
# }
```

## 认证方式与回退

`SshSession::connect` 的第三个参数可以是单个 `AuthMethod`，也可以是按顺序执行的
`AuthenticationPlan`。传入单个方法的旧代码仍然有效；计划为空会返回配置错误。每个方法
只有在服务端拒绝、或本地方法不可用且连接仍保持打开时才会继续尝试下一个方法：

```rust,no_run
use std::path::Path;
use xssh_rust_lib::{
    AuthMethod, AuthenticationPlan, KnownHostKeyVerifier, PrivateKey, RsaHashAlgorithm, SshConfig,
    SshSession,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let config = SshConfig::new("server.example.com", "alice")?;
let verifier = KnownHostKeyVerifier::from_path("/home/alice/.ssh/known_hosts")?;
let private_key = PrivateKey::read_openssh_file(Path::new("/home/alice/.ssh/id_rsa"))?;

let auth = AuthenticationPlan::new([
    AuthMethod::agent(),
    AuthMethod::private_key_with_rsa_hash(
        private_key,
        RsaHashAlgorithm::Sha512,
    ),
    AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
]);

let session = SshSession::connect(config, verifier, auth).await?;
session.disconnect().await?;
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

私钥认证支持口令保护的 key。RSA key 默认使用 `RsaHashAlgorithm::Auto`，优先读取
服务端 `server-sig-algs` 扩展并选择 `rsa-sha2-512` 或 `rsa-sha2-256`；也可以显式指定
`Sha256`、`Sha512`，或仅为兼容旧服务端而选择 `LegacySha1`。RSA 签名算法策略同样适用于
`AuthMethod::agent_with_rsa_hash`。

键盘交互适合 OTP、PAM 和多提示登录。回调在每次服务端 challenge 到达时异步执行，返回值
必须与 prompt 数量完全一致；`echo` 字段可用于决定 GPUI 是否遮挡输入：

```rust,no_run
use xssh_rust_lib::{AuthMethod, SecretString, SshError};

let auth = AuthMethod::keyboard_interactive(|challenge| async move {
    let answers = challenge.prompts.iter().map(|prompt| {
        // 实际应用应把 challenge 交给 GPUI，再把用户输入包装成 SecretString。
        let answer = if prompt.echo { "user-response" } else { "otp-response" };
        SecretString::new(answer)
    }).collect();
    Ok::<_, SshError>(answers)
});
```

OpenSSH 证书通过 `AuthMethod::openssh_certificate` 或带口令的构造函数启用。库会在发送
认证请求前检查证书是 user certificate，并确认它的公钥与私钥匹配；证书有效期、principal
和 CA 策略仍由 SSH 服务端执行。

SSH agent 在 Unix 上默认读取 `SSH_AUTH_SOCK`，也可以用 `agent_from_socket` 指定 Unix
domain socket；Windows 默认连接 Pageant，或把 named pipe 路径传给同一构造函数。agent
中不存在可用身份、socket/Pageant 不可用时，错误会进入认证观察结果并允许计划继续执行后续
方法。

认证失败返回的 `SshError` 提供 `authentication_observation()`，其中记录每次尝试的方法、
服务端剩余方法、partial-success 状态和脱敏错误信息。它适合在 GPUI 状态层展示下一步动作，
不需要解析错误字符串；密码、OTP 和 passphrase 不会出现在 `Debug` 或标准认证错误文本中。

## Direct TCP/IP 转发

`SshSession::open_direct_tcpip` 打开一个由 SSH 服务端发起的 `direct-tcpip` channel，
目标主机和端口由服务端解析。返回的 `SshChannel` 可以转换为支持
`AsyncRead`/`AsyncWrite` 的 `SshChannelStream`，适合与本地监听 socket 做双向 relay：

```rust,no_run
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use xssh_rust_lib::SshSession;

# async fn run(session: &SshSession) -> Result<(), Box<dyn std::error::Error>> {
let listener = TcpListener::bind("127.0.0.1:15432").await?;
loop {
    let (mut local, _) = listener.accept().await?;
    let channel = session.open_direct_tcpip("database.internal", 5432).await?;
    let mut remote = channel.into_stream();
    tokio::spawn(async move {
        let _ = copy_bidirectional(&mut local, &mut remote).await;
    });
}
# }
```

目标主机不能为空，目标端口必须大于零；参数错误会返回 `ErrorKind::Configuration`。
默认 originator 是 `127.0.0.1:0`，需要传递真实来源时使用
`open_direct_tcpip_from` 或其 `_with_context` 版本。打开 channel 支持
`OperationContext` 的截止时间和取消信号，channel stream 的 `read`、`write`、`flush`
也会沿用同一套操作超时策略。

远程反向转发使用 `request_remote_tcpip_forward` 注册服务端监听，再通过
`next_forwarded_tcpip` 消费每个进入的连接。远端 channel 队列容量固定为 64，消费速度不足
时会对 SSH handler 施加背压；上层应尽快把 channel 转交给 relay 任务：

```rust,no_run
use xssh_rust_lib::SshSession;

# async fn run(session: &mut SshSession) -> Result<(), Box<dyn std::error::Error>> {
let forward = session
    .request_remote_tcpip_forward("127.0.0.1", 0)
    .await?;
println!("remote listener: {}:{}", forward.address(), forward.port());

while let Some(incoming) = session.next_forwarded_tcpip().await? {
    println!(
        "incoming connection from {}:{}",
        incoming.originator_address(),
        incoming.originator_port()
    );
    let mut stream = incoming.into_stream();
    tokio::spawn(async move {
        // Connect a local socket and relay with copy_bidirectional here.
        let _ = stream.flush().await;
    });
}

session.cancel_remote_tcpip_forward(&forward).await?;
# Ok(())
# }
```

`request_remote_tcpip_forward` 和取消操作需要独占 `&mut SshSession`，以保证 russh 全局请求
的顺序；接收 channel 的 `next_forwarded_tcpip` 可以通过共享引用调用。端口为零时，返回值
会使用服务端分配的实际端口；服务端返回非法端口或动态端口缺失会报告
`ErrorKind::Protocol`。

## SOCKS5 动态代理

`Socks5Proxy` 在本地监听 SOCKS5 客户端，把每个 `CONNECT` 请求转换为 SSH
`direct-tcpip` channel，再执行双向字节 relay。支持 IPv4、IPv6 和域名目标；域名不会在
本地解析，而是原样交给 SSH 服务端，因此目标可访问服务端所在网络中的内网地址：

```rust,no_run
use std::sync::Arc;
use xssh_rust_lib::{CancellationToken, Socks5Proxy, SshSession};

# async fn run(session: SshSession) -> Result<(), Box<dyn std::error::Error>> {
let session = Arc::new(session);
let proxy = Socks5Proxy::bind(Arc::clone(&session), "127.0.0.1:1080").await?;
let cancellation = CancellationToken::new();

// 在关闭窗口或应用退出时调用 cancellation.cancel()。
proxy.run(cancellation).await?;
# Ok(())
# }
```

默认只接受 SOCKS5 no-auth 方法。需要认证时显式配置用户名密码、并设置合理的并发上限和
握手超时：

```rust,no_run
use std::sync::Arc;
use std::time::Duration;
use xssh_rust_lib::{
    Socks5Authentication, Socks5Proxy, Socks5ProxyOptions, SshSession,
};

# async fn run(session: SshSession) -> Result<(), Box<dyn std::error::Error>> {
let options = Socks5ProxyOptions {
    max_connections: 64,
    handshake_timeout: Duration::from_secs(15),
    authentication: Socks5Authentication::username_password("alice", "local-secret"),
};
let proxy = Socks5Proxy::bind_with_options(Arc::new(session), "127.0.0.1:0", options).await?;
println!("SOCKS5 listening on {}", proxy.local_addr()?);
# Ok(())
# }
```

代理默认不会暴露到公网；如果确实需要监听非回环地址，应同时启用用户名密码认证、系统
防火墙和访问控制。代理只实现 `CONNECT`，不支持 `BIND`、UDP ASSOCIATE 或代理链。

## 使用示例

```rust,no_run
use xssh_rust_lib::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};
use xssh_rust_lib::terminal::{TerminalOptions, TerminalSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SshConfig::new("server.example.com", "alice")?;

    // 生产环境应从受保护的 known_hosts 存储加载条目。
    let verifier = KnownHostKeyVerifier::from_path("/home/alice/.ssh/known_hosts")?;
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
        if matches!(event, xssh_rust_lib::terminal::TerminalEvent::Close) {
            break;
        }
    }

    session.disconnect().await?;
    Ok(())
}
```

SFTP 使用同一个 core 会话：

```rust,no_run
use xssh_rust_lib::sftp::SftpClient;

# async fn run(session: &xssh_rust_lib::SshSession) -> Result<(), Box<dyn std::error::Error>> {
let sftp = SftpClient::connect(session).await?;
sftp.write("/tmp/hello.txt", b"hello").await?;
let bytes = sftp.read("/tmp/hello.txt").await?;
assert_eq!(bytes, b"hello");
sftp.close().await?;
# Ok(())
# }
```

## 安全边界

- `KnownHostKeyVerifier` 默认拒绝未知、变更或 revoked 的服务器主机密钥；需要自动首次信任时显式使用 `TofuHostKeyVerifier`；
- 密码和私钥 passphrase 使用 `zeroize` 包装，不应写入日志或持久化配置；
- known-hosts 持久化由上层应用负责，应使用系统密钥链或经过审计的加密存储；
- terminal 和 sftp 不绕过 core 的认证和主机密钥策略。

## 当前未包含

GPUI UI、VT100 渲染、SQLite、Keychain、Windows Credential Manager、Unix socket forwarding
和 SSH ProxyJump/代理链不属于当前基础库。

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
cargo clippy --all-targets --all-features -- -D warnings
```

核心库使用 MIT 许可证。
