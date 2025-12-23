
# MCP 流量分析工具 (Rust 版)

这是一个基于 Rust 开发的专业网络协议分析工具，专门用于捕获、解析和美化输出 **Model Context Protocol (MCP)** 以及其他基于 HTTP 的流式通信数据（如 `text/event-stream`）。

## 核心功能

* **事务逻辑关联**：自动匹配 TCP 连接中的 Request 和 Response，将它们作为一个完整的事务块输出，避免了请求和响应在控制台中交织错乱。
* **SSE 深度解析**：支持 `Server-Sent Events` (SSE) 协议，能够实时捕获并聚合流式输出（如 `ping` 事件和 `data` 载荷）。
* **智能 Body 识别**：
* **请求体捕获**：根据 `Content-Length` 精确读取 POST 请求的 Body 内容。
* **JSON 美化**：自动检测 Body 中的 JSON 数据并进行缩进美化处理。
* **SSE 剥离**：自动识别并清除 SSE 事件中的 `data: ` 前缀，直接展示核心 JSON 数据。


* **状态机隔离**：内置 HTTP 状态机，严格区分 Header 和 Body 边界，有效处理 TCP 粘包问题。

---

## 处理数据场景介绍

在分析 MCP 接口流量时，通常会遇到以下复杂场景，本工具针对这些场景进行了优化：

### 1. 长连接 SSE 流 (Server-Sent Events)

MCP 经常使用 `/sse` 接口进行异步通知。服务器会保持连接不关闭，并周期性发送 `: ping` 或任务结果。

* **挑战**：传统的抓包工具会将每个 ping 包视作独立的片段。
* **方案**：本程序将所有属于该 SSE 响应的事件聚合成一个列表，并在对应的 GET 请求下方统一展示。

### 2. POST 请求与响应关联

当客户端发送指令（POST）并等待流式返回时：

* **挑战**：在高并发或粘包情况下，Request Body 和 Response Header 可能出现在同一个或相邻的 TCP 包中。
* **方案**：程序通过精确的字节计数（Content-Length）确保 Request Body 被完整读取后，才开始解析 Response Header。

### 3. JSON 格式化输出

MCP 交互中包含大量的嵌入式 JSON 字符串。

* **挑战**：原始日志中 JSON 通常是单行压缩格式，难以阅读。
* **方案**：工具自动进行 `Prettify` 处理，通过颜色和缩进清晰展示 JSON 层级。

---

## 快速开始

### 前置条件

确保您的系统已安装：

* [Rust & Cargo](https://rustup.rs/)
* `libpcap` 开发库（Linux: `apt-get install libpcap-dev`, macOS: 自带）


### 运行程序

将您的 `.pcap` 文件放在程序目录下，执行以下命令：

```bash
cargo run -- file -p <你的文件名>.pcap

```

从网口解析http网络请求。同时支持BPF过滤。

``` bash
cargo run -- live -i eth0
cargo run -- live -i eth0 -f "tcp port 8080"
```

---

## 输出示例说明

程序使用 ANSI 颜色代码增强可读性：

* **绿色 (▶ REQUEST)**：表示客户端发起的请求（方法、路径及 Header）。
* **蓝色 (◀ RESPONSE)**：表示服务器返回的响应状态及 Header。
* **灰色 ([Request Body] / [SSE Ping])**：表示请求体内容或流式心跳包。
* **黄色 ([Event])**：表示 SSE 流中的有效数据事件，通常包含经过美化的 JSON。

---

## 跨平台交叉编译说明

由于本程序依赖于 `libpcap` 系统库，在进行交叉编译时，不仅需要 Rust 工具链的支持，还需要目标平台的 C 库环境。

### 1. 安装交叉编译工具链

推荐使用 `cross` 项目，它通过 Docker 容器封装了复杂的交叉编译环境。

```bash
cargo install cross

```

### 2. 为目标平台进行构建

#### 场景 A：从 macOS/Windows 构建 Linux (x86_64) 版本

这是最常见的场景，用于在服务器或云主机上运行。

```bash
# 使用 cross 进行构建
cross build --target x86_64-unknown-linux-gnu --release

```

#### 场景 B：为嵌入式或 ARM 设备构建 (aarch64)

如果您的分析环境是在树莓派或其他 ARM 架构的 Linux 设备上。

```bash
cross build --target aarch64-unknown-linux-gnu --release

```

### 3. 手动编译注意事项 (如果不使用 Docker)

如果您选择手动配置交叉编译环境，请确保：

1. **环境变量**：设置 `PKG_CONFIG_ALLOW_CROSS=1`。
2. **库路径**：您需要指向目标平台的 `libpcap.so` 或 `libpcap.a` 文件路径。
3. **静态链接**：为了提高移植性，建议尽可能使用静态链接：
```bash
# 在编译时指定静态链接 libpcap（需要目标平台有 .a 文件）
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release

```



### 4. 依赖项说明

* **Linux 目标机**：运行编译后的程序前，请确保目标机器已安装 `libpcap`。
```bash
sudo apt-get install libpcap-dev

```

### 跨平台兼容性表

| 宿主机 (Host) | 目标机 (Target) | 推荐工具 | 备注 |
| --- | --- | --- | --- |
| macOS (M1/M2) | Linux x86_64 | `cross` | 需安装 Docker |
| Windows | Linux x86_64 | `cross` / `WSL2` | 推荐在 WSL2 环境中直接编译 |
| Linux x86_64 | Linux ARM64 | `cross` | 适合边缘计算设备部署 |

---
