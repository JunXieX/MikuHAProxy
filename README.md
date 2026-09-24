# MikuHAProxy

Lets Velocity 4.0 accept both HAProxy PROXY protocol connections and direct player connections, while trusting PROXY headers only from whitelisted sources.

让 Velocity 4.0 同时接受「代理连接（HAProxy PROXY protocol）」与「玩家直连」，并且只放行可信来源发来的 PROXY 头。

- Version: **1.3.0**
- Author: **JunXieX** (MikuMC Server)
- QQ Group: **1105054380**

## Why You Need It

**为什么需要它**

Velocity's `velocity.toml` has a `haproxy-protocol` option. Once it is turned on, Velocity assumes that **every** incoming connection carries an HAProxy PROXY header and installs a decoder at the very front of the pipeline; a connection without a PROXY header is dropped immediately.

Velocity 的 `velocity.toml` 里有一项 `haproxy-protocol`。一旦打开，Velocity 就认为**每一条**进来的连接都带着 HAProxy 的 PROXY 头，并在管道最前面挂上解码器；不带 PROXY 头的连接会被直接掐断。

This creates a dilemma:

这带来一个两难：

- Leave `haproxy-protocol` off: you cannot see the player's real IP behind HAProxy, so IP bans, login restrictions and risk control all stop working.
    - 不开 `haproxy-protocol`：拿不到经过 HAProxy 之后的玩家真实 IP，IP 封禁、登录限制、风控全部失效。
- Turn `haproxy-protocol` on: only connections through HAProxy get in, and direct player connections (LAN debugging, backup entry points, ops probes) are all rejected.
    - 开了 `haproxy-protocol`：只有经过 HAProxy 的连接能进，玩家直连（内网调试、备用入口、运维探测）全部被拒。

MikuHAProxy keeps both: it places a detector at the head of the pipeline that decides, from **the first few bytes of the connection**, whether the connection is a proxied one or a direct one, and routes each down its own path.

MikuHAProxy 同时保住两头：在管道首位放一个探测器，**按连接开头的那几个字节**判断这条连接是代理连接还是直连，分别走各自的路径。

## Security Model

**安全模型**

Only when the **TCP peer address** — the address of the machine that actually opened the connection — is on the whitelist will its PROXY header be trusted.

**只有「TCP 对端地址」——也就是真正发起这条连接的机器的地址——出现在白名单里的连接，它发来的 PROXY 头才会被采信。**

There is no room for ambiguity here: the "client address" declared inside a PROXY header is a string written by the sender, and anyone can forge it. If you trusted what the PROXY header says, an attacker could simply stand up their own HAProxy, send a forged header, and impersonate any IP — IP bans would stop working instantly. So the only valid criterion is the TCP peer address: it is a fact of the network layer and cannot be forged.

这一点不能含糊：PROXY 头里声明的「客户端地址」是发送方自己填的字符串，任何人都能伪造。如果按 PROXY 头里的内容去信任，攻击者只要自己架一个 HAProxy 往里发头，就能把自己伪装成任意 IP，IP 封禁立刻失效。所以判据只能是 TCP 对端地址——它是网络层的事实，伪造不了。

When the whitelist is empty, **all proxied connections are rejected** and only direct connections are kept. That is a deliberate safe default.

白名单为空时，**所有代理连接都会被拒绝**，只保留直连。这是刻意的安全默认值。

Two things must be said plainly:

有两点必须说清楚：

- The whitelist governs **only** whose PROXY header is trusted. It does **not** restrict direct connections: any address that can reach the proxy port is still let in as a direct connection. If that port is exposed to the internet, control direct access with a firewall of your own.
    - 白名单只管「谁的 PROXY 头会被采信」，它**不限制直连**：任何能连到代理端口的地址，仍然可以按直连的方式进来。代理端口若对公网开放，请用防火墙单独控制直连来源。
- The shipped `whitelist.conf` already contains `127.0.0.0/8` and `::1/128`. That is **deliberate trust in loopback** — the usual deployment puts HAProxy and Velocity on the same machine — and the price is that any process on that machine which can reach the port may send a PROXY header claiming to be any IP, and have it believed. If the machine has untrusted users, delete those two lines and whitelist only HAProxy's actual address.
    - 出厂的 `whitelist.conf` 里预置了 `127.0.0.0/8` 与 `::1/128`。这是**有意的回环信任**（绝大多数部署把 HAProxy 与 Velocity 放在同一台机器上），代价是本机上任何能连到这个端口的进程，都可以发一个「自称任意 IP」的 PROXY 头并被采信。若这台机器上有不受信任的其他用户，请删掉这两条，改成只写 HAProxy 的实际地址。

## How It Works

**工作原理**

1. When a new connection is created, Velocity runs the connection initializer once. This plugin wraps around it: it runs Velocity's initializer unchanged first, then replaces the PROXY decoder at the head of the pipeline with its own detector.
    - 每条新连接创建时，Velocity 会执行一次连接初始化。本插件包了一层，先原样执行 Velocity 的初始化，再把管道最前面的 PROXY 解码器换成探测器。
2. The detector reads the opening bytes of the connection:
    - 探测器读连接开头的字节：
    - The opening **cannot** be a PROXY header → it is a direct connection. The detector removes itself from the pipeline and hands the already-buffered bytes over untouched (not a single byte of the handshake packet is lost).
        - 开头**不可能**是 PROXY 头 → 判定为直连，探测器把自己从管道里摘掉，已缓冲的字节原封不动交给后续处理器（握手包一个字节都不会丢）。
    - The opening **is** a PROXY header → it checks whether the TCP peer address is on the whitelist. If yes, a real PROXY decoder is put back and control returns to Velocity; if no, the connection is closed immediately.
        - 开头**确实是** PROXY 头 → 检查 TCP 对端地址是否在白名单里。在 → 换上真正的 PROXY 解码器交还给 Velocity；不在 → 立即关闭连接。
3. Once the decision is made, the detector takes no further part in that connection.

    判定完成后探测器就不再参与这条连接的任何后续处理。

The decision is progressive: the v2 signature starts with `0x0D` and the v1 prefix is `PROXY`, so the moment a received byte mismatches, the connection is immediately classified as direct. The vast majority of direct connections are settled by **looking at a single byte**, with no needless waiting.

判定是渐进式的：v2 的签名以 `0x0D` 开头、v1 的前缀是 `PROXY`，只要收到的字节出现失配就立刻定性为直连。绝大多数直连连接**只看 1 个字节**就能得出结论，不需要白等。

## Requirements

**环境要求**

| Item | Requirement |
|---|---|
| Proxy | Velocity 4.0 or newer; **Velocity-CTD** 4.x works as well (both verified) |
| Java | **Java 25** (Velocity 4.0 itself requires Java 25) |
| Prerequisite | `haproxy-protocol = true` in `velocity.toml` |

| 项 | 要求 |
|---|---|
| 代理端 | Velocity 4.0 及以上；**Velocity-CTD** 4.x 同样适用（两者均已核对） |
| Java | **Java 25**（Velocity 4.0 自身要求 Java 25） |
| 前置配置 | `velocity.toml` 中 `haproxy-protocol = true` |

## Installation

**安装**

1. Put `MikuHAProxy-1.3.0.jar` into the proxy's `plugins/` directory.
    - 把 `MikuHAProxy-1.3.0.jar` 放进代理端的 `plugins/` 目录。
2. Start the proxy once. The plugin creates its data directory `plugins/MikuHAProxy/`, containing `config.toml` and `whitelist.conf`.
    - 启动一次代理。插件会生成数据目录 `plugins/MikuHAProxy/`，内含 `config.toml` 与 `whitelist.conf`。
3. Set `haproxy-protocol = true` in `velocity.toml`, then **restart the proxy** (this option is not hot-reloadable).
    - 在 `velocity.toml` 中设置 `haproxy-protocol = true`，然后**重启代理**（这一项不支持热重载）。
4. Write your HAProxy server address into `plugins/MikuHAProxy/whitelist.conf`.
    - 把你的 HAProxy 服务器地址写进 `plugins/MikuHAProxy/whitelist.conf`。
5. Run `/mikuproxy reload` to apply the whitelist, or simply restart the proxy.
    - 执行 `/mikuproxy reload` 让白名单生效，或直接重启代理。

> If the startup log says that `haproxy-protocol` is not enabled in `velocity.toml`, step 3 has not been done yet and the plugin will have no effect.

> 启动日志里如果出现「`velocity.toml` 里没有启用 `haproxy-protocol`」，说明第 3 步还没做，插件不会起作用。

## Configuration

**配置**

### `plugins/MikuHAProxy/config.toml`

It uses only the simplest `key = value` form. **Any mistyped entry simply falls back to its default and reports the problem on the console — it never makes the plugin fail to load.**

只使用 `键 = 值` 这一种最简形式。**任何一项写错都只会回退到默认值并在控制台报出问题，不会让插件加载失败。**

| Option | Default | Description |
|---|---|---|
| `allow-all-proxies` | `false` | Whether to accept proxied connections from **any** source. **Never enable this in production** — see the warning below. |
| `whitelist-file` | `"whitelist.conf"` | Path to the whitelist file. A relative path is resolved against `plugins/MikuHAProxy/`; an absolute path also works. |
| `log-rejected-connections` | `true` | Whether to output the "proxied connection rejected", "exception while deciding" and "connection dropped before deciding" log lines. Keeping it on is recommended: the first two are your first clue that someone is forging IPs. The third is normal network noise and is written only at DEBUG, so it stays invisible unless you enable debug logging. When off, none of the three is written, but the counts of the first two are still visible under "Rejected" and "Errors" in `status`. |
| `log-accepted-connections` | `false` | Whether to output a log line for every accepted proxied connection. Usually best kept off. |
| `rejected-log-interval-seconds` | `60` | Minimum interval, in seconds, between log lines for the same throttle slot (a slot is a log category + source address); range `0 ~ 86400`. `0` disables throttling. |
| `rejected-log-max-tracked` | `4096` | How many throttle slots (a slot is a log category + source address) the log throttle tracks at once; range `16 ~ 1000000`. |

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `allow-all-proxies` | `false` | 是否放行**任何来源**的代理连接。**生产环境绝对不要开启**，详见下方警告。 |
| `whitelist-file` | `"whitelist.conf"` | 白名单文件路径。相对路径相对于 `plugins/MikuHAProxy/`，也可以写绝对路径。 |
| `log-rejected-connections` | `true` | 是否输出「代理连接被拒绝」「判定过程发生异常」「连接在判定前被对端中断」三类日志。建议保持开启：前两类是发现有人在伪造 IP 的第一手线索；第三类属正常网络现象，只在 DEBUG 级输出、默认看不到。关闭后三类都不再输出，前两类的次数仍可在 `status` 的「拒绝」「异常」计数里看到。 |
| `log-accepted-connections` | `false` | 是否输出「代理连接被接受」的日志（每条代理连接一行）。平时建议关闭。 |
| `rejected-log-interval-seconds` | `60` | 同一限流槽（日志分类 + 来源地址）的日志最短间隔，单位秒，范围 `0 ~ 86400`。`0` 表示不限流。 |
| `rejected-log-max-tracked` | `4096` | 日志限流器最多同时跟踪多少个限流槽（日志分类 + 来源地址），范围 `16 ~ 1000000`。 |

> **About `allow-all-proxies`**: enabling it is the same as disabling the whitelist. Anyone can stand up their own HAProxy and send forged PROXY headers to your proxy, impersonating a player's real IP; IP bans, login restrictions and risk control all stop working. Use it only in a fully isolated test environment that is not exposed to the internet.

> **关于 `allow-all-proxies`**：打开它等于关闭白名单。任何人都可以自己架一个 HAProxy 向你的代理发送伪造的 PROXY 头，从而伪造玩家真实 IP，IP 封禁、登录限制、风控全部失效。仅在完全隔离、不对公网暴露的测试环境里才可以使用。

### `plugins/MikuHAProxy/whitelist.conf`

One rule per line; everything after `#` is a comment and blank lines are ignored.

每行一条规则，`#` 之后是注释，空行忽略。

```
# Single IPv4 / IPv6
127.0.0.1
::1

# Network range (CIDR)
127.0.0.0/8
10.0.0.0/8
fd00::/8

# Domain name: resolved once at startup, all A / AAAA records are included
proxy.example.com
```

Notes:

说明：

- What is checked here is the address of **the machine that opened the TCP connection** (your HAProxy server), not the client address declared in the PROXY header.
    - 这里判断的是**发起 TCP 连接的那台机器的地址**（你的 HAProxy 服务器），不是 PROXY 头里声明的客户端地址。
- A domain name cannot carry a `/prefix`: one domain may have both IPv4 and IPv6 addresses, and a single prefix length cannot express that. Write a CIDR if you need a range.
    - 域名不能带 `/前缀`：一个域名可能同时有 IPv4 和 IPv6 地址，前缀长度无法统一表达。需要网段请直接写 CIDR。
- **A malformed line only skips that line**, and the console reports which line it was, what it contained and what was wrong — the plugin never fails to load because of it.
    - **某一行写法有误只会跳过该行**，并在控制台提示「第几行、什么内容、什么问题」，不会导致插件加载失败。
- If HAProxy and Velocity run on the same machine, usually only `127.0.0.0/8` and `::1/128` are needed.
    - 如果 HAProxy 和 Velocity 装在同一台机器上，通常只需要 `127.0.0.0/8` 和 `::1/128` 两条。
- An empty whitelist means rejecting every proxied connection and keeping direct connections only.
    - 白名单为空 = 拒绝所有代理连接，只保留直连。

## Commands and Permissions

**命令与权限**

| Command | Description |
|---|---|
| `/mikuproxy` | Show help |
| `/mikuproxy status` | Show pipeline injection state, the `haproxy-protocol` switch, a whitelist summary, connection counters and uptime |
| `/mikuproxy list` | List all whitelist rules currently in effect |
| `/mikuproxy reload` | Re-read `config.toml` and the whitelist; **effective immediately for connections created afterwards**, existing connections are unaffected. If something in the config is wrong, whoever runs the command sees the list of problems directly (anything beyond the list is in the console log) |

| 命令 | 说明 |
|---|---|
| `/mikuproxy` | 显示帮助 |
| `/mikuproxy status` | 查看管道注入状态、`haproxy-protocol` 开关、白名单概览、连接计数、已运行时间 |
| `/mikuproxy list` | 列出当前生效的全部白名单规则 |
| `/mikuproxy reload` | 重新读取 `config.toml` 与白名单，**立即对之后新建的连接生效**，已建立的连接不受影响。配置里若有写错的项，执行这条命令的人会直接看到问题清单（列不完的部分在控制台日志里） |

Aliases: `/mhp`, `/mikuhaproxy`.

别名：`/mhp`、`/mikuhaproxy`。

Permission: `mikuhaproxy.admin` (granted to the console by default).

权限：`mikuhaproxy.admin`（控制台默认拥有）。

What the connection counters in `status` mean:

`status` 里的连接计数含义：

| Counter | Meaning |
|---|---|
| Direct | Connections classified as direct |
| Proxied | Connections classified as proxied and accepted by the whitelist |
| Rejected | Connections classified as proxied whose source is not on the whitelist, and which were closed |
| Not injected | No PROXY decoder was found anywhere in the pipeline (usually means `haproxy-protocol` is off in `velocity.toml`) |
| Errors | Connections where the decision raised an exception or injection failed, and which were handled as before |

| 计数 | 含义 |
|---|---|
| 直连 | 判定为直连的连接数 |
| 代理 | 判定为代理连接、且白名单校验通过的连接数 |
| 拒绝 | 判定为代理连接但来源不在白名单，已被关闭的连接数 |
| 未注入 | 管道里没有找到 PROXY 解码器（通常意味着 `velocity.toml` 没开 `haproxy-protocol`） |
| 异常 | 判定过程出现异常或注入失败，已按原有方式处理的连接数 |

## Troubleshooting

**常见问题**

**After enabling it, players' real IPs look like the HAProxy address?**

**开启后玩家真实 IP 变成 HAProxy 的地址了？**

The PROXY header is not being trusted. Check in order: whether `haproxy-protocol` is `true` in `velocity.toml`, whether HAProxy is configured with `send-proxy` (v1) or `send-proxy-v2`, whether HAProxy's address is in `whitelist.conf`, and whether the "Proxied" counter in `/mikuproxy status` is growing.

说明 PROXY 头没被采信。依次检查：`velocity.toml` 的 `haproxy-protocol` 是否为 `true`、HAProxy 是否配置了 `send-proxy`（v1）或 `send-proxy-v2`、HAProxy 的地址是否在 `whitelist.conf` 里、`/mikuproxy status` 的「代理」计数是否在增长。

**HAProxy is configured correctly, yet connections are still rejected?**

**HAProxy 明明配好了，还是被拒绝？**

Look at the rejection line in the console and at `/mikuproxy list`. The most common cause is that the actual source address of the HAProxy→Velocity connection differs from what you wrote in the whitelist (for example a NAT or container network sits in between) — in that case, whitelist the actual peer address.

看控制台那条拒绝日志，以及 `/mikuproxy list`。最常见的原因是 HAProxy 与 Velocity 之间的实际连接来源地址和写进白名单的不一致（例如中间隔了一层 NAT 或容器网络），此时按实际对端地址放行。

**The plugin seems to do nothing after startup?**

**插件启动后完全没生效？**

Run `/mikuproxy status` and check whether "Pipeline injection" is "Installed" and whether "`haproxy-protocol` in `velocity.toml`" is "Enabled". If either one is wrong, the plugin does not change how connections are handled.

用 `/mikuproxy status` 看「管道注入」是否为「已安装」、「`velocity.toml` 的 `haproxy-protocol`」是否为「已启用」。两者任一不对，插件都不会改变连接处理方式。

**What happens if the config is wrong?**

**配置写错了会怎样？**

The plugin starts as usual, the bad entry falls back to its default, and the problem is printed to the console as "which line, what problem". `whitelist.conf` behaves the same way: an invalid line only skips itself. When you run `/mikuproxy reload`, those problems are echoed back to whoever ran the command, so there is no need to dig through logs.

插件照常启动，出错的那一项回退默认值，问题以「第几行、什么问题」的形式打到控制台；`whitelist.conf` 同理，非法行只跳过自己。执行 `/mikuproxy reload` 时，这些问题会直接回显给执行命令的人，不必再去翻日志。

## Statement

**声明**

This project is an original plugin of the MikuMC server, released to the public free of charge. The MikuMC server and the author JunXieX hold the copyright of this project. This project is not open source, please note.

本项目为 MikuMC 服务器原创插件，公开给大众免费使用，MikuMC 服务器与作者 JunXieX 享有项目著作权，本项目非开源项目，请注意。

MikuMC 系列插件交流群：**1105054380**
