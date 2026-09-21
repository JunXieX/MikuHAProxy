# MikuHAProxy

让 **Velocity 4.0** 同时接受「代理连接（HAProxy PROXY protocol）」与「玩家直连」，并且只放行可信来源发来的 PROXY 头。

- 版本：**1.0.1**
- 作者：**JunXieX**（MikuMC 服务器）
- 交流群：**1105054380**

---

## 为什么需要它

Velocity 的 `velocity.toml` 里有一项 `proxy-protocol`。一旦打开，Velocity 就认为**每一条**进来的连接都带着 HAProxy 的 PROXY 头，并在管道最前面挂上解码器；不带 PROXY 头的连接会被直接掐断。

这带来一个两难：

- **不开** `proxy-protocol`：拿不到经过 HAProxy 之后的玩家真实 IP，IP 封禁、登录限制、风控全部失效。
- **开了** `proxy-protocol`：只有经过 HAProxy 的连接能进，玩家直连（内网调试、备用入口、运维探测）全部被拒。

MikuHAProxy 同时保住两头：在管道首位放一个探测器，**按连接开头的那几个字节**判断这条连接是代理连接还是直连，分别走各自的路径。

## 安全模型

**只有「TCP 对端地址」——也就是真正发起这条连接的机器的地址——出现在白名单里的连接，它发来的 PROXY 头才会被采信。**

这一点不能含糊：PROXY 头里声明的「客户端地址」是发送方自己填的字符串，任何人都能伪造。如果按 PROXY 头里的内容去信任，攻击者只要自己架一个 HAProxy 往里发头，就能把自己伪装成任意 IP，IP 封禁立刻失效。所以判据只能是 TCP 对端地址——它是网络层的事实，伪造不了。

白名单为空时，**所有代理连接都会被拒绝**，只保留直连。这是刻意的安全默认值。

## 工作原理

1. 每条新连接创建时，Velocity 会执行一次连接初始化。本插件包了一层，先原样执行 Velocity 的初始化，再把管道最前面的 PROXY 解码器换成探测器。
2. 探测器读连接开头的字节：
   - 开头**不可能**是 PROXY 头 → 判定为直连，探测器把自己从管道里摘掉，已缓冲的字节原封不动交给后续处理器（握手包一个字节都不会丢）。
   - 开头**确实是** PROXY 头 → 检查 TCP 对端地址是否在白名单里。在 → 换上真正的 PROXY 解码器交还给 Velocity；不在 → 立即关闭连接。
3. 判定完成后探测器就不再参与这条连接的任何后续处理。

判定是渐进式的：v2 的签名以 `0x0D` 开头、v1 的前缀是 `PROXY`，只要收到的字节出现失配就立刻定性为直连。绝大多数直连连接**只看 1 个字节**就能得出结论，不需要白等。

## 环境要求

| 项 | 要求 |
|---|---|
| 代理端 | Velocity 4.0 及以上；**Velocity-CTD** 4.x 同样适用（两者均已核对） |
| Java | **Java 25**（Velocity 4.0 自身要求 Java 25） |
| 前置配置 | `velocity.toml` 中 `proxy-protocol = true` |

## 安装

1. 把 `MikuHAProxy-1.0.1.jar` 放进代理端的 `plugins/` 目录。
2. 启动一次代理。插件会生成数据目录 `plugins/MikuHAProxy/`，内含 `config.toml` 与 `whitelist.conf`。
3. 在 `velocity.toml` 中设置 `proxy-protocol = true`，然后**重启代理**（这一项不支持热重载）。
4. 把你的 HAProxy 服务器地址写进 `plugins/MikuHAProxy/whitelist.conf`。
5. 执行 `/mikuproxy reload` 让白名单生效，或直接重启代理。

> 启动日志里如果出现「`velocity.toml` 里没有启用 `proxy-protocol`」，说明第 3 步还没做，插件不会起作用。

## 配置

### `plugins/MikuHAProxy/config.toml`

只使用 `键 = 值` 这一种最简形式。**任何一项写错都只会回退到默认值并在控制台报出问题，不会让插件加载失败。**

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `allow-all-proxies` | `false` | 是否放行**任何来源**的代理连接。**生产环境绝对不要开启**，详见下方警告。 |
| `whitelist-file` | `"whitelist.conf"` | 白名单文件路径。相对路径相对于 `plugins/MikuHAProxy/`，也可以写绝对路径。 |
| `log-rejected-connections` | `true` | 是否输出「代理连接被拒绝」与「判定过程发生异常」这两类日志。建议保持开启，这是发现有人在伪造 IP 的第一手线索；关闭后两类日志都不再输出，次数仍可在 `status` 的「拒绝」「异常」计数里看到。 |
| `log-accepted-connections` | `false` | 是否输出「代理连接被接受」的日志（每条代理连接一行）。平时建议关闭。 |
| `rejected-log-interval-seconds` | `60` | 同一来源地址的拒绝日志最短间隔，单位秒，范围 `0 ~ 86400`。`0` 表示不限流。 |
| `rejected-log-max-tracked` | `4096` | 日志限流器最多同时跟踪多少个来源地址，范围 `16 ~ 1000000`。 |

> **关于 `allow-all-proxies`**：打开它等于关闭白名单。任何人都可以自己架一个 HAProxy 向你的代理发送伪造的 PROXY 头，从而伪造玩家真实 IP，IP 封禁、登录限制、风控全部失效。仅在完全隔离、不对公网暴露的测试环境里才可以使用。

### `plugins/MikuHAProxy/whitelist.conf`

每行一条规则，`#` 之后是注释，空行忽略。

```
# 单个 IPv4 / IPv6
127.0.0.1
::1

# 网段（CIDR）
127.0.0.0/8
10.0.0.0/8
fd00::/8

# 域名：启动时解析一次，A / AAAA 记录全部纳入
proxy.example.com
```

说明：

- 这里判断的是**发起 TCP 连接的那台机器的地址**（你的 HAProxy 服务器），不是 PROXY 头里声明的客户端地址。
- 域名不能带 `/前缀`：一个域名可能同时有 IPv4 和 IPv6 地址，前缀长度无法统一表达。需要网段请直接写 CIDR。
- **某一行写法有误只会跳过该行**，并在控制台提示「第几行、什么内容、什么问题」，不会导致插件加载失败。
- 如果 HAProxy 和 Velocity 装在同一台机器上，通常只需要 `127.0.0.0/8` 和 `::1/128` 两条。
- 白名单为空 = 拒绝所有代理连接，只保留直连。

## 命令与权限

| 命令 | 说明 |
|---|---|
| `/mikuproxy` | 显示帮助 |
| `/mikuproxy status` | 查看管道注入状态、`proxy-protocol` 开关、白名单概览、连接计数、已运行时间 |
| `/mikuproxy list` | 列出当前生效的全部白名单规则 |
| `/mikuproxy reload` | 重新读取 `config.toml` 与白名单，**立即对之后新建的连接生效**，已建立的连接不受影响。配置里若有写错的项，执行这条命令的人会直接看到问题清单（列不完的部分在控制台日志里） |

别名：`/mhp`、`/mikuhaproxy`。

权限：`mikuhaproxy.admin`（控制台默认拥有）。

`status` 里的连接计数含义：

| 计数 | 含义 |
|---|---|
| 直连 | 判定为直连的连接数 |
| 代理 | 判定为代理连接、且白名单校验通过的连接数 |
| 拒绝 | 判定为代理连接但来源不在白名单，已被关闭的连接数 |
| 未注入 | 管道首位没有找到 PROXY 解码器（通常意味着 `velocity.toml` 没开 `proxy-protocol`） |
| 异常 | 判定过程出现异常或注入失败，已按原有方式处理的连接数 |

## 常见问题

**开启后玩家真实 IP 变成 HAProxy 的地址了？**
说明 PROXY 头没被采信。依次检查：`velocity.toml` 的 `proxy-protocol` 是否为 `true`、HAProxy 是否配置了 `send-proxy`（v1）或 `send-proxy-v2`、HAProxy 的地址是否在 `whitelist.conf` 里、`/mikuproxy status` 的「代理」计数是否在增长。

**HAProxy 明明配好了，还是被拒绝？**
看控制台那条拒绝日志，以及 `/mikuproxy list`。最常见的原因是 HAProxy 与 Velocity 之间的实际连接来源地址和写进白名单的不一致（例如中间隔了一层 NAT 或容器网络），此时按实际对端地址放行。

**插件启动后完全没生效？**
用 `/mikuproxy status` 看「管道注入」是否为「已安装」、「`velocity.toml` 的 `proxy-protocol`」是否为「已启用」。两者任一不对，插件都不会改变连接处理方式。

**配置写错了会怎样？**
插件照常启动，出错的那一项回退默认值，问题以「第几行、什么问题」的形式打到控制台；`whitelist.conf` 同理，非法行只跳过自己。执行 `/mikuproxy reload` 时，这些问题会直接回显给执行命令的人，不必再去翻日志。

## 声明

本项目为 MikuMC 服务器原创插件，公开给大众免费使用，MikuMC 服务器 与作者 JunXieX 享有项目著作权，本项目非开源项目，请注意。

MikuMC 系列插件交流群：**1105054380**
