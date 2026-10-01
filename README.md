# cf-vpngate

> Cloudflare Worker：**前端 VLESS over WebSocket / XHTTP，后端 SSTP（VPN Gate 公共节点）+ ProxyIP 落地**。
> 原仓库 `CF-SoftEther` 的实验性 SSTP 出站代码，已按 [jacobax/snippets](https://github.com/jacobax/snippets) 的 `snippet.js` 全面重构（冲突处以上游 `snippet.js` 为准）。

它不是普通的 `WebSocket → connect() → 目标` 字节转发：当后端走 SSTP 时，Worker 会在脚本里完成 **SSTP 建链 → PPP(LCP/PAP/IPCP) 协商 → 拿到虚拟 IPv4 → 手工封装 IPv4/TCP**，再与目标通信。

---

## 目录

- [上下文摘要](#上下文摘要)
- [架构](#架构)
- [源码结构（src/）](#源码结构-src)
- [这次重构做了什么](#这次重构做了什么)
- [部署](#部署)
- [配置](#配置)
- [路径与参数](#路径与参数)
- [节点示例](#节点示例)
- [自助节点页 /sub](#自助节点页-sub)
- [VPN Gate 节点从哪来](#vpn-gate-节点从哪来)
- [ProxyIP 是什么](#proxyip-是什么)
- [协议实现细节](#协议实现细节)
- [UDP(53)](#udp53)
- [优化点](#优化点)
- [未包含的功能](#未包含的功能)
- [限制与已知问题](#限制与已知问题)
- [排障](#排障)
- [许可与鸣谢](#许可与鸣谢)

---

## 上下文摘要

> 本节是项目「分析 / 优化 / 部署测试」的压缩上下文，用于快速载入全局认知；具体细节见后续各章。

### 定位

- **是什么**：Cloudflare Worker，前端 **VLESS over WS / XHTTP**，后端**仅两种出站**：`SSTP`（VPN Gate 公共节点）+ `ProxyIP`（含 `域名!txt`）。
- **不是**普通 `WS → connect() → 目标` 转发：走 SSTP 时 Worker 内部完成 **SSTP over TLS → PPP(LCP/PAP/IPCP) → 虚拟 IPv4 → 手工 IPv4/TCP 封包**，再与目标通信。
- **来源/对齐基准**：由旧仓库 `CF-SoftEther` 重构而来，**冲突处一律以上游 [jacobax/snippets](https://github.com/jacobax/snippets) 的 `snippet.js` 为准**。
- **性质**：协议研究/学习代码，非稳定 VPN，不做可用性承诺。许可 GPL-3.0。

### 架构

```text
客户端(v2rayN/Xray/sing-box) --VLESS over WS 或 XHTTP-->
Cloudflare Worker
  ├─ 直连 connect(目标)                ← 默认兜底
  └─ 落地（仅两种）
       ├─ ProxyIP  connect(proxyip:443)，按 SNI 反代到目标
       ├─ SSTP     SSTP over TLS → PPP → 虚拟 IPv4 → 手工 TCP → 目标
       └─ 域名!txt  从 TXT 随机取一条上面两种地址
--> 目标站点
```

- **出站顺序默认**：**先落地 → 失败/超时 → 再直连**（不是先直连）。`global=1` 只走落地且关闭建连超时；`race=1` 并发竞速。
- **竞速「就绪」判定**：SSTP 候选须完成**隧道内 TCP 三次握手（拿到目标 SYN+ACK）**才算就绪；ProxyIP/直连只到 TCP 建连。竞速不发应用层请求。

### 源码结构与构建

- 唯一手写目录 `src/`，构建产出两个单文件：`worker.js` 可读版（~88 KB，wrangler 部署）与 `snippet.js` 压缩版（~31.5 KB，**仅体积对照，Snippets 跑不动**）。
- **约束**：合并后同作用域，**模块间不得有同名顶层标识符**（`npm run build` 后 `node --check` 会暴露）。
- 命令：`npm run build`（含 snippet ≤32KB 与语法校验）、`npm run check`（产物是否与 src 同步，不写文件）、`npm run deploy`（build + wrangler deploy）、`npm run dev`、`npm run tail`。

### 关键配置（`src/config.js` → `CONFIG`）

- `uuid=495c7195-85b8-498a-bf20-2ea9ce9175b5`（可用 Worker 变量 `UUID` 覆盖）；`proxyip=proxyip.example.com!txt`（**占位值，必须用 `fdip=` 给真实落地**）。
- **超时（据 2026-10 探针实测定，原 3000 有害）**：`dialTimeoutMs=4500`、`sstpConnectMs=5000`、`sstpHandshakeMs=1500`。
- SSTP：`mss=1400`（**不可调大**，伪首部缓冲固定 1432）、`sstpReuseTunnel=true`、`sstpMaxStreams=8`、`sstpRetransmit/RtoMs/MaxRetries=true/1000/5`。
- 队列/背压：`maxQueueBytes/maxQueueTotalBytes=8MB/32MB`、`wsBackpressureBytes/Release=256KB/64KB`、`dnAdaptive/dnAdaptiveBps=true/262144`。
- DNS：`dnsServer/dnsPort=1.1.1.1/53`、`dnsNegativeTtlMs=30000`、`dnsAnswerTtlMs=60000`（DoH 正缓存 3 分钟 + 并发去重）。
- 落地策略：`dialFailThreshold/Cooldown=3/30000`、`dialRaceCandidates=2`、`allowClientGlobal=true`、`blockedPorts=[]`。
- XHTTP：`xhttpPadding=true`、`xhttpPaddingHeader/Key=a290fd/_d8d344`、`xhttpPaddingRange=[100,1000]`、`xhttpStrictPadding=false`。
- `/sub` 访问控制：`subAuth='uuid'`（定长时间比较）/`off`/`none`；调试：`debug=false`。完整表见[配置](#配置)。

### 部署

- **方式一（推荐）**：`npm i && npx wrangler login && npm run deploy`（保留 `wrangler.toml`：`main=worker.js`、`compatibility_date=2026-09-25`）。
- **方式二**：Dashboard 新建 Worker → 快速编辑 → 粘贴 `worker.js` → 部署 → 绑自定义域。
- **方式三 Snippets：不可用，勿部署**（执行 5ms / 内存 2MB / 子请求 2~5 的限制，见[部署](#部署)）。
- ⚠️ **Snippet 与 Worker 同域会抢流量**（`Snippets → Worker`），表现为"两个都连不上"→ 去 规则→Snippets 删规则。
- ⚠️ 出现 **1101**：删旧片段/旧 Worker 后重新部署。

### 测试与部署验证

- `npm test`：`scripts/smoke.mjs` 纯逻辑冒烟（不需要 wrangler/网络），`cloudflare:sockets` 用 stub 顶替。
- `npm run test:exit-ip`：端到端断言「出口 IP 属 SSTP 节点网段」，5 步链（CSV `IP` 列取 `expectedIp` → 隧道内 DNS → 隧道内 HTTPS 取 `exitIp` → 本机直连取 `localIp` → 断言 `exitIp != localIp` 且同网段）。
- `npm run probe`：`scripts/sstp-probe.mjs`，用 **Node 原生 socket** 建隧道（能过 TUN），量各段耗时并给超时建议。
- **三条硬性注意**：
  1. **必须带 `global=1`**（脚本默认加），否则落地失败回落直连 → **假通过**。
  2. **本地 `wrangler dev` 连不上通常是网络而非代码**：workerd 的 `connect()` **不走 TUN**，本地失败**不能判定线上失败** → 用 `--url wss://...` 打线上 Worker。
  3. **SSTP crypto binding 节点不兼容 Worker**（含 `public-vpn-153`）：服务端要求 `CRYPT_BINDING_RESP`，Node 能算（`getPeerCertificate().raw`），**Workers 拿不到对端证书** → 卡建链。探针打 `⚠ 该节点要求 SSTP crypto binding` → **看到就换节点**。
- **实测出口（2026-10）**：本机 TUN 出口 `61.124.1.97`(ASN 2497)；`public-vpn-68/100.opengw.net` 隧道出口 `219.100.37.234/236`，与节点 IP **同 /24、同 ASN 36599**（节点做 NAT，出口≠接入，断言只能"同网段"）。
- **CSV vs API 字段别混用**：API `HostName`=短名（无域名）；CSV `Hostname`=完整域名，期望 IP 取自 CSV `IP` 列（不依赖 DNS）。判定逻辑见 `scripts/vpngate-csv.mjs` 的 `relationToNode()`。

### 优化点（已落地）

- 功能瘦身（入站仅 VLESS，出站仅 SSTP+ProxyIP）；XHTTP **先建连再返回响应**（失败给干净 `400/502`）；padding 对齐 edgetunnel。
- DNS 缓存+并发去重、负缓存、UDP(53) 应答缓存；TXT 列表缓存。
- 上行分片入队+出队合并；下行攒包 64KB + `bufferedAmount` 背压感知；BYOB 零拷贝读；SSTP 收包缓冲复用。
- **SSTP 隧道复用**（按 `user:pass@host:port` 分池，按目的端口分发；冷路径从"每次全量建链"降到"隧道内一次握手"）。
- 隧道内 TCP 可靠性修正（只收 `seq===ack`、窗口随缓冲变化+0 窗口背压、简化重传、读循环不设读超时）。
- checksum 32 位宽累加；XHTTP 首包预分配缓冲（避免 O(n²)）；UUID 前缀只校验一次；全局队列预算防叠加 OOM；半开连接 + 异常统一收口。完整列表见[优化点](#优化点)。

### 已知坑与限制

- **XHTTP 必须显式 `mode=stream-one`**：`mode` 空或 `auto` → Xray 按 `packet-up` 处理（仅 REALITY 自动变 stream-one），v2rayN 默认也是 `auto` → 下行 GET 被回 `204` → 日志 `unexpected status 204`，全盘失败。
- `noGRPCHeader` **必须 true**（本实现按裸 VLESS 头解析，否则 400）；`alpn=h2`。
- 只支持 TCP 目标，**UDP 仅 53**（转 TCP DNS）；Workers 无原生 UDP 出站。
- SSTP 本身只有 TCP → **TCP-over-TCP**，丢包双重重传放大。
- 不支持：XHTTP `packet-up/stream-up`、gRPC 帧、socks5/http(s)/turn(s) 落地、自适应 proxyip。
- 不依赖任何绑定（无 KV/DO/Cache API/env），缓存全是 isolate 级 `Map` → **不跨实例共享**，冷启动/多实例需重建。

---

## 架构

```text
客户端 (v2rayN / Xray / sing-box ...)
   │  VLESS over WebSocket  或  VLESS over XHTTP
   ▼
Cloudflare Worker  ── 本仓库
   │
   ├─ 直连（默认优先）：connect(目标)
   │
   └─ 落地（只有两种）：
        ├─ ProxyIP        → connect(proxyip:443)，由它按 SNI 反代到目标
        ├─ SSTP           → SSTP over TLS → PPP → 虚拟 IPv4 → 手工 TCP → 目标
        └─ 域名!txt        → 从 TXT 记录里随机取一条上面两种地址
   ▼
目标网站 / 目标服务器
```

SSTP 后端的完整链路：

```text
VLESS over WS/XHTTP
  → Cloudflare Worker
  → SSTP over TLS (SSTP_DUPLEX_POST)
  → PPP：LCP → PAP → IPCP
  → PPP 分配的虚拟 IPv4
  → 手工 IPv4 + TCP 封包（SYN / ACK / PSH / FIN、序号、窗口、校验和）
  → 目标 TCP 服务
```

---

## 源码结构（src/）

`src/` 是唯一手写的地方，构建会产出**两个单文件**：

| 产物 | 用途 | 体积 |
| --- | --- | --- |
| `worker.js` | 可读版（保留注释与换行），用于 wrangler 部署 / 人工阅读 | 约 88 KB |
| `snippet.js` | **压缩版**（esbuild 压缩 + 剔除调试日志），体积对照用 | 约 31.5 KB |

```bash
npm run build     # src/ → worker.js + snippet.js（snippet.js 超 32KB 或语法不合法会报错）
npm run check     # 只校验两个产物是否都与 src/ 一致（不写文件）
npm run deploy    # 先 build 再 wrangler deploy
```

> `snippet.js` 只是为「32KB 体积上限」做的压缩对照；**Snippets 因运行时限制（5ms 执行 / 2MB 内存）跑不动本项目的 SSTP 隧道，请只用 Worker 部署**（详见[部署](#部署)）。
> 本地告警线可用环境变量 `SNIPPET_LIMIT` 调整（默认 `32768`）。

| 模块 | 职责 |
| --- | --- |
| `src/config.js` | `CONFIG`、`XHTTP_HEADERS`、`XHTTP_EXTRA`、`log` |
| `src/utils.js` | 字节读写、拼接、校验和、UUID、资源释放 |
| `src/padding.js` | XHTTP padding 提取 / 校验 / 回填 |
| `src/net.js` | `tcpConnect`（`cloudflare:sockets`） |
| `src/dns.js` | DoH 解析（缓存 + 并发去重）、UDP(53) 转 TCP DNS |
| `src/sstp/client.js` | SSTP 建链 + PPP(LCP/PAP/IPCP) 协商 |
| `src/sstp/tcp.js` | PPP 之上的最小 IPv4/TCP 栈（一条流 = 一个目标连接） |
| `src/sstp/pool.js` | SSTP 隧道池（复用隧道承载多条流）+ 出站入口 |
| `src/outbound.js` | 落地地址解析与出站调度（SSTP / ProxyIP） |
| `src/vless.js` | VLESS 头解析、握手探测、Early Data、path 落地解析 |
| `src/queue.js` | 上行队列、下行攒包发送器、`pipeToWebSocket` |
| `src/ws.js` | VLESS over WebSocket 入站 |
| `src/xhttp.js` | VLESS over XHTTP 入站（仅 `mode=stream-one`） |
| `src/share.js` | `/sub`、`/uuid` 节点信息页 |
| `src/index.js` | Worker 入口 `fetch` |

约束：合并后所有模块处于同一作用域，**模块之间不能有同名顶层标识符**（`npm run build` 后 `node --check worker.js` 会发现）。

## 这次重构做了什么

| 项目 | 旧版 `CF-SoftEther` | 重构后 `cf-vpngate` |
| --- | --- | --- |
| 入站 | 仅 VLESS over WebSocket | **VLESS over WebSocket + VLESS over XHTTP**（`mode=stream-one`、Early Data、padding 混淆） |
| 后端 | 仅 SSTP（path 里写死 `sstp://`） | **只保留两种：SSTP + ProxyIP**（含 `域名!txt` 列表），统一调度 |
| DNS | 每次请求都打 DoH | DoH 结果缓存 3 分钟 + 同域名并发去重 |
| TXT 落地 | 无 | 支持 `域名!txt`，列表缓存，随机取一条 |
| 上行 | 逐条 `write` | 分片入队 + 出队合并，队列 8MB 上限，带反压 |
| 下行 | 逐块 `ws.send` | 攒包到 64KB + `bufferedAmount` 背压感知 + `scheduler.wait` 让出 |
| 读取方式 | 默认 reader | 优先 BYOB（零拷贝）读 |
| 半关闭 | 无 | `allowHalfOpen`，正确收发 FIN，收尾干净 |
| UDP | 不支持 | 53 端口（DNS）转成 TCP 上的 DNS 查询再回写 |
| 代码结构 | 一个函数流，缩写变量 | 14 个分区、命名函数、`CONFIG` 集中配置、异常统一收口 |
| 调试 | 满屏 `console.log` | `CONFIG.debug` 开关，默认关闭 |
| 部署形态 | 只能当 Worker | Worker（wrangler / Dashboard）；Snippets 受 5ms 执行时间 / 2MB 内存上限约束，**跑不动本项目的 SSTP 隧道** |

冲突处理原则：**凡是与上游 `snippet.js` 行为不一致的地方，以上游为准**（例如握手超时、early data 来源、`!txt` 处理顺序、xhttp 响应头、UDP/53 的 DNS 方案等）。

---

## 部署

### 方式一：Wrangler（推荐，可保留 `wrangler.toml`）

```bash
npm i
npx wrangler login
npm run deploy          # 等价于 wrangler deploy
```

### 方式二：Dashboard 新建 Worker

新建 Worker → 进入"快速编辑" → 把 `worker.js` 全文粘贴进去 → 保存并部署 → 绑定自定义域（或用 `*.workers.dev`）。

### 方式三：Cloudflare Snippets（⚠️ 不可用，请勿部署）

`npm run build` 仍会产出 `snippet.js`（32KB 以内），但 **Snippets 的运行时上限决定了它跑不动本项目**：

| Snippets 硬限制（官方） | 本项目需求 | 结果 |
| --- | --- | --- |
| 最大执行时间 **5 ms** | SSTP 建链 = TLS 握手 + PPP(LCP/PAP/IPCP) 协商，CPU 数百 ms 量级 | 必然被杀 |
| 最大内存 **2 MB** | 单连接上行队列上限就 8 MB，另有隧道池 / 收发缓冲 | 必然 OOM |
| 子请求数 2（Pro）/ 3（Business）/ 5（Enterprise） | 一次连接需多次出站（SSTP 建链、DNS、目标 TCP） | 不够用 |
| 无 `env` / KV / Cache API | 已按 isolate 内存缓存适配 | 仅此项适配成功 |

**请只用方式一 / 方式二部署 Worker。**

> ⚠️ 若你把 `snippet.js` 挂到了与 Worker **相同域名**上：执行顺序是 `Snippets → Worker`，
> Snippet 会**先执行并抢走请求**，导致 Worker 永远收不到流量——这正是"两个都连不上"的典型原因。
> 请到 规则 → Snippets 删除该规则。

> 若出现 1101，请删掉旧片段/旧 Worker 后重新部署（新代码会触发代码检测）。

---

## 配置

所有可调项集中在 `CONFIG`（`worker.js` 与 `snippet.js` 顶部都是同一份，源头在 `src/config.js`）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `uuid` | `495c7195-85b8-498a-bf20-2ea9ce9175b5` | VLESS UUID。可用 Worker 变量 `UUID` 或全局变量 `UUID` 覆盖 |
| `proxyip` | `proxyip.example.com!txt` | 默认落地。只支持 `1.2.3.4:443` / `[v6]:443` / `域名` / `域名!txt` / `sstp://host:443` |
| `chunk` | `65536` | socket → WebSocket 读块大小 |
| `dnPack` / `dnTail` / `dnMs` | `65536` / `2048` / `2` | 下行攒包上限、剩余空间阈值、延迟冲刷毫秒 |
| `upPack` | `65536` | 上行入队分片大小 |
| `maxED` | `8192` | Early Data 最大长度 |
| `hsMax` / `xhInit` / `xhNext` | `16384` / `32768` / `8192` | XHTTP 握手头最大等待字节、首读与后续读字节数 |
| `xhttpHeaderTimeout` | `15000` | XHTTP 等待客户端首包（VLESS 头）的毫秒数 |
| `xhttpPadding` | `true` | 是否在响应头回填 padding |
| `xhttpPaddingHeader` / `xhttpPaddingKey` | `a290fd` / `_d8d344` | padding 的头名 / 键名，需与客户端 extra 一致 |
| `xhttpPaddingRange` | `[100, 1000]` | padding 长度区间，对应 extra 的 `xPaddingBytes` |
| `xhttpStrictPadding` | `false` | 是否校验请求 padding 长度（严格模式） |
| `mss` | `1400` | SSTP 隧道内 TCP 分片（**不要超过 1400**，受伪首部缓冲区 1432 限制） |
| `dialTimeoutMs` | `4500` | **建连超时**：落地与直连都受它约束。默认「先落地 → 超时 → 再直连」，超时即切换；`global=1` 时该值被置 0（不设超时）。4500 来自实测，见[实测超时参数](#实测超时参数npm-run-probe) |
| `wsHandshakeTimeout` | `15000` | WebSocket 入站等待 VLESS 头的最长毫秒数 |
| `sstpConnectMs` | `5000` | SSTP 建链（TCP+TLS → SSTP → PPP）总超时；实测 p95 ≈ 2.9s，留约 1.7 倍余量 |
| `sstpHandshakeMs` | `1500` | 隧道内 TCP 三次握手超时；实测 0.4~0.6s，取 3 倍 |
| `sstpReuseTunnel` | `true` | **SSTP 隧道复用**开关；关闭则一连接一隧道（旧行为） |
| `sstpMaxStreams` | `8` | 单条隧道最多并发多少条目标 TCP 流（超过再开一条隧道） |
| `sstpIdleMs` / `sstpStreamIdleMs` | `60000` / `300000` | 隧道空闲回收 / 有流但无数据的兜底回收 |
| `sstpBufferBytes` | `262144` | 隧道内接收缓冲上限，配合窗口通告做背压 |
| `sstpWindowBytes` | `65535` | 通告给对端的最大窗口 |
| `dialFailThreshold` / `dialFailCooldownMs` | `3` / `30000` | 落地连续失败 N 次后进入冷却，冷却期内跳过落地直接直连（避免每个请求都白等 `dialTimeoutMs`） |
| `sstpRetransmit` / `sstpRtoMs` / `sstpMaxRetries` | `true` / `1000` / `5` | 简化重传：未确认段超时重发 |
| `maxQueueBytes` / `maxQueueTotalBytes` | `8388608` / `33554432` | 单连接上行队列上限 / **全局队列总预算**（防并发叠加 OOM） |
| `queueWakeBytes` / `queueDrainBytes` | `1048576` / `262144` | 上行队列触发 / 解除反压的水位 |
| `wsBackpressureBytes` / `wsBackpressureReleaseBytes` | `262144` / `65536` | 下行 `bufferedAmount` 的等待 / 恢复水位 |
| `dnAdaptive` / `dnAdaptiveBps` | `true` / `262144` | 下行自适应：低吞吐（交互流量）立即冲刷，高吞吐才攒包 |
| `dnsNegativeTtlMs` | `30000` | DoH 解析失败的负缓存，避免反复查询放大 |
| `dnsAnswerTtlMs` | `60000` | UDP(53) 转发结果的缓存 |
| `subAuth` | `'uuid'` | 节点页访问控制：`uuid` 需带正确 UUID / `off` 关闭 / `none` 不校验 |
| `dialRaceCandidates` | `2` | 竞速（`?race=1`）时最多并发几个落地候选（从 `域名!txt` 列表取） |
| `allowClientGlobal` | `true` | 是否允许请求方用 header/query 的 `global=1` 强制走落地 |
| `blockedPorts` | `[]` | 禁止代理的目标端口（如 `[25, 445]`） |
| `sstpUser` / `sstpPass` | `vpn` / `vpn` | PPP 的 PAP 认证（VPN Gate 公共节点固定为 `vpn`/`vpn`） |
| `dnsServer` / `dnsPort` | `1.1.1.1` / `53` | UDP(53) 转发的 TCP DNS 服务器 |
| `debug` | `false` | 打开后输出 `[cf-vpngate]` 前缀日志，配合 `wrangler tail` 查看 |

Worker 环境变量：`UUID`（可选）。其余全部走 path 传入，改落地不用重新部署。

---

## 路径与参数

```text
/fdip=<落地地址>?ed=2560[&global=1][&race=1]
```

- `fdip`：键名可任意（如 `proxy`、`p`、`1234`），值就是落地地址；
- `ed=2560`：Early Data，客户端侧参数，**放最后**；
- `global=1`：**只走落地**，不回落直连，且建连超时被关闭（见[出站顺序](#出站顺序落地--直连)）；
- `race=1`：并发竞速拨号，直连 / 落地 / 多个落地候选同时拨，谁先就绪用谁（不写就是串行，默认行为）。

```text
/fdip=sstp://219.100.37.196:443?ed=2560
/fdip=sstp://219.100.37.196:443?ed=2560&race=1
```

落地地址写法（只有两种出站）：

| 写法 | 含义 |
| --- | --- |
| `1.2.3.4:443`、`[2001:db8::1]:443` | ProxyIP 直连 |
| `proxy.example.com` | ProxyIP 直连（默认 443） |
| `sub.example.com!txt` | 取该域名 TXT 记录里的一条地址（逗号/换行分隔，随机选） |
| `sstp://host:443` | SSTP（VPN Gate / SoftEther），默认 `vpn:vpn` |
| `sstp://user:pass@host:443` | 自定义 PAP 认证的 SSTP |

`socks5://`、`http(s)://`、`turn(s)://` 等写法已不再支持，写了会被当成无效落地并返回失败。

示例：

```text
/fdip=sstp://219.100.37.196:443?ed=2560
/fdip=vpn1234.opengw.net:443?ed=2560
/fdip=1.2.3.4:443?ed=2560&global=1
/fdip=william.us.ci!txt?ed=2560
```

---

## 节点示例

### VLESS over WebSocket

```text
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@www.shopify.com:443?path=%2Ffdip%3Dsstp%3A%2F%2Fvpn1234.opengw.net%3A443%3Fed%3D2560&security=tls&encryption=none&host=vless.example.com&fp=chrome&type=ws&allowInsecure=0&sni=vless.example.com#cf-vpngate-ws
```

### VLESS over XHTTP

```text
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@www.shopify.com:443?mode=stream-one&path=%2Ffdip%3Dsstp%3A%2F%2Fvpn1234.opengw.net%3A443%3Fed%3D2560&security=tls&alpn=h2&encryption=none&host=vless.example.com&fp=chrome&type=xhttp&allowInsecure=0&sni=vless.example.com#cf-vpngate-xhttp
```

其中：

| 字段 | 说明 |
| --- | --- |
| `path` | URL 编码后的 `/fdip=<落地>?ed=2560` |
| `host` / `sni` | Worker 自己的域名 |
| `mode=stream-one` | **必须是 `stream-one`**（一次 POST 承载一个完整会话） |
| `alpn=h2` | XHTTP 走 h2，与 `mode` 搭配 |
| `ed=2560` | 与客户端 Early Data 长度一致 |

### 客户端 xhttp extra 怎么填

打开客户端的 XHTTP 传输设置，把下面这段填进 **extra** 文本框（V2rayN / NekoBox / sing-box 里可能是 `Extra` 或 `extra`），并且xhttp模式必须是stream-one：

```json
{
  "noGRPCHeader": true,
  "xPaddingObfsMode": true,
  "xPaddingMethod": "tokenish",
  "xPaddingPlacement": "queryInHeader",
  "xPaddingHeader": "a290fd",
  "xPaddingKey": "_d8d344"
}
```

逐项说明：

| 字段 | 是否必填 | 说明 |
| --- | --- | --- |
| `noGRPCHeader` | **必填 `true`** | 关掉 gRPC 的 5 字节帧头。本实现按「裸 VLESS 头」解析请求体，**不填会直接返回 400** |
| `headers.Content-Type` | 建议填 | 设成 `application/octet-stream`，与节点模板保持一致 |
| `xPaddingBytes` | 可选 | padding 长度范围，对应 Worker 的 `xhttpPaddingRange`（示例未列出，用客户端默认值即可） |
| `xPaddingObfsMode` | 必填 `true` | 开启 padding 混淆；Worker 会校验请求 padding 并在响应头回填 padding |
| `xPaddingMethod` | 必填 | 固定 `tokenish` |
| `xPaddingPlacement` | 必填 | 固定 `queryInHeader`：padding 放 query 里，query 再放进 header |
| `xPaddingHeader` | 必填 | 承载 padding 的请求头名，示例为 `a290fd`；**必须与 Worker 的 `xhttpPaddingHeader` 一致** |
| `xPaddingKey` | 必填 | padding 的 query 参数名，示例为 `_d8d344`；**必须与 Worker 的 `xhttpPaddingKey` 一致** |

不想手抄的话，直接 `curl https://你的域名/sub` 就能拿到这段 JSON 和对应节点链接。

服务端对 padding 的处理（对齐 edgetunnel）：

1. 从 `a290fd` 请求头里取值，兼容 `?_d8d344=` 直接放 query、纯值 header，以及 edgetunnel 由 UUID 派生的头名/键名（默认 UUID 对应 `95c719` / `_ea9ce9`）；
2. `xhttpStrictPadding = true` 时校验长度落在 `xhttpPaddingRange`，不合法直接 `400`；
3. 响应头回填一个 100–1000 字符的随机 padding：`a290fd: https://x.invalid/?_d8d344=<随机串>`。

### 支持的 XHTTP 形态与错误码

| 项 | 情况 |
| --- | --- |
| `mode=stream-one` | ✅ 支持（**必须显式指定**） |
| `mode=packet-up` / `stream-up` | ❌ 不支持：它们用「一条 GET 下行 + 多个 POST 上行」并且要靠跨请求会话表关联，Worker 侧不维护会话 |
| gRPC 帧（`noGRPCHeader: false`） | ❌ 不支持，首包解析失败返回 `400` |
| 请求路由 | 任意 `POST` 都按 XHTTP 处理（与 edgetunnel 一致），`GET /sub` 除外 |
| 首包解析失败 / UDP 非 53 / padding 非法 | `400`，响应体里带具体原因 |
| 落地建连失败 | `502` |

> 建连在返回响应**之前**完成，因此失败时客户端拿到的是干净的 `400` / `502`，而不是一条被中断的流；
> 这条路径与 edgetunnel 的 `处理叉HTTP请求` 一致。

#### ⚠️ 最容易踩的坑：不写 mode 就是 packet-up

Xray 的 `mode` 为空或 `auto` 时并不是"自动挑一个能用的"，而是**直接按 packet-up 处理**：

```go
// Xray-core transport/internet/splithttp/dialer.go
mode := transportConfiguration.Mode
if mode == "" || mode == "auto" {
    mode = "packet-up"
    if realityConfig != nil {   // 只有 REALITY 才会自动变成 stream-one
        mode = "stream-one"
        if transportConfiguration.DownloadSettings != nil { mode = "stream-up" }
    }
}
```

而 v2rayN 的 `mode` 下拉默认值也是 `auto`（`Global.DefaultXhttpMode = "auto"`）。所以：

- **手工在 v2rayN 里建节点**时，如果不手动把"模式"选成 `stream-one`（TLS 场景），客户端会用 packet-up；
- packet-up 的下行是一条 `GET ...?x_session=<id>` 长连接请求，Worker 对非 POST/WS 请求只回 `204`；
- 客户端日志就会出现：`transport/internet/splithttp: unexpected status 204`，随后 DNS 查询、网页全部失败。

典型日志：

```text
[Info] transport/internet/splithttp: XHTTP is dialing to tcp:1.2.3.4:443, mode packet-up, HTTP version 2, host your.worker.domain
[Info] transport/internet/splithttp: unexpected status 204
[Error] app/dns: failed to retrieve response for xxx > Post "https://...": io: read/write on closed pipe
```

**处理办法**：把节点（或分享链接）的 `mode` 显式改成 `stream-one`。
本仓库 `/sub` 生成的 xhttp 链接里已经带了 `mode=stream-one`，直接用它导入最省事。

---

## 自助节点页 /sub

访问 Worker 的 `/sub` 或 `/uuid`（GET）会返回纯文本节点信息，自动使用请求的 `Host`。
**默认需要携带正确 UUID**（`CONFIG.subAuth = 'uuid'`），否则返回 404——避免节点页被公开扫描后变成开放代理。

UUID 三种给法（任一命中即可）：

```bash
curl https://your-worker.example.com/<UUID>/sub
curl https://your-worker.example.com/sub?uuid=<UUID>
curl -H 'X-Uuid: <UUID>' https://your-worker.example.com/sub
```

换落地照旧（记得带上 uuid）：

```bash
curl 'https://your-worker.example.com/sub?sstp=sstp://vpn1234.opengw.net:443&uuid=<UUID>'
curl 'https://your-worker.example.com/sub?proxy=1.2.3.4:443&uuid=<UUID>'
```

| `CONFIG.subAuth` | 行为 |
| --- | --- |
| `'uuid'`（默认） | 需携带正确 UUID；比较用定长时间算法，防时序侧信道 |
| `'off'` | 节点页整体关闭（一律 404） |
| `'none'` | 不校验（**等于把 UUID 公开**，仅临时调试用） |

输出包含：ws 链接、xhttp 链接、以及可直接复制的 xhttp extra。
其它任何非代理请求一律返回 `204`，不暴露页面。

---

## VPN Gate 节点从哪来

VPN Gate 是筑波大学维护的公共 VPN 中继项目，服务器由志愿者提供，列表实时变化。

- 官网：<https://www.vpngate.net/>
- 英文页：<https://www.vpngate.net/en/>
- 公共 Relay 列表：<https://www.vpngate.net/en/volunteer_servers.aspx?number=0>

用法：在列表里挑一个 **支持 MS-SSTP（SoftEther）** 的节点，把它的主机名或 IP（推荐 443 端口）填成 `sstp://host:443`，放进 path 的 `fdip=` 后面即可。

注意：

- 节点质量/可用性/出口地区随时变化，失效就换一个；
- 优先选 443 端口（Cloudflare 出站对部分端口有限制）；
- 公共节点的带宽和稳定性不保证，仅适合研究与轻量使用；
- 认证固定为 `vpn` / `vpn`，个别节点不同则用 `sstp://user:pass@host:port` 指定。

---

## ProxyIP 是什么

ProxyIP 指"可访问 Cloudflare CDN 内容的 Cloudflare 官方 IP"。Worker 直连该 IP 后，把客户端原始流量（TLS ClientHello，SNI 指向真正的目标）交给它，由该 IP 所在机房按 SNI 反代到目标站点——相当于把"落地机房"固定下来。

- 走 ProxyIP 时，代码里是 `connect(proxyip)`，**不会**去连客户端请求的目标；
- `global=1` 才会强制走 ProxyIP；默认先直连，失败再回落；
- `域名!txt` 形式会从 TXT 记录里随机取一条，适合维护一批 ProxyIP。

---

## 协议实现细节

### SSTP 建链

```text
SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1
Host: <sstp-host>
Content-Length: 18446744073709551615
SSTPCORRELATIONID: {<uuid>}
```

### PPP 协商

```text
SSTP Connect Request → SSTP Connect Ack
LCP  Configure-Request(MRU 1500) → Configure-Ack
PAP  Authenticate-Request(vpn/vpn) → Authenticate-Ack
IPCP Configure-Request(IP 0.0.0.0) → Configure-Nak(分配 IP) → Configure-Request(IP) → Configure-Ack
→ 拿到虚拟 IPv4
```

### 手工 TCP

```text
SYN → ← SYN+ACK → ACK → PSH+ACK(数据) … → FIN+ACK → ← FIN+ACK
```

代码维护：源端口、seq/ack、IPv4 首部、TCP 首部、IPv4 校验和、TCP 伪首部校验和、MSS 分片；收到 FIN 时关闭读方向并 ACK，写方向等上层 `close()` 再发 FIN（半关闭）。

### SSTP 隧道复用（延迟优化）

旧版每来一个连接都要重跑一遍完整建链（TCP+TLS → SSTP_DUPLEX_POST → LCP → PAP → IPCP → 隧道内 TCP 三次握手），
全部串行 `await`，冷路径动辄数秒。现在同一 isolate 内按「SSTP 服务器」复用 PPP 隧道：

```text
第 1 条连接：TLS → SSTP → PPP → 虚拟 IP → 隧道内 TCP 三次握手
第 N 条连接：直接复用隧道 → 隧道内 TCP 三次握手（≈1 个 RTT）
```

- 隧道按 `user:pass@host:port` 分池，读循环唯一消费 SSTP buffer，按**目的端口**把包分发到各条流；
- 每条流独立 seq/ack、独立窗口与缓冲，互不影响；
- `sstpMaxStreams` 满则再开一条隧道，保持并发能力；
- 空闲 `sstpIdleMs` 后自动回收；出错立即销毁并从池中移除；
- `CONFIG.sstpReuseTunnel = false` 可退回「一连接一隧道」。

### SSTP 只有 TCP

1. **SSTP 协议本身只有 TCP**：SSTP = PPP over TLS over TCP（微软 MS-SSTP，443），
   握手就是一条 `SSTP_DUPLEX_POST` 的 HTTPS 请求，不存在「SSTP over UDP」。
2. **VPN Gate 节点的 TCP/UDP 是不同协议**（MS-SSTP / SoftEther SSL-VPN 走 TCP 443，
   OpenVPN 走 TCP+UDP 1194，L2TP/IPsec 走 UDP 500/4500），想走 UDP 就得实现
   OpenVPN 或 IPsec(IKEv2+ESP) 协议栈，不是给 SSTP 换个 socket 类型。
3. **Cloudflare Workers / Snippets 没有 UDP 出站能力**：`cloudflare:sockets` 的 `connect()` 只提供 TCP。
   这正是本仓库"UDP 只支持 53 端口、且必须转成 TCP DNS 才能出去"的原因。

所以代码里**没有任何 UDP 分支**——SSTP 出站固定 TCP。这属于 **TCP-over-TCP**，
丢包时会双重重传放大，缓解手段是：按序 seq 校验、简化重传（`sstpRtoMs`）、
窗口通告背压、以及用隧道复用摊掉建链成本。

### 并发竞速拨号（`race=1`）

不能"TCP 与 UDP 竞速"，就把竞速用在当前真正可用的维度上：

```text
候选 A：直连目标
候选 B：落地 1（!txt 列表里随机取）
候选 C：落地 2（!txt 列表里另取一条）
        ↓ 同时拨，谁先「就绪」用谁，其余立刻关闭
```

**「就绪」的判定很重要**（对应"谁先传回实际数据、非握手信息"）：

| 候选 | 判定点 |
| --- | --- |
| SSTP 落地 | `sstpConnect()` 返回前已完成**隧道内 TCP 三次握手**，即**拿到了目标的 SYN+ACK** —— 这是真实数据，不只是 SSTP/PPP 握手成功 |
| ProxyIP / 直连 | 只到 TCP 连接建立（目标是后端按 SNI 反代的，无法提前验证） |

也就是说竞速时 SSTP 候选的门槛反而更严格，赢下它意味着**端到端真的通了**。
竞速不会重复发应用层请求（不会让目标看到两条连接），只到握手为止。

**开关就是请求参数本身，没有 CONFIG 开关**：写 `?race=1`（或 `X-Race: 1` 头）就竞速，不写就走默认的「先直连，失败再串行回落落地」。
候选数量由 `CONFIG.dialRaceCandidates`（默认 2）控制。

### 隧道内 TCP 的可靠性修正

| 项 | 旧行为 | 现在 |
| --- | --- | --- |
| 乱序 / 重传段 | 不校验 seq，直接当新数据写进上层（**会损坏数据**） | 只接受 `seq === ack` 的段，其余丢弃并回 ACK |
| 背压 | 窗口固定 65535，缓冲无上限 | 窗口随接收缓冲变化，缓冲满通告 0 窗口；消费后主动发窗口更新 |
| 丢包 | 无重传，一次丢包即卡死 | 未确认段按 `sstpRtoMs` 重发，超过 `sstpMaxRetries` 断开 |
| 读超时 | `readPacket(60s)` 超时后残留的 pending read 会破坏 buffer 连续性 | 隧道读循环不设读超时（传 0），空闲回收交给看门狗 |

---

## UDP(53)

VLESS 的 UDP 只处理 **53 端口（DNS）**：Worker 把 DNS 查询包通过 TCP 发给客户端指定的 DNS 服务器（一般 `1.1.1.1:53`，解析不出时回落到 `CONFIG.dnsServer`），拿到带长度前缀的应答后原样回写给客户端。其它 UDP 目标直接断开（Worker 环境无原生 UDP 出站）。

---

## 优化点

1. **只留必要功能**：入站只有 VLESS（ws + xhttp），出站只有 SSTP + ProxyIP；去掉 trojan/ss 入站与 ss2022 加解密、socks5/http(s)/turn(s) 落地、并发竞速拨号与自适应 proxyip（`auto=1/2`），文件更短、冷启动更快、内存更省；
2. **XHTTP 先建连再返回响应**：落地失败直接 `502`，首包/padding 非法直接 `400`，不再给客户端一条被中断的流；
3. **XHTTP padding 对齐 edgetunnel**：请求侧提取 + 严格模式校验 + 响应侧回填随机 padding，obfs 行为与客户端 extra 匹配；
4. **DNS 缓存 + 并发去重**：同一域名 3 分钟内复用，并发请求共用一个查询；
5. **TXT 列表缓存**：`!txt` 落地不会每连接都解析一次；
6. **上行分片入队 + 出队合并**：把大量小 WebSocket 帧合并成 64KB 大包再写入 socket；
7. **下行攒包 + 背压**：`bufferedAmount` 超阈值时用 `scheduler.wait` 让出事件循环，避免堆积导致内存飙升；
8. **BYOB 读**：`getReader({ mode: 'byob' })` 直接读到复用缓冲区，少一次拷贝；
9. **SSTP 收包缓冲区复用**：`ArrayBuffer` 在多次 `readAtLeast` 间复用；
10. **超时统一**：WS/XHTTP 首包等待超时、SSTP 握手 10s、长连接等待 60s，避免 Worker 空转；
11. **半开连接**：`allowHalfOpen` + FIN 处理，落地侧先关闭时也能把残余数据回传；
12. **异常收口**：`dialOutbound` 失败统一返回 `null`，所有路径 `try/catch`，`fetch` 一律返回合法 `Response`；
13. **配置集中**：`CONFIG` 一处可调，日志用 `CONFIG.debug` 开关；
14. **路径解析简化**：`parsePathProxy()` 只认 `sstp://` 与 ProxyIP 两种值，不再解析内嵌 query；
15. **建连超时**：`dialTimeoutMs`（默认 3s）约束直连与落地建连，超时立刻回落，首包延迟可控；
16. **SSTP 隧道复用**：见上文，冷路径从「每次全量建链」降到「隧道内一次握手」；
17. **checksum 32 位宽累加**：每轮处理 4 字节，循环次数减半（已用参考实现做等价性测试）；
18. **缓冲复用 / 减少拷贝**：XHTTP 首包用预分配缓冲累积（旧版每片 `concat` 是 O(n²)）；BYOB buffer 只在 byob 分支重建；`frame()` 不再每次新建 `DataView`；
19. **UUID 前缀只校验一次**：多帧 Early Data 时不重复比对前 16 字节；padding 头名/键名随 uuid 缓存；
20. **全局队列预算**：在单连接上限之外加一层 isolate 级总预算，多并发不再叠加吃内存；
21. **DNS 缓存补齐**：DoH 加负缓存、UDP(53) 转发结果加应答缓存，显著减少建连与查询放大；
22. **XHTTP 的 DNS 并发**：同批查询并发执行、按序回写（旧版逐条 await，延迟叠加）。

---

## Snippets 适配约束

> ⚠️ 下列约束源自上游 `snippet.js`（历史遗留）：代码风格上"能整段粘贴进 Snippets"，
> 但 Snippets 的 **5ms 执行时间 / 2MB 内存** 上限决定了它**跑不了本项目的 SSTP 隧道**，实际请只用 Worker。
> 保留这些约束的好处是：不依赖任何绑定，Worker 冷启动更轻、可单文件部署。

代码刻意**不使用**任何 Snippets 没有的能力：

| 不用 | 原因 |
| --- | --- |
| KV / Durable Objects / Cache API | Snippets 无绑定；所有缓存都是 isolate 级 `Map`（DNS、TXT、padding、隧道池） |
| 环境变量 / secrets | Snippets 无 `env`；UUID 走 `CONFIG.uuid` 或全局 `UUID` |
| 动态 `import()` 分块加载 | Snippets 是单文件；因此 `src/` 的多模块由 `scripts/build.js` 合并成单文件 |
| 源码体积超过 32KB | 上游按 **32KB 上限**组织代码，故构建额外产出压缩版 `snippet.js`（esbuild 压缩 + 剔除调试日志 + UTF-8 保留中文） |
| `IdentityTransformStream` 等较新全局 | 保留 `TransformStream` 回退 |

代价：isolate 级缓存**不跨实例共享**，冷启动/多实例时 DNS 与隧道需要重建。
这也是 `sstpReuseTunnel` 与 `dnsTtlMs` 存在的意义——尽可能在同一个 isolate 的生命周期内摊掉这些开销。

## 测试

```bash
npm test             # node scripts/smoke.mjs：纯逻辑冒烟，不需要 wrangler / 网络
npm run test:exit-ip # node scripts/exit-ip.mjs：端到端验证「隧道出口 IP 属于 SSTP 节点网段」
npm run build        # 顺带校验 snippet.js 体积（≤32KB）与语法（node --check）
npm run check        # 校验 worker.js 与 snippet.js 是否都与 src/ 同步
```

覆盖：checksum 优化等价性、seq 回绕比较、隧道内 TCP 栈（建帧 / 握手 / 收包 / 乱序丢弃 / MSS 分片、
重传沿用原始 seq 且携带当前 ack）、落地与 path 解析、VLESS 头解析、`/sub` 访问控制、竞速拨号。
`cloudflare:sockets` 用 stub 顶替（写到 `CACHE_DIR`）。

### 出口 IP 一致性（npm run test:exit-ip）

`npm test` 只跑纯逻辑，证明不了「流量真的从 SSTP 节点出去了」——落地失败时 Worker 会**回落直连**，
于是请求照样成功，但出口 IP 是本机/边缘的。`scripts/exit-ip.mjs` 补上这个端到端断言：

```bash
npm run test:exit-ip                                    # 打本地 wrangler dev
node scripts/exit-ip.mjs --node public-vpn-68.opengw.net:443   # 期望 IP 取自 vpngate.csv
node scripts/exit-ip.mjs --csv ../vpngate/vpngate.csv --check-dns
node scripts/exit-ip.mjs --url wss://your-worker.workers.dev   # 打线上 Worker
```

断言链（除对照组外全部在隧道内完成）：

| 步骤 | 动作 | 期望 |
| --- | --- | --- |
| ① | 从 **`vpngate.csv` 的 `IP` 列**取该节点 IP（不再依赖 DNS） | 得到 `expectedIp` |
| ② | 隧道内 DNS（VLESS TCP → `1.1.1.1:53` 的 DNS-over-TCP）解析 `api.ip.sb` | 得到 `apiIp`（顺带证明隧道内 DNS 可用） |
| ③ | 隧道内 HTTPS（连 `apiIp:443` + TLS，SNI=`api.ip.sb`）访问 `/ip` | 得到 `exitIp` |
| ④ | 对照：本机直连同一接口 | 得到 `localIp` |
| ⑤ | 断言 | `exitIp != localIp` 且 `exitIp` 与 `expectedIp` **同网段** |

为什么期望值取自 CSV 而不是隧道内 DNS：CSV 的 `Hostname` 与 `IP` 是同一行的两列，节点该是哪个 IP
是确定值；把 DNS 当成断言前提等于多引入一个失败点（受限网络里域名解析未必可用）。`--check-dns`
可额外做一次隧道内解析做交叉比对，不一致只告警、不判失败。

两个必须注意的点：

- **必须带 `global=1`**（脚本默认加）。不带时 Worker 落地失败会回落直连，测试会「假通过」。
  传 `--no-global` 可关掉，仅用于排查。
- **本地 `wrangler dev` 连不上节点，通常是网络而不是代码**：本机若在受限网络里（到 SSTP 节点
  必须经 TUN 或 `127.0.0.1:1080` 代理），Node 走系统路由会经过 TUN 所以能连，而 `wrangler dev`
  里 workerd 的 `connect()` 不走 TUN，于是本地必然连不上（裸 IP 快速失败 `cannot connect to
  the specified address`，域名挂到超时 `sstp: connect timeout`）。**本地不通过不能判定线上失败**，
  请用 `--url` 打线上 Worker；想在本地拿到结论，用下面的 `--exit-ip`。

### 隧道出口 IP 对比（探针 `--exit-ip`）

本地 workerd 连不上节点时，用探针绕开 workerd：它用 **Node 原生 socket** 建隧道（能过 TUN），
在隧道内访问 `https://api.ip.sb/ip`，再与 `vpngate.csv` 里该节点的 IP 对比。

```bash
node scripts/sstp-probe.mjs sstp://public-vpn-68.opengw.net:443 --exit-ip
node scripts/sstp-probe.mjs sstp://public-vpn-68.opengw.net:443 --exit-ip --api api.ip.sb --csv ../vpngate/vpngate.csv
```

2026-10 实测（本机经 TUN 的直连出口为 `61.124.1.97`，ASN 2497 IIJ）：

| 节点 | 接入 IP（CSV） | 隧道出口 IP | 关系 |
| --- | --- | --- | --- |
| `public-vpn-68.opengw.net` | `219.100.37.17` | `219.100.37.234` | 同 /24 |
| `public-vpn-100.opengw.net` | `219.100.37.57` | `219.100.37.236` | 同 /24 |

出口 IP 与节点 IP 同属 **ASN 36599（SoftEther Telecommunication Research Institute）**，
即确实从 VPN Gate 出口池出去，只是**节点做了 NAT，出网地址不等于接入地址**。
所以断言是「同网段 + 不等于本机直连」，相等只是更强的情形——写成 `exitIp === nodeIp` 会误判。
判定逻辑见 `scripts/vpngate-csv.mjs` 的 `relationToNode()`。

关于节点主机名：VPN Gate 的**两种数据源字段不一样**，别混用——

| 数据源 | 字段 | 值 |
| --- | --- | --- |
| API（`api/iphone/`） | `HostName` | `public-vpn-68`（短名，**无域名**） |
| CSV（`vpngate.csv`） | `Hostname` | `public-vpn-68.opengw.net`（**完整域名**） |

CSV 里的域名可正常解析（`public-vpn-68.opengw.net` → `219.100.37.17`），但 `exit-ip.mjs` 的期望 IP
直接取自 CSV 的 `IP` 列，不依赖解析结果；`--node` 传域名还是裸 IP 只影响步骤 ① 的来源标注。

## 实测超时参数（npm run probe）

`dialTimeoutMs` / `sstpConnectMs` / `sstpHandshakeMs` 不该拍脑袋定。用探针连真实节点量一遍：

```bash
node scripts/sstp-probe.mjs sstp://vpn1234.opengw.net:443
node scripts/sstp-probe.mjs sstp://vpn1234.opengw.net:443 --n 5 --streams 3 --target www.example.com
node scripts/sstp-probe.mjs sstp://public-vpn-68.opengw.net:443 --exit-ip   # 隧道出口 IP vs vpngate.csv
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--n` | `3` | 建几条独立隧道（每条都是一次完整冷启动） |
| `--streams` | `3` | 每条隧道内开几条流（第 2 条起测的是**复用**耗时） |
| `--target` / `--target-port` | `www.example.com` / `443` | 隧道内握手的目标 |
| `--timeout` | `30000` | 单步超时（防挂死） |

输出示例：

```text
第 1 轮  dns=15  tcp=210  tls=140  sstp=830  inner=260  reuse=[95, 88]  冷启动合计=1440 ms
第 2 轮  dns=0   tcp=195  tls=130  sstp=790  inner=240  reuse=[90, 92]  冷启动合计=1355 ms

—— 实测建议（p95 × 安全系数，向上取整到 100ms）——
  sstpConnectMs   ≈ 1800    // TCP+TLS+SSTP 建链
  sstpHandshakeMs ≈ 800     // 隧道内握手
  dialTimeoutMs   ≈ 300     // 隧道常热时：reuse × 3
                  ≈ 1700    // 隧道常冷时：冷启动 × 1.2
```

### 实测样本：public-vpn-153.opengw.net

```
第 1 轮  dns=13  tcp=7   tls=997   sstp=1684  inner=403  reuse=[438, 413]  冷启动合计=3091 ms
第 2 轮  dns=1   tcp=3   tls=965   sstp=1982  inner=414  reuse=[435, 487]  冷启动合计=3364 ms
第 3 轮  dns=2   tcp=3   tls=1199  sstp=1727  inner=456  reuse=[417, 574]  冷启动合计=3385 ms

  sstpConnectMs   ≈ 4500   // TCP+TLS+SSTP：p95 2.95s
  sstpHandshakeMs ≈ 1400   // 隧道内握手：p95 0.46s
  dialTimeoutMs   ≈ 1800   // 隧道常热（reuse p95 0.57s × 3）
                  ≈ 4100   // 隧道常冷（冷启动 p95 3.39s × 1.2）
```

据此把默认值调成 `dialTimeoutMs = 4500`、`sstpConnectMs = 5000`、`sstpHandshakeMs = 1500`。
**注意原来的 3000 是有害的**：实测冷启动就要 3.1~3.4s，3s 会让 SSTP 冷启动 100% 超时回落到直连。

### ⚠️ 节点兼容性：SSTP crypto binding

部分节点（**含 public-vpn-153**）会在 `SSTP_MSG_CALL_CONNECT_ACK` 里带
`CRYPT_BINDING_REQ`（attr id 4，32 字节 nonce），要求客户端回 `CRYPT_BINDING_RESP`：

```text
CompoundMAC = HMAC-SHA256(key = nonce, msg = SHA256(服务端 TLS 证书 DER))
```

- **Node 下可以算**（`socket.getPeerCertificate().raw` 能拿到证书）→ 探针已实现，所以能测通；
- **Cloudflare Workers 做不到**：`cloudflare:sockets` 的 `connect()` 不暴露对端证书，
  算不出证书哈希 → 服务端会一直等，然后断开。

表现：Worker 侧 SSTP 卡在建链、`sstp: connect timeout` 或读到 EOF。
探针会在每轮输出 `⚠ 该节点要求 SSTP crypto binding` —— **看到这行就换节点**。

怎么选 `dialTimeoutMs`：它是「落地多久没成才回落直连」的门槛。

- 隧道复用命中是常态（一个 isolate 内连续请求）→ 只需覆盖 `reuse`，取小值，首包最快；
- 隔离区经常被回收、SSTP 多半冷启动 → 取大值，否则落地永远抢不到机会；
- 落地长期不可达时靠 `dialFailThreshold` / `dialFailCooldownMs` 临时跳过落地，
  不必把 `dialTimeoutMs` 压得过小。

探针在 Node 下独立实现 SSTP/PPP 建链（`src` 里的 client 依赖 `cloudflare:sockets`，Node 跑不了），
字节/校验和工具直接复用 `src/utils.js`。

---

## 出站顺序：落地 → 直连

默认**先走落地，超时后再直连**（不是先直连）：

```text
① 落地（fdip= 指定的 SSTP / ProxyIP）   ← 先走
      │ 失败 / 超过 dialTimeoutMs（默认 3s）
      ▼
② 直连目标                              ← 兜底
```

`global=1` 时**只走落地**，不回落直连，同时把建连超时关掉（置 0）——因为这时没有"超时后切直连"的对象了，
再用 3s 去掐落地建连只会白白失败：

| 模式 | 顺序 | 建连超时 |
| --- | --- | --- |
| 默认 | 落地 →（超时/失败）→ 直连 | `dialTimeoutMs`（默认 3000ms） |
| `global=1` | 只落地 | **0 = 不设超时**（SSTP 建链仍受 `sstpConnectMs` 保护，默认 10s） |
| `race=1` | 并发拨，谁先就绪用谁 | 同默认 |

⚠️ 两个要注意的点：

1. **顺序换代价**：落地排在第一位后，本来能直连的目标也要先等落地那一跳。
   若落地地址不可达，每次请求会多等 `dialTimeoutMs`（默认 3s）才回落到直连。
   落地质量差时把 `dialTimeoutMs` 调小（如 1000），或给这类目标用 `?race=1` 并发。
2. **`CONFIG.proxyip` 默认是占位值** `proxyip.example.com!txt`，一定要在 path 里用
   `fdip=` 给真实落地，否则每个请求都要先耗掉一次超时。

```154:179:src/outbound.js
export async function dialOutbound(targetHost, targetPort, proxy, globalMode, options = {}) {
  // 竞速由请求参数 ?race=1 决定（入口传入），不传则串行回落
  const race = options.race ?? false;

  if (!portAllowed(targetPort)) {
    log('blocked port', targetPort);
    return null;
  }

  // global=1 只走落地：没有"超时后回落直连"这一说了，
  // 落地建连不该被 dialTimeoutMs 掐断 —— 这里直接关掉超时（0 = 不设超时）。
  const timeout = globalMode === '1' ? 0 : CONFIG.dialTimeoutMs;

  const entries = await resolveProxyCandidates(proxy || CONFIG.proxyip, Math.max(1, CONFIG.dialRaceCandidates));
  if (!entries.length) {
    log('unsupported proxy', proxy);
    return null;
  }
  // 非竞速模式只取第一个候选，保持旧行为
  const useEntries = race ? entries : entries.slice(0, 1);

  const dialers = [];
  // ① 先走落地（顺序在直连之前）
  for (const entry of useEntries) dialers.push(() => dialViaEntry(entry, targetHost, targetPort, timeout));
  // ② 落地失败 / 超时后再直连
  if (globalMode !== '1') {
    dialers.push(() => tcpConnect(targetHost, targetPort, timeout).catch(() => null));
  }

  return race && dialers.length > 1 ? raceDial(dialers) : serialDial(dialers);
}
```

## 只支持两种出站

| 落地写法 | 行为 |
| --- | --- |
| `1.2.3.4:443` / `域名` / `域名!txt` | **ProxyIP**：`connect(落地)`，由它按 SNI 反代到真正的目标 |
| `sstp://host:443` | **SSTP**：SSTP over TLS → PPP → 虚拟 IPv4 → 手工 IPv4/TCP → 目标 |

`socks5://`、`http(s)://`、`turn(s)://`、`?auto=1` 等一律不再支持（写了会连接失败，`CONFIG.debug = true` 时日志里会打 `unsupported proxy`）。

---

## 未包含的功能

- **trojan / ss 入站**：本仓库前端只做 VLESS（ws + xhttp）；
- **XHTTP 的 `packet-up` / `stream-up` 模式**：需要跨请求会话表（多个 POST/GET 归并到一个会话），Worker 侧不维护会话；请用 `mode=stream-one`；
- **gRPC 帧头**（`noGRPCHeader: false`）：不做 5 字节帧的拆装，必须开 `noGRPCHeader: true`；
- **socks5 / http(s) / turn(s) 落地**：按"只留 SSTP + ProxyIP"的要求已从代码里移除；需要这些链式落地请参考上游 [jacobax/snippets](https://github.com/jacobax/snippets)；
- **自适应 proxyip（`?auto=1/2`，zjcloud 域名模板）与并发竞速拨号（`race`）**：已移除，`proxyip` 直接写死或用 `域名!txt` 轮换即可；
- **订阅器**：不带前端与订阅转换，可搭配 [EDT](https://github.com/cmliu/edgetunnel) 或任意订阅器使用。

---

## 限制与已知问题

- 这是协议研究与学习性质的代码，**不是稳定 VPN 客户端**，不做任何可用性承诺；
- SSTP 后端只模拟必要的 IPv4/TCP 路径，不是完整网络栈，TCP 选项（SACK、窗口缩放等）未实现；
- 只适合 TCP 目标；UDP 仅 53；
- 兼容性取决于 SSTP/SoftEther 服务端行为（不同版本对 IPCP、PAP 的处理有差异）；
- 大流量、长连接会受 Workers 运行时限制影响（CPU 时间、内存、并发连接数）；
- VPN Gate 公共节点随时可能下线，需要自行维护列表；
- Cloudflare 出站对部分端口有限制，优先用 443；
- `mss` 不要改大：TCP 伪首部缓冲区固定 1432 字节（12 + 20 + 1400）。

---

## 排障

| 现象 | 排查 |
| --- | --- |
| 1101 | 删除旧 Worker / 旧片段后重新部署 |
| 连不上（ws） | 确认 `Upgrade: websocket`、path 中的 UUID 与 `CONFIG.uuid` 一致 |
| xhttp 返回 400 且提示 `noGRPCHeader` | 客户端 extra 没开 `noGRPCHeader: true`，或路径/UUID 不对 |
| xhttp 返回 400 且提示 padding | 客户端 `xPaddingHeader` / `xPaddingKey` 与 Worker 的 `CONFIG` 不一致（或关掉 `xhttpStrictPadding`） |
| xhttp 返回 502 | 落地连不上：换 SSTP 节点 / ProxyIP，或加 `global=1`；响应体里带目标地址 |
| 日志 `unexpected status 204` | 客户端在用 **packet-up**（`mode` 没写或为 `auto`）。必须显式设 `mode=stream-one`（v2rayN：传输协议 xhttp → 模式选 `stream-one`） |
| xhttp 无响应 | 确认 `type=xhttp`、`mode=stream-one`、`alpn=h2` |
| SSTP 落地失败 | 换节点、确认 443 端口、`wrangler tail` 看是否卡在 PPP；把 `CONFIG.debug` 设为 `true` |
| UDP 不通 | 只支持 53 端口 DNS，其它 UDP 目标不支持 |
| 目标被重置 | 试 `global=1` 强制走落地，或换 ProxyIP / 换 SSTP 节点 |

打开调试日志：把 `CONFIG.debug` 改成 `true`，然后 `npm run tail`。

---

## 许可与鸣谢

- 许可：[GPL-3.0](./LICENSE)
- 上游实现与对齐基准：[jacobax/snippets](https://github.com/jacobax/snippets)（`snippet.js`）
- SoftEther VPN：<https://www.softether.org/> · <https://github.com/SoftEtherVPN/SoftEtherVPN>
- VPN Gate：<https://www.vpngate.net/>
- 鸣谢：AK、CM、ZJ 以及上游社区的各位

> 请遵守所在地法律法规与 Cloudflare 服务条款，仅用于协议学习与合法的网络访问。
