# cf-vpngate

> Cloudflare Worker / Snippet：**前端 VLESS over WebSocket / XHTTP，后端 SSTP（VPN Gate 公共节点）+ ProxyIP 落地**。
> 原仓库 `CF-SoftEther` 的实验性 SSTP 出站代码，已按 [jacobax/snippets](https://github.com/jacobax/snippets) 的 `snippet.js` 全面重构（冲突处以上游 `snippet.js` 为准）。

它不是普通的 `WebSocket → connect() → 目标` 字节转发：当后端走 SSTP 时，Worker 会在脚本里完成 **SSTP 建链 → PPP(LCP/PAP/IPCP) 协商 → 拿到虚拟 IPv4 → 手工封装 IPv4/TCP**，再与目标通信。

---

## 目录

- [架构](#架构)
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

## 架构

```text
客户端 (v2rayN / Xray / sing-box ...)
   │  VLESS over WebSocket  或  VLESS over XHTTP
   ▼
Cloudflare Worker  ── 本仓库
   │
   ├─ 直连（默认优先）：connect(目标)
   │
   └─ 落地（proxyip / SSTP / socks5 / http(s)）：
        ├─ ProxyIP        → connect(proxyip:443)，由它按 SNI 反代到目标
        ├─ SSTP           → SSTP over TLS → PPP → 虚拟 IPv4 → 手工 TCP → 目标
        ├─ socks5 / http(s) → CONNECT 目标
        └─ 域名!txt        → 取 TXT 记录里的任意一种上面地址，随机选一个
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

## 这次重构做了什么

| 项目 | 旧版 `CF-SoftEther` | 重构后 `cf-vpngate` |
| --- | --- | --- |
| 入站 | 仅 VLESS over WebSocket | **VLESS over WebSocket + VLESS over XHTTP**（含 Early Data） |
| 后端 | 仅 SSTP（path 里写死 `sstp://`） | **SSTP + ProxyIP + !txt + socks5 + http(s)**，统一调度 |
| DNS | 每次请求都打 DoH | DoH 结果缓存 3 分钟 + 同域名并发去重 |
| TXT 落地 | 无 | 支持 `域名!txt`，列表缓存，随机取一条 |
| 上行 | 逐条 `write` | 分片入队 + 出队合并，队列 8MB 上限，带反压 |
| 下行 | 逐块 `ws.send` | 攒包到 64KB + `bufferedAmount` 背压感知 + `scheduler.wait` 让出 |
| 读取方式 | 默认 reader | 优先 BYOB（零拷贝）读 |
| 半关闭 | 无 | `allowHalfOpen`，正确收发 FIN，收尾干净 |
| UDP | 不支持 | 53 端口（DNS）转成 TCP 上的 DNS 查询再回写 |
| 代码结构 | 一个函数流，缩写变量 | 14 个分区、命名函数、`CONFIG` 集中配置、异常统一收口 |
| 调试 | 满屏 `console.log` | `CONFIG.debug` 开关，默认关闭 |
| 部署形态 | 只能当 Worker | Worker（wrangler）与 Snippets（粘贴）都能用 |

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

### 方式三：Cloudflare Snippets

规则 → Snippets → 新建 → 粘贴 `worker.js` 全文 → 部署。
Snippets 没有环境变量，改 UUID 直接在文件顶部改 `CONFIG.uuid`，或写全局变量 `UUID = "..."`。

> 若出现 1101，请删掉旧片段/旧 Worker 后重新部署（新代码会触发代码检测）。

---

## 配置

所有可调项集中在 `worker.js` 顶部的 `CONFIG`：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `uuid` | `495c7195-85b8-498a-bf20-2ea9ce9175b5` | VLESS UUID。可用 Worker 变量 `UUID` 或全局变量 `UUID` 覆盖 |
| `proxyip` | `proxyip.example.com!txt` | 默认落地。支持 `1.2.3.4:443` / `域名!txt` / `sstp://host:443` / `socks5://host:1080` / `https://host:443` |
| `autoDomain` | `proxy.zjcloud.us.ci` | `auto=1/2` 时用的自适应 proxyip 域名模板（`${colo}.${autoDomain}`） |
| `race` | `1` | 直连并发拨号数，>1 时取最快的一条并关掉其余 |
| `chunk` | `65536` | socket → WebSocket 读块大小 |
| `dnPack` / `dnTail` / `dnMs` | `65536` / `2048` / `2` | 下行攒包上限、剩余空间阈值、延迟冲刷毫秒 |
| `upPack` | `65536` | 上行入队分片大小 |
| `maxED` | `8192` | Early Data 最大长度 |
| `hsMax` / `xhInit` / `xhNext` | `16384` / `32768` / `8192` | XHTTP 握手头最大等待字节、首读与后续读字节数 |
| `mss` | `1400` | SSTP 隧道内 TCP 分片（**不要超过 1400**，受伪首部缓冲区 1432 限制） |
| `sstpUser` / `sstpPass` | `vpn` / `vpn` | PPP 的 PAP 认证（VPN Gate 公共节点固定为 `vpn`/`vpn`） |
| `dnsServer` / `dnsPort` | `1.1.1.1` / `53` | UDP(53) 转发的 TCP DNS 服务器 |
| `debug` | `false` | 打开后输出 `[cf-vpngate]` 前缀日志，配合 `wrangler tail` 查看 |

Worker 环境变量：`UUID`（可选）。其余全部走 path 传入，改落地不用重新部署。

---

## 路径与参数

```text
/fdip=<落地地址>?ed=2560[&global=1][&auto=1]
```

- `fdip`：键名可任意（如 `proxy`、`p`、`1234`），值就是落地地址；
- `ed=2560`：Early Data，客户端侧参数，**放最后**；
- `global=1`：强制走落地（默认先尝试直连，失败再回落落地）；
- `auto=1` / `auto=2`：自适应 proxyip（`1`：hkg 优先 path 指定，其它走 zj；`2`：全部 zj）。

落地地址写法：

| 写法 | 含义 |
| --- | --- |
| `1.2.3.4:443`、`[2001:db8::1]:443` | ProxyIP 直连 |
| `proxy.example.com` | ProxyIP 直连（默认 443） |
| `sub.example.com!txt` | 取该域名 TXT 记录里的一条地址（逗号/换行分隔，随机选） |
| `sstp://host:443` | SSTP（VPN Gate / SoftEther），默认 `vpn:vpn` |
| `sstp://user:pass@host:443` | 自定义 PAP 认证的 SSTP |
| `socks5://host:1080`、`socks5://u:p@host:1080` | SOCKS5 落地 |
| `http://host:8080`、`https://host:443` | HTTP CONNECT 落地 |

示例：

```text
/fdip=sstp://219.100.37.196:443?ed=2560
/fdip=vpn1234.opengw.net:443?ed=2560
/fdip=1.2.3.4:443?ed=2560&global=1
/fdip=william.us.ci!txt?ed=2560
/?auto=1&ed=2560
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
| `mode=stream-one` | XHTTP 建议模式 |
| `alpn=h2` | XHTTP 走 h2，与 `mode` 搭配 |
| `ed=2560` | 与客户端 Early Data 长度一致 |

### xhttp extra（客户端 XHTTP 传输的 extra 配置，默认填这个）

留空也可以，效果自测。在 Xray 系客户端里填到 XHTTP 传输的 **extra** 文本框：

```json
{
"extra": {
  "noGRPCHeader": true,
  "headers": {
    "Content-Type": "application/octet-stream"
  },
  "xPaddingBytes": "100-1000",
  "xPaddingObfsMode": true,
  "xPaddingMethod": "tokenish",
  "xPaddingPlacement": "queryInHeader",
  "xPaddingHeader": "X-Cache",
  "xPaddingKey": "_dc"
}
}
```

服务端不需要为 padding 做额外处理：padding 落在 HTTP 请求头/查询里，不进 body，本实现直接按 `application/octet-stream` / `application/grpc` 读取请求体。

---

## 自助节点页 /sub

访问 Worker 的 `/sub` 或 `/uuid`（GET）会返回纯文本节点信息，自动使用请求的 `Host`：

```bash
curl https://your-worker.example.com/sub
curl https://your-worker.example.com/sub?sstp=sstp://vpn1234.opengw.net:443
curl https://your-worker.example.com/sub?proxy=1.2.3.4:443
```

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

代码维护：源端口、seq/ack、IPv4 首部、TCP 首部、IPv4 校验和、TCP 伪首部校验和、MSS 分片；收到 FIN 时冲刷缓冲后回 FIN+ACK 并关闭流。

---

## UDP(53)

VLESS 的 UDP 只处理 **53 端口（DNS）**：Worker 把 DNS 查询包通过 TCP 发给 `1.1.1.1:53`，拿到带长度前缀的应答后原样回写给客户端。其它 UDP 目标直接断开（Worker 环境无原生 UDP 出站）。

---

## 优化点

1. **去除了 trojan / ss 入站与 ss2022 加解密**：冷启动更快、内存更省，代码量减半；
2. **DNS 缓存 + 并发去重**：同一域名 3 分钟内复用，并发请求共用一个查询；
3. **TXT 列表缓存**：`!txt` 落地不会每连接都解析一次；
4. **上行分片入队 + 出队合并**：把大量小 WebSocket 帧合并成 64KB 大包再写入 socket；
5. **下行攒包 + 背压**：`bufferedAmount` 超阈值时用 `scheduler.wait` 让出事件循环，避免堆积导致内存飙升；
6. **BYOB 读**：`getReader({ mode: 'byob' })` 直接读到复用缓冲区，少一次拷贝；
7. **SSTP 收包缓冲区复用**：`ArrayBuffer` 在多次 `readAtLeast` 间复用；
8. **超时统一**：握手 10s、长连接等待 60s，避免 Worker 空转；
9. **半开连接**：`allowHalfOpen` + FIN 处理，落地侧先关闭时也能把残余数据回传；
10. **异常收口**：所有路径 `try/catch`，`fetch` 一律返回合法 `Response`，不抛未捕获异常；
11. **配置集中**：`CONFIG` 一处可调，日志用 `CONFIG.debug` 开关。

---

## 未包含的功能

- **trojan / ss 入站**：本仓库前端只做 VLESS（ws + xhttp）；
- **turn / turns 落地**：上游 `snippet.js` 有 STUN/TURN 实现，本仓库未纳入，需要请参考 [jacobax/snippets](https://github.com/jacobax/snippets)；
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
| xhttp 无响应 | 确认 `type=xhttp`、`mode=stream-one`、`Content-Type: application/octet-stream`（即 extra 里的 `noGRPCHeader: true`） |
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
