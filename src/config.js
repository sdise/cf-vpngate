/**
 * 全局配置与常量。
 * 所有可调项集中在这里；Worker 变量 UUID / Snippet 全局 UUID 可覆盖 CONFIG.uuid。
 *
 * 约束（适配 Cloudflare Snippets）：
 *   只用 cloudflare:sockets / fetch / Web Crypto / Streams 等通用能力，
 *   不使用 KV、Durable Objects、Cache API、环境变量——所有缓存均为 isolate 级内存缓存。
 */

export const CONFIG = {
  /* ---------- 基础 ---------- */
  /** VLESS UUID：可用 Worker 变量 UUID / Snippet 全局 UUID 覆盖 */
  uuid: '495c7195-85b8-498a-bf20-2ea9ce9175b5',
  /** 默认落地：ProxyIP（host:port / 域名 / 域名!txt）或 sstp://host:port */
  proxyip: 'proxyip.example.com!txt',

  /* ---------- 收发参数 ---------- */
  /** socket → WebSocket 的读块大小 */
  chunk: 65536,
  /** 下行（落地 → 客户端）组包上限 */
  dnPack: 65536,
  /** 下行剩余空间小于该值时立即冲刷，避免小包滞留 */
  dnTail: 2048,
  /** 下行延迟冲刷毫秒数；开启 dnAdaptive 后仅在高吞吐时才延迟 */
  dnMs: 2,
  /** 下行自适应：吞吐低于 dnAdaptiveBps 时立即冲刷（交互流量优先），否则攒包 */
  dnAdaptive: true,
  dnAdaptiveBps: 262144,
  /** 上行（客户端 → 落地）入队分片大小 */
  upPack: 65536,
  /** Early Data（sec-websocket-protocol / XHTTP 首片）最大长度 */
  maxED: 8192,
  /** 入站握手头解析的最大等待字节（超过即判定非法） */
  hsMax: 16384,
  /** XHTTP 首读 / 后续读的字节数 */
  xhInit: 32768,
  xhNext: 8192,

  /* ---------- 超时 ---------- */
  /**
   * 落地 / 直连的建连超时（毫秒）。超时即回落，避免首包被 TCP 超时拖死。
   * 4500 是实测值：SSTP 冷启动（TLS ~1.0s + SSTP/PPP ~1.8s + 隧道内握手 ~0.45s ≈ 3.4s）× 1.2 后取整。
   * 低于 3.4s 会导致 SSTP 冷启动永远抢不到机会（实测 3000ms 必超时）。
   */
  dialTimeoutMs: 4500,
  /** WebSocket 入站等待 VLESS 头的最长毫秒数 */
  wsHandshakeTimeout: 15000,
  /** XHTTP 等待客户端首包（VLESS 头）的最长毫秒数 */
  xhttpHeaderTimeout: 15000,

  /* ---------- 队列与背压 ---------- */
  /** 单连接上行队列上限（字节） */
  maxQueueBytes: 8388608,
  /** 全局（整个 isolate）上行队列总预算，超过则拒收，防多连接叠加 OOM */
  maxQueueTotalBytes: 33554432,
  /** 单连接队列超过该值即产生反压信号（让出事件循环） */
  queueWakeBytes: 1048576,
  /** 队列降到该值以下解除反压 */
  queueDrainBytes: 262144,
  /** 下行 bufferedAmount 超过该值开始等待 */
  wsBackpressureBytes: 262144,
  /** bufferedAmount 低于该值立即恢复发送 */
  wsBackpressureReleaseBytes: 65536,

  /* ---------- SSTP ---------- */
  /** SSTP 隧道内 TCP 分片大小（受 TCP 伪首部校验缓冲区 1432 限制，勿超过 1400） */
  mss: 1400,
  /** SSTP / PPP 的 PAP 认证信息（VPN Gate 公共节点固定为 vpn / vpn） */
  sstpUser: 'vpn',
  sstpPass: 'vpn',
  /** 竞速时最多并发几个落地候选（从 `域名!txt` 列表里取） */
  dialRaceCandidates: 2,
  /** 落地连续失败多少次后，本 isolate 内暂时跳过落地直接走直连 */
  dialFailThreshold: 3,
  /** 落地被跳过后的冷却毫秒（冷却期内不再为它付 dialTimeoutMs） */
  dialFailCooldownMs: 30000,
  /** SSTP 建链（TCP+TLS → SSTP → PPP）总超时；实测 p95 约 2.9s，留 ~1.7 倍余量 */
  sstpConnectMs: 5000,
  /** 隧道内 TCP 三次握手超时；实测 0.4~0.6s，取 3 倍 */
  sstpHandshakeMs: 1500,
  /** 隧道复用：单条 SSTP 隧道最多并发多少条目标 TCP 流（超过则再开一条隧道） */
  sstpMaxStreams: 8,
  /** 隧道复用：无人引用后的空闲存活毫秒 */
  sstpIdleMs: 60000,
  /** 隧道复用：仍有活跃流但长时间无数据时的兜底回收毫秒 */
  sstpStreamIdleMs: 300000,
  /** 隧道复用开关（关闭则每次连接都新建隧道，行为同旧版） */
  sstpReuseTunnel: true,
  /** 隧道内接收缓冲上限（字节），配合窗口通告做背压 */
  sstpBufferBytes: 262144,
  /** 通告给对端的最大窗口 */
  sstpWindowBytes: 65535,
  /** 是否启用简化重传（丢包时重发未确认段） */
  sstpRetransmit: true,
  /** 重传超时毫秒 */
  sstpRtoMs: 1000,
  /** 单段最大重传次数，超过则断开 */
  sstpMaxRetries: 5,

  /* ---------- DNS ---------- */
  /** UDP(53) 转发的 TCP DNS 服务器（仅当客户端目标解析不出时兜底） */
  dnsServer: '1.1.1.1',
  dnsPort: 53,
  /** DoH 结果缓存毫秒 */
  dnsTtlMs: 180000,
  /** 解析失败（空结果）的负缓存毫秒，避免反复查询放大 */
  dnsNegativeTtlMs: 30000,
  /** UDP(53) 转发结果的缓存毫秒（含失败） */
  dnsAnswerTtlMs: 60000,

  /* ---------- XHTTP padding ---------- */
  /** XHTTP padding：需与客户端 xhttp extra 的 xPadding* 一致 */
  xhttpPadding: true,
  xhttpPaddingHeader: 'a290fd',
  xhttpPaddingKey: '_d8d344',
  xhttpPaddingRange: [100, 1000],
  /** 请求带 padding 时是否校验长度（严格模式；默认宽松，避免误伤客户端） */
  xhttpStrictPadding: false,

  /* ---------- 安全 ---------- */
  /**
   * /sub 节点页的访问控制：
   *   'uuid'  —— 需携带正确 UUID（?uuid= / /<uuid>/sub / X-Uuid 头），否则 404
   *   'off'   —— 完全关闭节点页
   *   'none'  —— 不校验（任何人都能拿到 UUID，等同开放代理）
   */
  subAuth: 'uuid',
  /** 是否允许请求方用 header/query 的 global=1 强制走落地 */
  allowClientGlobal: true,
  /** 服务端默认 global 模式（allowClientGlobal=false 时生效）：'1' 强制落地，'' 先直连 */
  globalMode: '',
  /** 禁止代理的目标端口（如 [25, 445]）；空数组表示不限制 */
  blockedPorts: [],

  /* ---------- 调试 ---------- */
  /** 调试日志（Snippet 可在顶部改为 true 后用 `wrangler tail` 观察） */
  debug: true,
};

/** XHTTP 响应头（与 Xray 的 xhttp 客户端约定保持一致） */
export const XHTTP_HEADERS = {
  'Content-Type': 'application/octet-stream',
  'grpc-status': '0',
  'X-Accel-Buffering': 'no',
  'Cache-Control': 'no-store',
};

/** 客户端 xhttp extra 推荐值（GET /sub 会原样输出，方便复制） */
export const XHTTP_EXTRA = `{
  "noGRPCHeader": true,
  "xPaddingObfsMode": true,
  "xPaddingMethod": "tokenish",
  "xPaddingPlacement": "queryInHeader",
  "xPaddingHeader": "a290fd",
  "xPaddingKey": "_d8d344"
}`;

export const log = (...args) => { if (CONFIG.debug) console.log('[cf-vpngate]', ...args); };
