/**
 * cf-vpngate
 * -----------------------------------------------------------------------------
 * 入站（前端）：VLESS over WebSocket / VLESS over XHTTP（只支持 mode=stream-one）
 * 出站（后端）：SSTP（VPN Gate 公共节点） / ProxyIP（含 `域名!txt` 列表）
 *
 * 可直接作为 Cloudflare Worker 部署（需 `wrangler.toml`），
 * 也可整段粘贴到 Cloudflare Snippets / Dashboard 快速编辑器中使用。
 *
 * ⚠️ 本文件由 src/ 自动生成（node scripts/build.js），请勿直接编辑；
 *    修改请改 src/ 下对应模块后重新执行 `npm run build`。
 *
 * 设计要点：
 *   - 有冲突的实现细节以 jacobax/snippets 的 snippet.js 为准；
 *   - 入站只保留 VLESS（ws + xhttp），去掉 trojan / ss 入站与 ss2022 加解密；
 *   - 出站只保留 SSTP 与 ProxyIP 两种，去掉 socks5 / http(s) / turn(s) 等落地；
 *   - UDP 仅支持 53 端口（DNS），由 Worker 转成 TCP 上的 DNS 查询再回写。
 */

import { connect } from 'cloudflare:sockets';

/* ------------------------------- src/config.js ------------------------------- */
/**
 * 全局配置与常量。
 * 所有可调项集中在这里；Worker 变量 UUID / Snippet 全局 UUID 可覆盖 CONFIG.uuid。
 *
 * 约束（适配 Cloudflare Snippets）：
 *   只用 cloudflare:sockets / fetch / Web Crypto / Streams 等通用能力，
 *   不使用 KV、Durable Objects、Cache API、环境变量——所有缓存均为 isolate 级内存缓存。
 */

const CONFIG = {
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
const XHTTP_HEADERS = {
  'Content-Type': 'application/octet-stream',
  'grpc-status': '0',
  'X-Accel-Buffering': 'no',
  'Cache-Control': 'no-store',
};

/** 客户端 xhttp extra 推荐值（GET /sub 会原样输出，方便复制） */
const XHTTP_EXTRA = `{
  "noGRPCHeader": true,
  "xPaddingObfsMode": true,
  "xPaddingMethod": "tokenish",
  "xPaddingPlacement": "queryInHeader",
  "xPaddingHeader": "a290fd",
  "xPaddingKey": "_d8d344"
}`;

const log = (...args) => { if (CONFIG.debug) console.log('[cf-vpngate]', ...args); };

/* ------------------------------- src/utils.js ------------------------------- */
/**
 * 通用工具：字节读写、拼接、校验和、UUID、资源释放。
 * 全部为纯函数 / 无状态，供热路径高频调用。
 */

const EMPTY = new Uint8Array(0);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

const encode = str => encoder.encode(str);
const u16 = (buf, offset) => (buf[offset] << 8) | buf[offset + 1];
const u32 = (buf, offset) =>
  ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;

const setU16 = (buf, offset, value) => { buf[offset] = (value >> 8) & 255; buf[offset + 1] = value & 255; };
const setU32 = (buf, offset, value) => {
  buf[offset] = (value >>> 24) & 255;
  buf[offset + 1] = (value >>> 16) & 255;
  buf[offset + 2] = (value >>> 8) & 255;
  buf[offset + 3] = value & 255;
};

const randomBytes = n => crypto.getRandomValues(new Uint8Array(n));
const randomU16 = () => u16(randomBytes(2), 0);
const randomU32 = () => u32(randomBytes(4), 0);

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};

/** 任意 ArrayBuffer / ArrayBufferView → Uint8Array（零拷贝视图） */
const toU8 = value =>
  value instanceof Uint8Array
    ? value
    : ArrayBuffer.isView(value)
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : new Uint8Array(value);

/** 关闭 socket / reader / writer：有 cancel 用 cancel，否则用 close */
const tryClose = target => {
  try { const result = target?.cancel?.(); if (result === undefined) target?.close?.(); } catch {}
};
const releaseLock = target => { try { target?.releaseLock?.(); } catch {} };

/**
 * 标准 Internet 校验和（IPv4 首部 / TCP 伪首部共用）。
 * 按 32 位宽累加再折叠——比逐 16 位累加少一半循环次数，结果等价（模 2^16-1 一致）。
 */
const checksum = (data, offset, length) => {
  let sum = 0;
  const end = offset + length;
  let i = offset;
  // 每轮把 4 字节拆成两个 16 位相加：sum 每轮增长 < 2^17，
  // 全程保持 < 2^32，最后的折叠才能安全用位运算（否则 >>>16 会丢掉高位进位）
  for (; i + 4 <= end; i += 4) {
    const word = ((data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]) >>> 0;
    sum += (word & 0xffff) + (word >>> 16);
  }
  if (i + 2 <= end) { sum += u16(data, i); i += 2; }
  if (i < end) sum += data[i] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
};

/** TCP 序号比较（考虑 32 位回绕）：a < b / a <= b */
const seqLT = (a, b) => ((a - b) | 0) < 0;
const seqLE = (a, b) => a === b || ((a - b) | 0) < 0;

/** 'xxxxxxxx-xxxx-...' → 16 字节 */
const hexNibble = code => 15 & (code > 64 ? code + 9 : code);
const uuidToBytes = uuid => {
  const out = new Uint8Array(16);
  let i = 0;
  for (let b = 0; b < 16; b++) {
    let hi = uuid.charCodeAt(i++); if (hi === 45) hi = uuid.charCodeAt(i++);
    let lo = uuid.charCodeAt(i++); if (lo === 45) lo = uuid.charCodeAt(i++);
    out[b] = (hexNibble(hi) << 4) | hexNibble(lo);
  }
  return out;
};

const uuidCache = new Map();
const getUuidBytes = uuid => {
  let bytes = uuidCache.get(uuid);
  if (!bytes) { bytes = uuidToBytes(uuid); uuidCache.set(uuid, bytes); }
  return bytes;
};

/** 带超时的 promise：超时后 reject，不取消原任务（调用方自行收尾） */
const withTimeout = (promise, ms, message) => {
  if (!ms || ms <= 0) return promise;
  let timer;
  const guard = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || 'timeout')), ms); });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
};

/* ------------------------------- src/padding.js ------------------------------- */
/**
 * XHTTP padding（对齐 edgetunnel）。
 * 请求侧提取 + 可选严格校验，响应侧回填随机 padding。
 */




/** paddingIds 随 uuid 缓存：避免每请求都做 slice / filter / 数组分配 */
const idCache = new Map();

/**
 * XHTTP padding 的「头名 / 键名」。
 * 默认用 CONFIG 里的 `a290fd` / `_d8d344`（与 extra 的 xPaddingHeader / xPaddingKey 对应），
 * 同时兼容 edgetunnel 由 UUID 派生的名字：uuid.slice(1,7) / '_' + uuid.slice(25,31)。
 */
function paddingIds(uuid) {
  let ids = idCache.get(uuid);
  if (!ids) {
    ids = {
      headers: [CONFIG.xhttpPaddingHeader, uuid.slice(1, 7)].filter(Boolean),
      keys: [CONFIG.xhttpPaddingKey, `_${uuid.slice(25, 31)}`].filter(Boolean),
    };
    idCache.set(uuid, ids);
  }
  return ids;
}

/**
 * 取出请求中的 padding，支持客户端 xPaddingPlacement 的三种放置方式：
 *   queryInHeader / header → 值在 header 里（可能是 `https://x/?_dc=xxx` 形态的 URL）
 *   query                  → 值在请求 URL 的 query 里
 * @param {URL} [url] 入口已解析好的 URL，传进来可省一次 new URL
 */
function extractXhttpPadding(request, uuid, url) {
  const { headers, keys } = paddingIds(uuid);
  for (const name of headers) {
    const value = request.headers.get(name);
    if (!value) continue;
    try {
      const inner = new URL(value, 'https://x.invalid');
      for (const key of keys) {
        const hit = inner.searchParams.get(key);
        if (hit) return hit;
      }
    } catch { /* 不是 URL 形态，按原值处理 */ }
    return value;
  }
  const parsed = url || new URL(request.url);
  for (const key of keys) {
    const hit = parsed.searchParams.get(key);
    if (hit) return hit;
  }
  return '';
}

/** 客户端没开 padding 直接放行；严格模式下校验长度是否落在 xPaddingBytes 区间 */
function paddingAcceptable(padding) {
  if (!padding || !CONFIG.xhttpStrictPadding) return true;
  const [min, max] = CONFIG.xhttpPaddingRange;
  return padding.length >= min - 2 && padding.length <= max + 2;
}

const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** 批量取随机字节再映射，避免逐字符 Math.random() + 字符串累加 */
const randomPadding = length => {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += B62[bytes[i] % 62];
  return out;
};

/** 回填 padding 响应头（对齐 edgetunnel：头值是一个带 query 的 URL） */
function applyPaddingHeader(headers) {
  if (!CONFIG.xhttpPadding) return;
  try {
    const [min, max] = CONFIG.xhttpPaddingRange;
    const url = new URL('https://x.invalid/');
    url.searchParams.set(CONFIG.xhttpPaddingKey, randomPadding(min + Math.floor(Math.random() * (max - min + 1))));
    headers.set(CONFIG.xhttpPaddingHeader, url.toString());
  } catch { /* 头名非法则忽略 */ }
}

/* ------------------------------- src/net.js ------------------------------- */
/**
 * 最底层的 TCP 连接封装。
 * 半开直连（保留半关闭能力，便于落地侧 FIN 之后的残余数据回传）。
 */





/**
 * @param {string} host
 * @param {number} port
 * @param {number} [timeoutMs] 建连超时；超时会关闭 socket 并 reject
 */
async function tcpConnect(host, port, timeoutMs = 0) {
  const hostname = String(host).replace(/^\[|\]$/g, '');
  const socket = connect({ hostname, port }, { allowHalfOpen: true });
  try {
    if (timeoutMs > 0) await withTimeout(socket.opened, timeoutMs, `connect timeout: ${hostname}:${port}`);
    else await socket.opened;
    return socket;
  } catch (err) {
    tryClose(socket);
    throw err;
  }
}

/* ------------------------------- src/dns.js ------------------------------- */
/**
 * DNS：DoH 解析（缓存 + 并发去重 + 负缓存）+ UDP(53) 转 TCP 的 DNS 查询（带应答缓存）。
 *
 * 缓存全部是 isolate 级内存缓存（不依赖 KV / Cache API），因此在 Snippets 下同样可用。
 */





const DNS_CACHE = new Map();
const DNS_INFLIGHT = new Map();

async function dnsQuery(name, type) {
  const key = `${name}_${type}`;
  const now = Date.now();
  const cached = DNS_CACHE.get(key);
  if (cached) {
    // 命中缓存：正结果走 dnsTtlMs，负结果（空）走 dnsNegativeTtlMs
    const ttl = cached.data.length ? CONFIG.dnsTtlMs : CONFIG.dnsNegativeTtlMs;
    if (now - cached.time < ttl) return cached.data;
    DNS_CACHE.delete(key);
  }
  const inflight = DNS_INFLIGHT.get(key);
  if (inflight) return inflight;
  const task = (async () => {
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' } },
      );
      if (!res.ok) return [];
      const answers = (await res.json()).Answer || [];
      if (answers.length || CONFIG.dnsNegativeTtlMs > 0) {
        if (DNS_CACHE.size >= 400) DNS_CACHE.delete(DNS_CACHE.keys().next().value);
        DNS_CACHE.set(key, { data: answers, time: Date.now() });
      }
      return answers;
    } catch { return []; }
  })();
  DNS_INFLIGHT.set(key, task);
  try { return await task; } finally { DNS_INFLIGHT.delete(key); }
}

/** 解析 A 记录（已是 IPv4 则直接返回） */
const resolveIPv4 = async host => {
  if (IPV4_RE.test(host)) return host;
  const list = (await dnsQuery(host, 'A')).filter(a => a.type === 1).map(a => a.data);
  if (!list.length) throw new Error(`resolve failed: ${host}`);
  return list[0];
};

/** 解析 TXT 记录，值按逗号 / 换行切分成候选列表 */
const resolveTXT = async host => {
  const records = (await dnsQuery(host, 'TXT')).filter(a => a.type === 16).map(a => a.data);
  if (!records.length) return [];
  return records
    .map(t => t.replace(/"/g, ''))
    .join(',')
    .replace(/[\r\n\s]+/g, ',')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
};

/**
 * UDP(53) 的应答缓存。
 * key 采用「查询体去掉 2 字节 ID」：同一域名/类型的重复查询（浏览器重试很常见）直接命中。
 */
const ANSWER_CACHE = new Map();
const ANSWER_MAX = 200;

/**
 * FNV-1a 哈希做 key：避免把整个查询体转成字符串（每次查询都要造几百字符，CPU/GC 都亏）。
 * 前 2 字节（transaction id）按 0 参与哈希，保证同一查询不同 ID 命中同一条缓存。
 */
const answerKey = (host, port, body) => {
  if (body.byteLength < 12) return null; // 太短，无法安全剥离 ID
  let hash = 2166136261;
  for (let i = 0; i < body.length; i++) {
    hash ^= i < 2 ? 0 : body[i];
    hash = Math.imul(hash, 16777619);
  }
  return `${host}:${port}:${body.length}:${hash >>> 0}`;
};

/** UDP(53)：把 DNS 查询包放到 TCP 上发给 DNS 服务器，拿回应答 */
async function dnsOverTcp(query, host = CONFIG.dnsServer, port = CONFIG.dnsPort) {
  const request = toU8(query);
  // 抹掉 ID 之前先算 key（缓存只按内容命中，与 ID 无关）
  const cacheKey = CONFIG.dnsAnswerTtlMs > 0 ? answerKey(host, port, request) : null;
  if (cacheKey) {
    const hit = ANSWER_CACHE.get(cacheKey);
    if (hit && Date.now() - hit.time < CONFIG.dnsAnswerTtlMs) return hit.data;
    if (hit) ANSWER_CACHE.delete(cacheKey);
  }

  let answer = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    let socket;
    try {
      socket = await tcpConnect(host, port, CONFIG.dialTimeoutMs);
      const writer = socket.writable.getWriter();
      const reader = socket.readable.getReader();
      let buffer = EMPTY;

      const need = async n => {
        while (buffer.byteLength < n) {
          const { done, value } = await reader.read();
          if (done) throw new Error('dns: eof');
          const chunk = toU8(value);
          buffer = buffer.byteLength ? concat(buffer, chunk) : chunk;
        }
        const out = buffer.subarray(0, n);
        buffer = buffer.byteLength > n ? buffer.subarray(n) : EMPTY;
        return out;
      };

      // WebSocket 上的 UDP 报文已带 2 字节长度前缀；XHTTP 上没有，这里补上
      const hasLengthPrefix = request.byteLength >= 2 && u16(request, 0) === request.byteLength - 2;
      await writer.write(
        hasLengthPrefix ? request : concat(new Uint8Array([request.byteLength >> 8, request.byteLength & 255]), request),
      );
      const header = await need(2);
      const body = await need(u16(header, 0));
      answer = hasLengthPrefix ? concat(header, body) : body;
      break;
    } catch {
      if (attempt === 1) break;
    } finally {
      tryClose(socket);
    }
  }

  if (cacheKey && (answer || CONFIG.dnsAnswerTtlMs > 0)) {
    if (ANSWER_CACHE.size >= ANSWER_MAX) ANSWER_CACHE.delete(ANSWER_CACHE.keys().next().value);
    ANSWER_CACHE.set(cacheKey, { data: answer, time: Date.now() });
  }
  return answer;
}

/* ------------------------------- src/sstp/client.js ------------------------------- */
/**
 * SSTP 客户端：SSTP over TLS 建链 + PPP(LCP/PAP/IPCP) 协商 + SSTP 报文收发。
 * 只负责「隧道本身」，不关心隧道里跑什么（TCP 流由 ./tcp.js 处理）。
 */






const PPP_LCP = 0xc021;   // Link Control Protocol
const PPP_PAP = 0xc023;   // Password Authentication Protocol
const PPP_IPCP = 0x8021;  // IP Control Protocol
const PPP_IPV4 = 0x0021;  // IPv4 数据报文

function createSstpClient(username, password) {
  let socket = null;
  let reader = null;
  let writer = null;
  let host = '';
  let buffer = EMPTY;
  let pppId = 1;
  let readBuffer = new ArrayBuffer(16384);
  // 已被放弃（外部调用过 close）；connect 若在放弃后才完成，立刻关掉，避免 socket 泄漏
  let abandoned = false;

  const credit = password || CONFIG.sstpPass;
  const account = username || CONFIG.sstpUser;

  /** 精确读取 n 字节（带跨包拼接） */
  const readBytes = async n => {
    if (buffer.length >= n) {
      const out = buffer.subarray(0, n);
      buffer = buffer.subarray(n);
      return out;
    }
    const saved = buffer.length > 0 ? new Uint8Array(buffer) : null;
    const { value, done } = await reader.readAtLeast(n - buffer.length, new Uint8Array(readBuffer));
    if (done) throw new Error('sstp: eof');
    readBuffer = value.buffer;
    if (saved) {
      const merged = concat(saved, value);
      buffer = merged.subarray(n);
      return merged.subarray(0, n);
    }
    buffer = value.subarray(n);
    return value.subarray(0, n);
  };

  /** 读取一行 HTTP 头 */
  const readLine = async () => {
    for (;;) {
      const index = buffer.indexOf(10);
      if (index >= 0) {
        const line = decoder.decode(buffer.subarray(0, index));
        buffer = buffer.subarray(index + 1);
        return line.replace(/\r$/, '');
      }
      const saved = buffer.length > 0 ? new Uint8Array(buffer) : null;
      const { value, done } = await reader.readAtLeast(1, new Uint8Array(readBuffer));
      if (done) throw new Error('sstp: eof');
      readBuffer = value.buffer;
      buffer = saved ? concat(saved, value) : value;
    }
  };

  /**
   * 读取一个 SSTP 报文。
   * @param {number} ms 超时毫秒；**0 表示不超时**（隧道读循环用，避免超时后残留的
   *   pending read 破坏 buffer 连续性；隧道的空闲回收交给上层看门狗处理）
   */
  const readPacket = async (ms = 10000) => {
    if (ms <= 0) {
      const header = await readBytes(4);
      const length = u16(header, 2) & 0x0fff;
      return { ctrl: (header[1] & 1) === 1, body: length > 4 ? await readBytes(length - 4) : EMPTY };
    }
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('sstp: timeout')), ms); });
    try {
      const header = await Promise.race([readBytes(4), timeout]);
      clearTimeout(timer);
      const length = u16(header, 2) & 0x0fff;
      return { ctrl: (header[1] & 1) === 1, body: length > 4 ? await readBytes(length - 4) : EMPTY };
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  };

  /** SSTP 数据帧（承载 PPP） */
  const sstpData = frame => {
    const size = 6 + frame.length;
    const packet = new Uint8Array(size);
    packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03]);
    packet.set(frame, 6);
    return packet;
  };

  /** SSTP 控制帧 */
  const sstpControl = (messageType, attributes = []) => {
    const total = attributes.reduce((sum, attr) => sum + 4 + attr.data.length, 0);
    const packet = new Uint8Array(8 + total);
    const view = new DataView(packet.buffer);
    packet[0] = 0x10;
    packet[1] = 0x01;
    view.setUint16(2, (8 + total) | 0x8000);
    view.setUint16(4, messageType);
    view.setUint16(6, attributes.length);
    attributes.reduce((offset, attr) => {
      packet[offset + 1] = attr.id;
      view.setUint16(offset + 2, 4 + attr.data.length);
      packet.set(attr.data, offset + 4);
      return offset + 4 + attr.data.length;
    }, 8);
    return packet;
  };

  /** PPP 报文（协议 / code / id / 选项） */
  const pppFrame = (protocol, code, id, options = []) => {
    const total = options.reduce((sum, opt) => sum + 2 + opt.data.length, 0);
    const frame = new Uint8Array(6 + total);
    const view = new DataView(frame.buffer);
    view.setUint16(0, protocol);
    frame[2] = code;
    frame[3] = id;
    view.setUint16(4, 4 + total);
    options.reduce((offset, opt) => {
      frame[offset] = opt.type;
      frame[offset + 1] = 2 + opt.data.length;
      frame.set(opt.data, offset + 2);
      return offset + 2 + opt.data.length;
    }, 6);
    return frame;
  };

  /** PAP Authenticate-Request */
  const papFrame = id => {
    const user = encode(account);
    const pass = encode(credit);
    const tail = 6 + user.length + pass.length;
    const frame = new Uint8Array(2 + tail);
    const view = new DataView(frame.buffer);
    view.setUint16(0, PPP_PAP);
    frame[2] = 1;
    frame[3] = id;
    view.setUint16(4, tail);
    frame[6] = user.length;
    frame.set(user, 7);
    frame[7 + user.length] = pass.length;
    frame.set(pass, 8 + user.length);
    return frame;
  };

  const parsePPP = data => {
    const offset = data.length >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
    if (data.length - offset < 4) return null;
    const protocol = u16(data, offset);
    if (protocol === PPP_IPV4) return { protocol, ip: data.subarray(offset + 2) };
    return data.length - offset >= 6
      ? { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), raw: data.subarray(offset) }
      : null;
  };

  const parseOptions = data => {
    const options = [];
    for (let i = 0; i + 2 <= data.length;) {
      const type = data[i];
      const length = data[i + 1];
      if (length < 2 || i + length > data.length) break;
      options.push({ type, data: data.subarray(i + 2, i + length) });
      i += length;
    }
    return options;
  };

  const connectSstp = async (hostname, port) => {
    socket = connect({ hostname, port }, { secureTransport: 'on' });
    await socket.opened;
    // 建链超时后 connect 仍可能姗姗来迟，此时必须自己关掉，否则 socket 泄漏
    if (abandoned) { tryClose(socket); throw new Error('sstp: abandoned'); }
    reader = socket.readable.getReader({ mode: 'byob' });
    writer = socket.writable.getWriter();
    host = hostname;
  };

  const establish = async () => {
    const request = encode(
      `SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `Content-Length: 18446744073709551615\r\n` +
      `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`,
    );
    const protocolId = new Uint8Array(2);
    new DataView(protocolId.buffer).setUint16(0, 1);
    const mru = new Uint8Array(2);
    new DataView(mru.buffer).setUint16(0, 1500);

    await writer.write(concat(
      request,
      sstpControl(0x0001, [{ id: 1, data: protocolId }]),
      sstpData(pppFrame(PPP_LCP, 1, pppId++, [{ type: 1, data: mru }])),
    ));

    const status = await readLine();
    while ((await readLine()) !== '');
    if (!status.includes('200')) throw new Error(`sstp: http ${status}`);

    let sstpAcked = false;
    let lcpOpened = false;
    let authenticated = false;
    let finished = false;
    let myIp = null;

    for (let round = 0; round < 25 && !finished; round++) {
      const packet = await readPacket();
      if (packet.ctrl) {
        if (!sstpAcked && packet.body.length >= 2 && u16(packet.body, 0) === 2) sstpAcked = true;
        continue;
      }
      const ppp = parsePPP(packet.body);
      if (!ppp) continue;

      if (ppp.protocol === PPP_LCP) {
        if (ppp.code === 1) {
          // Configure-Request → Configure-Ack（顺带在 LCP 打开后发 PAP）
          const ack = new Uint8Array(ppp.raw);
          ack[2] = 2;
          await writer.write(
            lcpOpened && !authenticated
              ? concat(sstpData(ack), sstpData(papFrame(pppId++)))
              : sstpData(ack),
          );
          if (lcpOpened) authenticated = true;
        } else if (ppp.code === 2) {
          lcpOpened = true;
          if (!authenticated) { await writer.write(sstpData(papFrame(pppId++))); authenticated = true; }
        }
      } else if (ppp.protocol === PPP_PAP && ppp.code === 2) {
        // PAP 认证成功 → 请求 IPCP 分配地址
        await writer.write(sstpData(pppFrame(PPP_IPCP, 1, pppId++, [{ type: 3, data: new Uint8Array(4) }])));
      } else if (ppp.protocol === PPP_IPCP) {
        if (ppp.code === 1) {
          const ack = new Uint8Array(ppp.raw);
          ack[2] = 2;
          await writer.write(sstpData(ack));
        } else if (ppp.code === 3) {
          const option = parseOptions(ppp.payload).find(opt => opt.type === 3);
          if (option) {
            myIp = [...option.data].join('.');
            await writer.write(sstpData(pppFrame(PPP_IPCP, 1, pppId++, [{ type: 3, data: option.data }])));
          }
        } else if (ppp.code === 2) {
          const option = parseOptions(ppp.payload).find(opt => opt.type === 3);
          if (option) { myIp = [...option.data].join('.'); finished = true; }
        }
      }
    }
    if (!myIp) throw new Error('sstp: no ip from ipcp');
    log('sstp established', host, 'ip=', myIp);
    return myIp;
  };

  return {
    connect: connectSstp,
    establish,
    readPacket,
    parsePPP,
    get buffer() { return buffer; },
    get writer() { return writer; },
    close: () => { abandoned = true; [reader, writer, socket].forEach(tryClose); },
  };
}

/* ------------------------------- src/sstp/tcp.js ------------------------------- */
/**
 * PPP 之上的最小 IPv4/TCP 栈（一条流 = 一个目标 TCP 连接）。
 *
 * 相比旧版的关键改进：
 *   - 状态机独立成模块，可被多条流共享同一条 SSTP 隧道（见 ./pool.js）；
 *   - 校验 seq 连续性：乱序 / 重复段不再被当成新数据写进上层（旧版会损坏数据）；
 *   - 窗口通告随接收缓冲变化，缓冲满时通告 0 窗口做背压（旧版固定 65535）；
 *   - 简化重传：未确认段超时重发，避免隧道内单次丢包就卡死；
 *   - 半关闭：收到 FIN 只关读方向并 ACK，写方向等上层 close() 再发 FIN。
 */




const FLAG_FIN = 0x01;
const FLAG_SYN = 0x02;
const FLAG_RST = 0x04;
const FLAG_PSH = 0x08;
const FLAG_ACK = 0x10;

/** 解析 PPP 内的 IPv4 报文 → TCP 头字段与数据区间（payload 用 IP 总长度裁剪，去掉 padding） */
function parseIpTcp(ip) {
  if (ip.length < 20 || ip[9] !== 6) return null;
  const ihl = (ip[0] & 0x0f) * 4;
  if (ip.length < ihl + 20) return null;
  const total = u16(ip, 2) || ip.length;
  const offset = ihl + ((ip[ihl + 12] >> 4) & 0x0f) * 4;
  const end = Math.min(ip.length, Math.max(offset, total));
  return {
    srcPort: u16(ip, ihl),
    dstPort: u16(ip, ihl + 2),
    seq: u32(ip, ihl + 4),
    ackNum: u32(ip, ihl + 8),
    flags: ip[ihl + 13],
    offset,
    end,
  };
}

/**
 * @param {object} tunnel 隧道句柄（见 ./pool.js）：提供 allocPort / write / sourceBytes / alive
 * @param {string} targetIp 目标 IPv4
 * @param {number} targetPort
 */
function createTcpStream(tunnel, targetIp, targetPort) {
  const sourcePort = tunnel.allocPort();
  const sourceBytes = tunnel.sourceBytes;
  const targetBytes = new Uint8Array(targetIp.split('.').map(Number));

  let seq = randomU32();
  let ack = 0;
  let state = 'syn';                 // syn → established → closed
  let finSent = false;
  let finReceived = false;
  let destroyed = false;

  // --- 发送侧 ---
  const ipHeader = new Uint8Array(20);
  ipHeader.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); // v4/IHL5, DF, TTL64, TCP
  ipHeader.set(sourceBytes, 12);
  ipHeader.set(targetBytes, 16);

  // TCP 伪首部（12 + 报文长度，缓冲区 1432 ⇒ MSS 上限 1400）
  const pseudo = new Uint8Array(1432);
  pseudo.set(sourceBytes);
  pseudo.set(targetBytes, 4);
  pseudo[9] = 6;

  // --- 接收侧（背压缓冲） ---
  const chunks = [];
  let buffered = 0;
  let controller = null;
  let readableDone = false;
  let lastWindow = CONFIG.sstpWindowBytes;

  // --- 重传 ---
  let unacked = [];

  const windowSize = () => {
    const room = CONFIG.sstpBufferBytes - buffered;
    return room <= 0 ? 0 : Math.min(CONFIG.sstpWindowBytes, room);
  };

  /**
   * @param {number} flags
   * @param {Uint8Array} [data]
   * @param {number} [seqValue] 序号覆盖（重传时必须用该段的原始起始 seq）
   */
  const frame = (flags, data = EMPTY, seqValue = seq) => {
    const payloadLength = data.length;
    const tcpLength = 20 + payloadLength;
    const ipLength = 20 + tcpLength;
    const size = 8 + ipLength;
    const packet = new Uint8Array(size);

    // SSTP 头 + PPP(0x0021) + IPv4 头
    packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03, 0x00, 0x21]);
    packet.set(ipHeader, 8);
    setU16(packet, 10, ipLength);
    setU16(packet, 12, randomU16());               // identification
    setU16(packet, 18, checksum(packet, 8, 20));   // IPv4 校验和（字段初值为 0）

    // TCP 头
    setU16(packet, 28, sourcePort);
    setU16(packet, 30, targetPort);
    setU32(packet, 32, seqValue);
    setU32(packet, 36, ack);
    packet[40] = 0x50;                             // data offset = 5 * 4
    packet[41] = flags;
    setU16(packet, 42, windowSize());
    setU16(packet, 44, 0);
    if (payloadLength) packet.set(data, 48);

    pseudo[10] = tcpLength >> 8;
    pseudo[11] = tcpLength & 0xff;
    pseudo.set(packet.subarray(28, 28 + tcpLength), 12);
    setU16(packet, 44, checksum(pseudo, 0, 12 + tcpLength));
    return packet;
  };

  const sendAck = () => {
    if (destroyed || !tunnel.alive) return;
    lastWindow = windowSize();
    tunnel.write(frame(FLAG_ACK));
  };

  const sendFin = () => {
    if (finSent || destroyed) return;
    finSent = true;
    tunnel.write(frame(FLAG_FIN | FLAG_ACK));
    seq = (seq + 1) >>> 0;
  };

  const closeReadable = () => {
    if (readableDone) return;
    readableDone = true;
    try { controller?.close(); } catch {}
  };

  const drain = () => {
    if (!controller) return;
    while (chunks.length && !readableDone) {
      const chunk = chunks.shift();
      buffered -= chunk.byteLength;
      controller.enqueue(chunk);
    }
    // 之前通告过 0 窗口、现在有空间了 → 主动发窗口更新
    if (lastWindow === 0 && windowSize() > 0 && !destroyed && tunnel.alive) sendAck();
    if (finReceived && !chunks.length && !readableDone) closeReadable();
  };

  const push = data => {
    if (!data.byteLength) return;
    chunks.push(data);
    buffered += data.byteLength;
    drain();
  };

  /**
   * 记录一个未确认段。存「起始 seq + flags + 载荷」而不是整帧：
   * 重传时需要用**当前**的 ack 与窗口重新构造，重发旧帧会把过期的
   * window（可能是 0）再发一遍，导致双方互等死锁。
   */
  const recordUnacked = (startSeq, endSeq, flags, data) => {
    if (!CONFIG.sstpRetransmit) return;
    unacked.push({ start: startSeq, end: endSeq, flags, data, time: Date.now(), retries: 0 });
    if (unacked.length > 64) unacked.shift();
  };

  /**
   * 清掉已被确认的段。
   * 只在「确认号落在我们已发送范围内」时才生效：异常确认号（0、远超 snd_nxt 等）
   * 与序号回绕叠加时会把未确认段误判为已确认，导致丢包不重传。
   */
  const clearUnacked = ackNum => {
    if (!unacked.length) return;
    if (!seqLE(ackNum, seq)) return;
    unacked = unacked.filter(item => seqLT(ackNum, item.end));
  };

  /** 由隧道读循环 / 看门狗定期调用 */
  const checkRetransmit = () => {
    if (!CONFIG.sstpRetransmit || !unacked.length || destroyed || !tunnel.alive) return;
    const now = Date.now();
    for (const item of unacked) {
      if (now - item.time < CONFIG.sstpRtoMs) continue;
      if (item.retries >= CONFIG.sstpMaxRetries) { destroy(new Error('sstp: retransmit exceeded')); return; }
      item.retries += 1;
      item.time = now;
      tunnel.write(frame(item.flags, item.data, item.start));
    }
  };

  // --- 握手 ---
  let settle = null;
  const handshakePromise = new Promise((resolve, reject) => { settle = { resolve, reject }; });

  /** @param {number} [timeoutMs] 拨号方给的超时；0 表示用 CONFIG.sstpHandshakeMs */
  const handshake = async (timeoutMs = 0) => {
    const syn = frame(FLAG_SYN);
    recordUnacked(seq, (seq + 1) >>> 0, FLAG_SYN, EMPTY);
    await tunnel.write(syn);
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('sstp: tcp handshake timeout')), timeoutMs || CONFIG.sstpHandshakeMs);
    });
    try { return await Promise.race([handshakePromise, timeout]); }
    finally { clearTimeout(timer); }
  };

  // --- 收包 ---
  const deliver = (info, ip) => {
    if (destroyed) return;

    if (state === 'syn') {
      if (info.flags & FLAG_RST) { destroy(new Error('sstp: rst')); return; }
      if ((info.flags & (FLAG_SYN | FLAG_ACK)) !== (FLAG_SYN | FLAG_ACK)) return;
      ack = (info.seq + 1) >>> 0;
      seq = (seq + 1) >>> 0;               // SYN 消耗一个序号
      state = 'established';
      clearUnacked(info.ackNum);           // 用 SYN-ACK 的确认号清 unacked，不是用对端 seq
      sendAck();
      settle?.resolve(true);
      return;
    }
    if (state !== 'established') return;

    if (info.flags & FLAG_RST) { destroy(new Error('sstp: rst')); return; }
    if (info.flags & FLAG_ACK) clearUnacked(info.ackNum);

    let needAck = false;
    const length = info.end - info.offset;

    if (length > 0 && !finReceived) {
      if (info.seq === ack) {
        // 只有序号连续的段才交给上层；乱序 / 重传段一律丢弃（对端会重传）
        ack = (ack + length) >>> 0;
        push(ip.subarray(info.offset, info.end));
      }
      needAck = true;
    }
    if (info.flags & FLAG_FIN && !finReceived) {
      finReceived = true;
      ack = (ack + 1) >>> 0;               // FIN 也占一个序号
      needAck = true;
      closeReadable();
    }
    if (needAck) sendAck();
  };

  const destroy = err => {
    if (destroyed) return;
    destroyed = true;
    state = 'closed';
    chunks.length = 0;
    buffered = 0;
    unacked = [];
    closeReadable();
    try { settle?.reject(err || new Error('sstp: stream closed')); } catch {}
    tunnel.removeStream(sourcePort);
  };

  /** ReadableStream 的 queuing strategy：按字节计，配合窗口做背压 */
  const strategy = { highWaterMark: CONFIG.sstpBufferBytes, size: chunk => chunk.byteLength };

  const readable = new ReadableStream({
    start(stream) { controller = stream; },
    pull() { drain(); },
    cancel() { destroy(new Error('sstp: readable cancelled')); },
  }, strategy);

  const writable = new WritableStream({
    async write(chunk) {
      if (destroyed || !tunnel.alive) throw new Error('sstp: stream closed');
      const data = toU8(chunk);
      if (!data.byteLength) return;
      // 统一按 MSS 分片：每段单独记录 unacked（重传时才能只重发一段），
      // 但一次性 concat 写出，减少 write 次数
      const frames = [];
      for (let offset = 0; offset < data.length; offset += CONFIG.mss) {
        const segment = data.subarray(offset, Math.min(offset + CONFIG.mss, data.length));
        const start = seq;
        frames.push(frame(FLAG_PSH | FLAG_ACK, segment));
        seq = (seq + segment.length) >>> 0;
        recordUnacked(start, seq, FLAG_PSH | FLAG_ACK, segment);
      }
      await tunnel.write(frames.length === 1 ? frames[0] : concat(...frames));
      checkRetransmit();
    },
    close() { sendFin(); },
    abort() { destroy(new Error('sstp: writable aborted')); },
  });

  return {
    sourcePort,
    readable,
    writable,
    handshake,
    deliver,
    checkRetransmit,
    destroy,
    get state() { return state; },
  };
}

/* ------------------------------- src/sstp/pool.js ------------------------------- */
/**
 * SSTP 隧道池：同一 isolate 内按「服务器」复用 PPP 隧道，一条隧道可并发承载多条目标 TCP 流。
 *
 * 这是 SSTP 路径最大的延迟优化：
 *   旧版每来一个连接都要重跑一遍
 *     TCP+TLS 握手 → SSTP_DUPLEX_POST → LCP → PAP → IPCP → 隧道内 TCP 三次握手
 *   （全部串行 await，一次冷路径动辄数秒）；复用后只有建池的第一条连接付这个代价，
 *   后续连接只在隧道内做一次 TCP 三次握手（通常 1 个 RTT）。
 *
 * 同时保留退化开关：CONFIG.sstpReuseTunnel = false 时回到「一连接一隧道」。
 */







const TUNNELS = new Map();
const INFLIGHT = new Map();

const keyOf = server => `${server.username || ''}:${server.password || ''}@${server.host}:${server.port}`;

function createTunnel(server, key) {
  const client = createSstpClient(server.username, server.password);
  const streams = new Map();
  let sourceBytes = null;
  let nextPort = 10000 + (randomU16() % 50000);
  let alive = false;
  let busy = 0;               // 已占用的流槽位（acquire 时 +1，release 时 -1），用于容量判断
  let watchdog = 0;
  let lastActivity = Date.now();

  const allocPort = () => {
    for (let i = 0; i < 50000; i++) {
      const port = 10000 + ((nextPort++ - 10000) % 50000);
      if (!streams.has(port)) return port;
    }
    throw new Error('sstp: no free port');
  };

  /** 写失败说明隧道已废：记日志并销毁，别让上层以为发出去了 */
  const failWrite = err => {
    log('sstp write failed', key, err?.message || err);
    if (alive) destroy(err);
  };

  const write = bytes => {
    lastActivity = Date.now();   // 只上传不下载的流也要算活跃，否则会被空闲回收误杀
    try { return client.writer.write(bytes)?.catch?.(failWrite) ?? Promise.resolve(); }
    catch (err) { failWrite(err); return Promise.resolve(); }
  };

  const stopWatchdog = () => { if (watchdog) { clearTimeout(watchdog); watchdog = 0; } };

  // destroy 必须总是关掉底层 socket：建链失败（超时 / 抛错）时同样要走这里，
  // 否则 connect 姗姗来迟会留下一个没人管的 TLS socket
  const destroy = err => {
    const wasAlive = alive;
    alive = false;
    stopWatchdog();
    TUNNELS.delete(key);
    const pending = [...streams.values()];
    streams.clear();
    for (const stream of pending) { try { stream.destroy(err); } catch {} }
    client.close();
    if (wasAlive || pending.length) log('sstp tunnel closed', key, err?.message || err || 'closed');
  };

  /** 空闲回收 + 重传看门狗（用可重排的 setTimeout，避免长驻 setInterval） */
  const tick = () => {
    const idleFor = Date.now() - lastActivity;
    const limit = streams.size ? CONFIG.sstpStreamIdleMs : CONFIG.sstpIdleMs;
    // 只看「多久没有动静」：有流却长期无数据（客户端半死）同样要回收
    if (idleFor >= limit) { destroy(new Error('sstp: idle')); return; }
    for (const stream of streams.values()) { try { stream.checkRetransmit(); } catch {} }
    watchdog = setTimeout(tick, Math.min(limit, 15000));
  };

  const armWatchdog = () => {
    stopWatchdog();
    watchdog = setTimeout(tick, Math.min(streams.size ? CONFIG.sstpStreamIdleMs : CONFIG.sstpIdleMs, 15000));
  };

  /** 隧道读循环：唯一消费 client.buffer 的地方，按目的端口分发到各条流 */
  const run = async () => {
    try {
      for (;;) {
        const packet = await client.readPacket(0); // 0 = 不设读超时（超时会破坏 buffer 连续性）
        lastActivity = Date.now();
        if (packet.ctrl) continue;
        const ppp = client.parsePPP(packet.body);
        if (!ppp || ppp.protocol !== PPP_IPV4) continue;
        const info = parseIpTcp(ppp.ip);
        if (!info) continue;
        const stream = streams.get(info.dstPort);
        if (!stream) continue;
        stream.deliver(info, ppp.ip);
        stream.checkRetransmit();
      }
    } catch (err) {
      destroy(err);
    }
  };

  /**
   * @param {number} [timeoutMs] 建链超时；0 表示用 CONFIG.sstpConnectMs 兜底
   */
  const start = async (timeoutMs = 0) => {
    await withTimeout(
      (async () => {
        await client.connect(server.host, server.port);
        const myIp = await client.establish();
        sourceBytes = new Uint8Array(myIp.split('.').map(Number));
      })(),
      timeoutMs || CONFIG.sstpConnectMs,
      'sstp: connect timeout',
    );
    alive = true;
    lastActivity = Date.now();
    armWatchdog();
    void run();
  };

  const api = {
    start,
    allocPort,
    write,
    destroy,
    get alive() { return alive; },
    get load() { return busy; },   // 已预留的流槽位数（并发 acquire 时用于容量判断）
    get sourceBytes() { return sourceBytes; },
    get streams() { return streams; },
    removeStream(port) {
      if (!streams.delete(port)) return;
      lastActivity = Date.now();
    },
    acquire() {
      busy += 1;
      lastActivity = Date.now();
      armWatchdog();
    },
    release() {
      busy -= 1;
      lastActivity = Date.now();
      if (!CONFIG.sstpReuseTunnel) { destroy(new Error('sstp: reuse disabled')); return; }
      armWatchdog();
    },
  };

  return api;
}

async function acquireTunnel(server, timeoutMs = 0) {
  const key = keyOf(server);

  if (CONFIG.sstpReuseTunnel) {
    const existing = TUNNELS.get(key);
    // 用 load（已预留槽位）而不是 streams.size：并发 acquire 时槽位已被占住，
    // 否则多个请求会同时判定「还没满」而挤爆单条隧道
    if (existing?.alive && existing.load < CONFIG.sstpMaxStreams) {
      existing.acquire();
      return existing;
    }
    const inflight = INFLIGHT.get(key);
    if (inflight) {
      try {
        const tunnel = await inflight;
        if (tunnel.alive && tunnel.load < CONFIG.sstpMaxStreams) { tunnel.acquire(); return tunnel; }
      } catch { /* 建隧道失败，继续自己建一条 */ }
    }
  }

  const task = (async () => {
    const tunnel = createTunnel(server, key);
    try {
      await tunnel.start(timeoutMs);
    } catch (err) {
      tunnel.destroy(err);   // 建链失败也要关 socket，否则泄漏
      throw err;
    }
    if (CONFIG.sstpReuseTunnel) TUNNELS.set(key, tunnel);
    return tunnel;
  })();
  INFLIGHT.set(key, task);
  try {
    const tunnel = await task;
    tunnel.acquire();
    return tunnel;
  } finally {
    INFLIGHT.delete(key);
  }
}

/**
 * SSTP 出站：复用（或新建）隧道 → 隧道内开一条 TCP 流 → 三次握手
 * 返回 { readable, writable, close }，失败返回 null。
 */
async function sstpConnect(server, targetHost, targetPort, timeoutMs = 0) {
  let tunnel = null;
  let stream = null;
  const teardown = () => {
    if (stream) { try { tunnel?.removeStream(stream.sourcePort); stream.destroy(); } catch {} stream = null; }
    if (tunnel) { try { tunnel.release(); } catch {} tunnel = null; }
  };

  try {
    const targetIp = await resolveIPv4(targetHost);
    tunnel = await acquireTunnel(server, timeoutMs);
    if (!tunnel.alive) throw new Error('sstp: tunnel dead');

    stream = createTcpStream(tunnel, targetIp, targetPort);
    tunnel.streams.set(stream.sourcePort, stream);
    try {
      // 拨号方给的超时同样约束隧道内握手，否则复用隧道时会退化成 sstpHandshakeMs
      await stream.handshake(timeoutMs);
    } catch (err) {
      try { tunnel.removeStream(stream.sourcePort); stream.destroy(); } catch {}
      stream = null;
      throw err;
    }

    let closed = false;
    const close = () => { if (closed) return; closed = true; teardown(); };
    return { readable: stream.readable, writable: stream.writable, close };
  } catch (err) {
    log('sstp failed', server.host, server.port, err?.message || err);
    teardown();
    return null;
  }
}

/* ------------------------------- src/outbound.js ------------------------------- */
/**
 * 出站调度：只有 SSTP 与 ProxyIP 两种落地。
 */







let txtDomain = null;
let txtEntries = null;

/**
 * 解析落地地址，只支持两种出站：
 *   sstp://host:443             → SSTP（VPN Gate / SoftEther）
 *   sstp://user:pass@host:443   → 自定义 PAP 认证的 SSTP
 *   1.2.3.4:443 / [v6]:443      → ProxyIP
 *   纯域名（默认 443）           → ProxyIP
 * 其它带协议的写法（socks5://、http(s)://、turn://…）一律视为不支持，返回 null。
 */
function parseProxyAddress(raw) {
  const input = String(raw || '').trim();
  if (!input) return null;

  if (/^sstp:\/\//i.test(input)) {
    try {
      const url = new URL(input);
      return {
        type: 'sstp',
        host: url.hostname,
        port: parseInt(url.port, 10) || 443,
        username: url.username ? decodeURIComponent(url.username) : CONFIG.sstpUser,
        password: url.password ? decodeURIComponent(url.password) : CONFIG.sstpPass,
      };
    } catch { return null; }
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) return null; // 其它协议不再支持

  const bracketed = input.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    const port = parseInt(bracketed[2], 10);
    return { type: 'proxyip', host: bracketed[1], port: !isNaN(port) && port > 0 ? port : 443 };
  }
  const colon = input.lastIndexOf(':');
  if (colon > 0) {
    const port = parseInt(input.slice(colon + 1), 10);
    if (!isNaN(port) && port > 0 && port <= 65535) return { type: 'proxyip', host: input.slice(0, colon), port };
  }
  return { type: 'proxyip', host: input, port: 443 };
}

/**
 * 把落地字符串解析成最多 count 个候选 { type: 'sstp' | 'proxyip', host, port, ... }。
 * `域名!txt`：从该域名 TXT 记录里随机取不重复的若干条（值可以是 sstp:// 或 ProxyIP），带缓存。
 */
async function resolveProxyCandidates(raw, count = 1) {
  const text = String(raw || '').trim();
  if (!text) return [];

  if (!text.toLowerCase().endsWith('!txt')) {
    const single = parseProxyAddress(text);
    return single ? [single] : [];
  }

  const domain = text.slice(0, -4).trim();
  let list = null;
  try {
    if (txtDomain !== domain || !txtEntries) {
      const resolved = await resolveTXT(domain);
      if (resolved.length) { txtDomain = domain; txtEntries = resolved; }
    }
    if (txtEntries?.length) list = txtEntries;
  } catch { /* 解析失败就把域名本身当 ProxyIP */ }

  if (!list?.length) return [{ type: 'proxyip', host: domain, port: 443 }];

  const limit = Math.max(1, Math.min(count, list.length));
  const picked = new Set();
  for (let guard = 0; picked.size < limit && guard < limit * 10; guard++) {
    picked.add(list[Math.floor(Math.random() * list.length)]);
  }
  const entries = [...picked].map(parseProxyAddress).filter(Boolean);
  return entries.length ? entries : [{ type: 'proxyip', host: domain, port: 443 }];
}

/**
 * 落地失败负缓存。
 * 「先落地后直连」的顺序下，一个不可达的落地会让**每个**请求都先耗掉 dialTimeoutMs。
 * 连续失败若干次后，冷却期内直接跳过落地，省掉这段白等的延迟。
 */
const LANDING_FAILS = new Map();

const landingKey = proxy => String(proxy || CONFIG.proxyip).trim();
const landingCooling = key => (LANDING_FAILS.get(key)?.until ?? 0) > Date.now();

const noteLandingResult = (key, failed) => {
  if (!failed) { LANDING_FAILS.delete(key); return; }
  const item = LANDING_FAILS.get(key) || { fails: 0, until: 0 };
  item.fails += 1;
  if (item.fails >= CONFIG.dialFailThreshold) {
    item.until = Date.now() + CONFIG.dialFailCooldownMs;
    log('landing cooling down', key, `${CONFIG.dialFailCooldownMs}ms`);
  }
  LANDING_FAILS.set(key, item);
};

/**
 * 通过某个落地候选建连。
 * @param {number} timeoutMs 0 表示不设超时
 */
async function dialViaEntry(entry, targetHost, targetPort, timeoutMs) {
  log('dial', `${targetHost}:${targetPort}`, 'via', entry.type, `${entry.host}:${entry.port}`);
  try {
    // SSTP：复用隧道，隧道内手搓 IPv4/TCP 连目标
    if (entry.type === 'sstp') return await sstpConnect(entry, targetHost, targetPort, timeoutMs);
    // ProxyIP：直连该 IP/域名，由它按 SNI 反代到真正的目标
    return await tcpConnect(entry.host, entry.port, timeoutMs);
  } catch (err) {
    log('dial error', err?.message || err);
    return null;
  }
}

/**
 * 并发竞速拨号：所有候选同时拨，谁先「就绪」就用谁，其余立即关闭。
 * @param {Array<() => Promise<{readable,writable,close}|null>>} dialers
 *
 * 关于「就绪」的判定（对应"谁先传回实际数据、非握手信息"）：
 *   - SSTP 候选：`sstpConnect()` 返回前已完成**隧道内 TCP 三次握手**（拿到目标的 SYN+ACK），
 *     也就是说它证明的是"目标真的可达"，而不只是 SSTP/PPP 握手成功；
 *   - ProxyIP / 直连候选：只完成到 TCP 连接建立，目标是后端按 SNI 反代的，无法提前验证。
 * 因此竞速时 SSTP 候选的门槛更严格，这也是它更可信的原因。
 */
async function raceDial(dialers) {
  if (!dialers.length) return null;
  if (dialers.length === 1) return dialers[0]();

  let settled = false;
  let remaining = dialers.length;
  return new Promise(resolve => {
    const finish = value => { if (settled) return; settled = true; resolve(value); };
    for (const dial of dialers) {
      dial().then(
        conn => {
          if (settled) { tryClose(conn); return; }   // 输家：立刻收摊，别占着连接
          if (conn) { finish(conn); return; }
          if (--remaining === 0) finish(null);
        },
        () => { if (--remaining === 0) finish(null); },
      );
    }
  });
}

/** 目标端口是否允许代理（CONFIG.blockedPorts 为空表示不限制） */
function portAllowed(port) {
  const blocked = CONFIG.blockedPorts;
  if (!blocked?.length) return true;
  return !blocked.includes(Number(port));
}

/**
 * 建立出站连接。
 * @param {string} targetHost  客户端请求的目标
 * @param {number} targetPort
 * @param {string} proxy       落地地址（空则用 CONFIG.proxyip）
 * @param {string} globalMode  '1' 表示只走落地，否则先落地、超时后再直连
 * @param {object} [options]   { race?: boolean }
 * @returns {Promise<{readable, writable, close}|null>} 失败返回 null
 */
async function dialOutbound(targetHost, targetPort, proxy, globalMode, options = {}) {
  // 竞速由请求参数 ?race=1 决定（入口传入），不传则串行回落
  const race = options.race ?? false;

  if (!portAllowed(targetPort)) {
    log('blocked port', targetPort);
    return null;
  }

  // global=1 只走落地：没有"超时后回落直连"这一说了，
  // 落地建连不该被 dialTimeoutMs 掐断 —— 这里直接关掉超时（0 = 不设超时）。
  const timeout = globalMode === '1' ? 0 : CONFIG.dialTimeoutMs;

  const key = landingKey(proxy);
  // 落地处于冷却期且不是「只走落地」模式 → 本次直接跳过落地
  const skipLanding = globalMode !== '1' && landingCooling(key);

  let entries = [];
  if (!skipLanding) {
    entries = await resolveProxyCandidates(proxy || CONFIG.proxyip, Math.max(1, CONFIG.dialRaceCandidates));
    if (!entries.length) {
      log('unsupported proxy', proxy);
      return null;
    }
  }
  // 非竞速模式只取第一个候选，保持旧行为
  const useEntries = race ? entries : entries.slice(0, 1);

  let landingFailed = !useEntries.length && !skipLanding;
  const dialers = [];
  // ① 先走落地（顺序在直连之前）
  for (const entry of useEntries) {
    dialers.push(async () => {
      const conn = await dialViaEntry(entry, targetHost, targetPort, timeout);
      if (!conn) landingFailed = true;
      return conn;
    });
  }
  // ② 落地失败 / 超时 / 冷却后再直连
  if (globalMode !== '1') {
    dialers.push(() => tcpConnect(targetHost, targetPort, timeout).catch(() => null));
  }

  const conn = race && dialers.length > 1 ? await raceDial(dialers) : await serialDial(dialers);
  if (!skipLanding) noteLandingResult(key, landingFailed);
  return conn;
}

/** 串行兜底：依次尝试，第一个成功的胜出 */
async function serialDial(dialers) {
  for (const dial of dialers) {
    const conn = await dial();
    if (conn) return conn;
  }
  return null;
}

/* ------------------------------- src/vless.js ------------------------------- */
/**
 * VLESS 入站解析：地址编解码、请求头解析、握手探测、Early Data、path 落地解析。
 */




const formatAddress = (type, bytes) =>
  type === 1
    ? `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`
    : type === 3
      ? decoder.decode(bytes)
      : `[${Array.from({ length: 8 }, (_, i) => u16(bytes, i * 2).toString(16)).join(':')}]`;

const parseAddress = (buffer, offset, type) => {
  const length = type === 3 ? buffer[offset++] : type === 1 ? 4 : type === 4 ? 16 : 0;
  if (!length || offset + length > buffer.length) return null;
  return { bytes: buffer.subarray(offset, offset + length), offset: offset + length };
};

/** UUID 比对：VLESS 头的第 1~16 字节 */
const matchUuid = (buffer, uuidBytes) => {
  for (let i = 0; i < 16; i++) if (buffer[i + 1] !== uuidBytes[i]) return false;
  return true;
};

/** VLESS 请求头 → { host, port, payload, responsePrefix, udp } */
function parseVlessHeader(buffer, uuidBytes) {
  if (buffer.byteLength < 24 || !matchUuid(buffer, uuidBytes)) return null;

  const base = 19 + buffer[17]; // 1(ver) + 16(uuid) + 1(addonLen) + addon + 1(cmd)
  if (base + 3 > buffer.byteLength) return null;

  let addrType = buffer[base + 2];
  const port = (buffer[base] << 8) | buffer[base + 1];
  if (addrType !== 1) addrType += 1; // 标准：1=IPv4 2=域名 3=IPv6 → 内部：1 / 3 / 4

  const parsed = parseAddress(buffer, base + 3, addrType);
  if (!parsed) return null;

  return {
    host: formatAddress(addrType, parsed.bytes),
    port,
    payload: buffer.subarray(parsed.offset),
    responsePrefix: new Uint8Array([buffer[0], 0]), // 版本 + 附加长度 0
    udp: buffer[18 + buffer[17]] === 2,
  };
}

/**
 * 握手阶段判定：0=数据不足 1=VLESS 3=非法
 * @param {boolean} [prefixChecked] 前 16 字节 UUID 已校验过时可跳过比对
 */
function detectInbound(buffer, uuidBytes, prefixChecked = false) {
  if (!prefixChecked) {
    const limit = Math.min(buffer.byteLength, 17);
    for (let i = 1; i < limit; i++) if (buffer[i] !== uuidBytes[i - 1]) return 3;
  }
  if (parseVlessHeader(buffer, uuidBytes)) return 1;
  return buffer.byteLength < CONFIG.hsMax ? 0 : 3;
}

/** 从 sec-websocket-protocol（早期数据）与 Referer 中取出 base64url 数据 */
function extractEarlyData(request) {
  const candidates = [request.headers.get('sec-websocket-protocol')];
  const referer = request.headers.get('Referer');
  if (referer) candidates.push(referer.slice((request.headers.get('host') || '').length));

  for (const raw of candidates) {
    try {
      if (!raw || raw.length > 4 * Math.ceil(CONFIG.maxED / 3)) continue;
      const bytes =
        typeof Uint8Array.fromBase64 === 'function'
          ? Uint8Array.fromBase64(raw, { alphabet: 'base64url' })
          : Uint8Array.from(
            atob(raw.replace(/-/g, '+').replace(/_/g, '/') + '===='.slice(0, (4 - (raw.length % 4)) % 4)),
            char => char.charCodeAt(0),
          );
      if (bytes.byteLength && bytes.byteLength <= CONFIG.maxED) return bytes;
    } catch { /* 非 base64url，跳过 */ }
  }
  return null;
}

/**
 * 从 path 里取出落地地址：`/fdip=<落地>?ed=2560`
 * 键名任意（fdip / proxy / p…），值就是落地；取不到返回 null。
 */
function parsePathProxy(url) {
  let raw = url.pathname + (url.search || '');
  if (raw.startsWith('/')) raw = raw.slice(1);
  try { raw = decodeURIComponent(raw); } catch { /* 保持原样 */ }

  const queryAt = raw.indexOf('?');
  const main = queryAt < 0 ? raw : raw.slice(0, queryAt);
  const equalAt = main.indexOf('=');
  if (equalAt <= 0) return null;

  const value = main.slice(equalAt + 1).trim();
  if (!value) return null;

  // 值只可能是 sstp://host:port 或 ProxyIP（host:port / 域名）
  const scheme = value.match(/^sstp:\/\/[^/?#]+/i);
  if (scheme) return scheme[0];
  const slash = value.indexOf('/');
  return slash >= 0 ? value.slice(0, slash).trim() : value;
}

/** 布尔开关：`?key=1|true|on` → true，其它 → false */
function parseFlag(url, request, key) {
  const raw = url.searchParams.get(key) ?? request?.headers?.get(`x-${key}`) ?? '';
  const text = String(raw).trim().toLowerCase();
  return text === '1' || text === 'true' || text === 'on' || text === 'yes';
}

/* ------------------------------- src/queue.js ------------------------------- */
/**
 * 数据队列与下行发送：上行分片入队 / 出队合并，下行攒包 + 背压感知。
 */





/**
 * isolate 级的上行队列总预算。
 * 旧版只有「单连接 8MB」上限，并发一多就会被多连接叠加吃光内存；
 * 这里再加一层全局预算，超了就拒收（上层随即冲刷或断流）。
 */
let TOTAL_BYTES = 0;

/** 上行队列：按 CONFIG.upPack 切片入队，出队时尽量合并成一个大包 */
function createQueue(maxSize) {
  let items = [];
  let head = 0;
  let bytes = 0;
  let waiter = null;
  let wake = null;
  let scratch = null;

  const isEmpty = () => head >= items.length;
  const compact = () => { if (head > 32 && head * 2 >= items.length) { items = items.slice(head); head = 0; } };
  const take = () => {
    if (isEmpty()) return null;
    const item = items[head];
    items[head++] = undefined;
    bytes -= item.byteLength;
    TOTAL_BYTES -= item.byteLength;
    compact();
    return item;
  };

  return {
    empty: isEmpty,
    get size() { return bytes; },
    get wait() { return waiter; },
    clear() {
      items = []; head = 0;
      TOTAL_BYTES -= bytes;
      bytes = 0;
      wake?.(); wake = waiter = null;
    },
    push(chunk) {
      const length = chunk?.byteLength || 0;
      if (!length) return false;
      if (bytes + length > CONFIG.maxQueueBytes) return false;          // 单连接上限
      if (TOTAL_BYTES + length > CONFIG.maxQueueTotalBytes) return false; // 全局预算
      items.push(chunk);
      bytes += length;
      TOTAL_BYTES += length;
      if (bytes >= CONFIG.queueWakeBytes) waiter ||= new Promise(resolve => { wake = resolve; }); // 反压信号
      return true;
    },
    pack(first) {
      let item = first || take();
      if (!item || isEmpty()) return item || null;
      let total = item.byteLength;
      let index = head;
      while (index < items.length) {
        const next = items[index].byteLength;
        if (total + next > maxSize) break;
        total += next;
        index++;
      }
      if (index === head) return item;
      const out = (scratch ||= new Uint8Array(maxSize));
      out.set(item);
      let offset = item.byteLength;
      while (head < index) {
        const chunk = items[head];
        items[head++] = undefined;
        bytes -= chunk.byteLength;
        TOTAL_BYTES -= chunk.byteLength;
        out.set(chunk, offset);
        offset += chunk.byteLength;
      }
      compact();
      return out.slice(0, total);
    },
    drain() { if (bytes <= CONFIG.queueDrainBytes) { wake?.(); wake = waiter = null; } },
  };
}

/** 下行发送器：攒包 + 背压感知 + 自适应冲刷，减少 WebSocket 小包 */
function createDownstreamSender(ws) {
  const maxPack = CONFIG.dnPack;
  const tail = CONFIG.dnTail;
  const queue = createQueue(maxPack);
  let timer = 0;
  // 吞吐估算：交互流量（低速率）立即冲刷，大流量才攒包等 dnMs
  let rate = 0;
  let lastFlushAt = Date.now();
  let bytesSinceFlush = 0;

  const emit = chunk => { if (ws.readyState === WebSocket.OPEN) ws.send(chunk); };
  const noteFlush = () => {
    const now = Date.now();
    const elapsed = Math.max(1, now - lastFlushAt);
    rate = rate ? rate * 0.7 + ((bytesSinceFlush * 1000) / elapsed) * 0.3 : (bytesSinceFlush * 1000) / elapsed;
    lastFlushAt = now;
    bytesSinceFlush = 0;
  };
  const flush = () => {
    if (timer) { clearTimeout(timer); timer = 0; }
    noteFlush();
    for (;;) {
      const chunk = queue.pack();
      if (!chunk) break;
      emit(chunk);
    }
  };

  return {
    send(data) {
      let offset = 0;
      const length = data?.byteLength || 0;
      if (!length) return;
      bytesSinceFlush += length;
      while (offset < length) {
        const room = maxPack - queue.size;
        const size = Math.min(room, length - offset);
        if (!size) { flush(); continue; }
        const slice = offset || size !== length ? data.subarray(offset, offset + size) : data;
        if (!queue.push(slice)) { flush(); if (!queue.push(slice)) break; }
        offset += size;
        if (queue.size >= maxPack || maxPack - queue.size < tail || !ws.bufferedAmount) flush();
        else {
          const delay = CONFIG.dnAdaptive && rate < CONFIG.dnAdaptiveBps ? 0 : CONFIG.dnMs;
          timer ||= setTimeout(flush, queue.size >= maxPack >> 1 ? delay : 0);
        }
      }
    },
    fastSend: emit,
    reap: flush,
  };
}

/** 落地 readable → WebSocket（byob 读 + 背压等待） */
async function pipeToWebSocket(readable, ws) {
  let reader;
  let byob = false;
  try { reader = readable.getReader({ mode: 'byob' }); byob = true; } catch { reader = readable.getReader(); }

  const sender = createDownstreamSender(ws);
  const waitBackpressure = async () => {
    while (ws.readyState === WebSocket.OPEN && ws.bufferedAmount > CONFIG.wsBackpressureBytes) {
      const delay = ws.bufferedAmount > CONFIG.wsBackpressureBytes * 2 ? 8 : 2;
      await (globalThis.scheduler?.wait?.(delay) ?? new Promise(resolve => setTimeout(resolve, delay)));
      if (ws.bufferedAmount <= CONFIG.wsBackpressureReleaseBytes) break;
    }
  };
  const finish = () => {
    releaseLock(reader);
    try { ws.close(1000, ''); } catch {}
  };

  // BYOB 的 buffer 在 read 后会被转移/分离，只在 byob 分支需要重建；非 byob 分支用不到
  let buffer = byob ? new ArrayBuffer(CONFIG.chunk) : EMPTY.buffer;
  try {
    for (;;) {
      if (ws.readyState !== WebSocket.OPEN) break;
      await waitBackpressure();
      const { done, value } = byob ? await reader.read(new Uint8Array(buffer)) : await reader.read();
      if (done) break;
      if (value?.byteLength) {
        if (value.byteLength >= CONFIG.chunk >> 1) {
          sender.reap();          // 大块：先把攒着的发掉，再整块直发
          sender.fastSend(value);
        } else {
          sender.send(value);
        }
        if (byob) buffer = new ArrayBuffer(CONFIG.chunk);
      }
    }
    sender.reap();
  } catch {
    /* 连接已断开 */
  } finally {
    try { sender.reap(); } catch {}
    finish();
  }
}

async function sendDnsResponse(query, ws, host, port) {
  try {
    const answer = await dnsOverTcp(query, host, port);
    if (answer?.byteLength && ws.readyState === WebSocket.OPEN) ws.send(answer);
  } catch { /* 忽略 */ }
}

/* ------------------------------- src/ws.js ------------------------------- */
/**
 * 入站：VLESS over WebSocket。
 *
 * 流程：Early Data / message 入队 → 攒齐 VLESS 头 → 建出站连接 → 双向转发；
 * UDP 只放行 53 端口（转 TCP DNS）。
 */







async function handleWebSocket(request, uuidBytes, proxy, globalMode, options = {}) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.binaryType = 'arraybuffer';
  server.accept({ allowHalfOpen: true });

  const remote = { socket: null, writer: null };
  const queue = createQueue(CONFIG.upPack);

  let closed = false;
  let running = false;
  let handshakeDone = false;
  let prefixChecked = false;
  let dnsMode = false;
  let dnsTarget = null;
  let earlyBuffer = null;
  let timer = setTimeout(() => { if (!handshakeDone) close(1000); }, CONFIG.wsHandshakeTimeout);

  /** 数据入队（按 upPack 切片），队列满返回 0 */
  const feed = data => {
    if (!data?.byteLength) return 1;
    for (let offset = 0, total = data.byteLength; offset < total;) {
      const size = Math.min(CONFIG.upPack, total - offset);
      if (!queue.push(offset || size !== total ? data.subarray(offset, offset + size) : data)) return 0;
      offset += size;
    }
    return 1;
  };

  function close(code = 1000) {
    if (typeof code !== 'number') code = 1000;
    if (closed) return;
    closed = true;
    queue.clear();
    if (timer) { clearTimeout(timer); timer = 0; }
    try { remote.writer?.close(); } catch {}
    releaseLock(remote.writer);
    tryClose(remote.socket);
    try { server.close(code, ''); } catch {}
  }

  /** 消费队列：握手 → 建连 → 转发 */
  async function pump() {
    if (running || closed) return;
    running = true;
    try {
      while (!closed) {
        if (dnsMode) {
          // UDP(53)：后续每个包都是一次独立 DNS 查询
          const query = queue.pack();
          if (!query) break;
          await sendDnsResponse(query, server, dnsTarget.host, dnsTarget.port);
          queue.drain();
          continue;
        }
        if (!remote.socket) {
          const head = queue.pack();
          if (!head) break;
          const session = parseVlessHeader(head, uuidBytes);
          if (!session) throw new Error('bad vless header');

          if (session.responsePrefix.byteLength) server.send(session.responsePrefix);

          if (session.udp) {
            if (session.port !== 53) throw new Error('udp only for dns');
            dnsMode = true;
            dnsTarget = { host: session.host, port: session.port };
            await sendDnsResponse(session.payload, server, dnsTarget.host, dnsTarget.port);
            queue.drain();
            continue;
          }

          const socket = await dialOutbound(session.host, session.port, proxy, globalMode, options);
          if (!socket) throw new Error('dial failed');
          if (closed) { tryClose(socket); break; }

          remote.socket = socket;
          remote.writer = socket.writable.getWriter();
          pipeToWebSocket(socket.readable, server).catch(() => close(1011));

          const payload = queue.pack(session.payload);
          if (payload?.byteLength) await remote.writer.write(payload);
          queue.drain();
          continue;
        }

        const chunk = queue.pack();
        if (!chunk) break;
        await remote.writer.write(chunk);
        queue.drain();
      }
    } catch (err) {
      log('ws pump error', err?.message || err);
      close(1011);
    } finally {
      running = false;
      if (!queue.empty() && !closed) pump();
    }
  }

  const onData = data => {
    if (closed) return;
    let chunk = toU8(data);
    if (!chunk.byteLength) return;

    if (!handshakeDone) {
      earlyBuffer = earlyBuffer?.byteLength ? concat(earlyBuffer, chunk) : chunk;
      // prefixChecked：16 字节 UUID 已经比对通过后就不再重复比对（多帧 Early Data 时省 CPU）
      const state = detectInbound(earlyBuffer, uuidBytes, prefixChecked);
      if (!state) {
        if (earlyBuffer.byteLength >= 17) prefixChecked = true;
        return; // 头还没收全
      }
      if (state === 3) { close(1011); return; }
      chunk = earlyBuffer;
      earlyBuffer = null;
      handshakeDone = true;
      if (timer) { clearTimeout(timer); timer = 0; }
    }
    if (feed(chunk)) pump(); else close(1011);
  };

  const earlyData = extractEarlyData(request);
  if (earlyData) onData(earlyData);

  server.addEventListener('message', async event => {
    onData(event.data);
    const wait = queue.wait;
    if (wait) await wait; // 队列过大时让出，形成反压
  });
  server.addEventListener('close', close);
  server.addEventListener('error', close);

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { 'Sec-WebSocket-Extensions': '' },
  });
}

/* ------------------------------- src/xhttp.js ------------------------------- */
/**
 * 入站：VLESS over XHTTP（只支持 mode=stream-one）。
 *
 * 一次 POST 承载一个完整会话：首包必须自带 VLESS 头（客户端需开 noGRPCHeader）。
 * 先建连再返回响应，失败时给干净的 400 / 502，而不是一条被中断的流。
 */








const byobReader = stream => {
  try { return { reader: stream.getReader({ mode: 'byob' }), byob: true }; }
  catch { return { reader: stream.getReader(), byob: false }; }
};

async function readSome(source, size) {
  if (source.byob) {
    const buffer = new ArrayBuffer(size);
    const { done, value } = await source.reader.read(new Uint8Array(buffer));
    return { done, value: value ? toU8(value) : EMPTY };
  }
  const { done, value } = await source.reader.read();
  return { done, value: value ? toU8(value) : EMPTY };
}

const xhttpError = (status, message) =>
  new Response(`cf-vpngate: ${message}`, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

/**
 * 攒齐 VLESS 首包。
 * XHTTP 只实现 stream-one：一次 POST 承载一个完整会话，首包必须自带 VLESS 头，
 * 即客户端需要开启 noGRPCHeader（这也是首包解析失败时最常见的原因）。
 *
 * 用一块预分配的 hsMax 缓冲累积（旧版每片 concat 一次，多片时是 O(n²) 拷贝）；
 * 命中后把 payload 拷出来，因为缓冲会被后续读取复用。
 */
async function readVlessHeader(source, uuidBytes) {
  const buf = new Uint8Array(CONFIG.hsMax);
  let filled = 0;
  let prefixChecked = false;

  for (;;) {
    if (!prefixChecked && filled >= 17) {
      if (!matchUuid(buf, uuidBytes)) {
        throw new Error('bad vless header；XHTTP 请设置 noGRPCHeader=true（或 Content-Type: application/octet-stream）');
      }
      prefixChecked = true;
    }
    if (filled >= 24) {
      const session = parseVlessHeader(buf.subarray(0, filled), uuidBytes);
      if (session) return { ...session, payload: new Uint8Array(session.payload) };
    }
    if (filled >= CONFIG.hsMax) throw new Error('header too large');
    const size = Math.min(filled === 0 ? CONFIG.xhInit : CONFIG.xhNext, CONFIG.hsMax - filled);
    if (size <= 0) throw new Error('bad header');
    const { done, value } = await readSome(source, size);
    if (done) throw new Error('eof before vless header');
    if (value.byteLength) {
      const take = value.subarray(0, Math.min(value.byteLength, CONFIG.hsMax - filled));
      buf.set(take, filled);
      filled += take.byteLength;
    }
  }
}

/** XHTTP 的 UDP(53)：按 2 字节长度前缀分包，逐批走 TCP DNS 后写进响应流 */
function createDnsResponder(emit, dnsHost, dnsPort) {
  let buffered = EMPTY;
  let chain = Promise.resolve();
  let stopped = false;

  const handle = async data => {
    if (stopped || !data?.byteLength) return;
    const chunk = toU8(data);
    buffered = buffered.byteLength ? concat(buffered, chunk) : chunk;

    const queries = [];
    let offset = 0;
    while (buffered.byteLength - offset >= 2) {
      const end = offset + 2 + ((buffered[offset] << 8) | buffered[offset + 1]);
      if (buffered.byteLength < end) break;
      queries.push(buffered.slice(offset, end));
      offset = end;
    }
    buffered = offset < buffered.byteLength ? buffered.slice(offset) : EMPTY;
    if (!queries.length) return;

    // 同一批并发查询（旧版逐条 await，延迟会叠加），再按原顺序回写
    const answers = await Promise.all(queries.map(query => dnsOverTcp(query, dnsHost, dnsPort)));
    for (let i = 0; i < answers.length; i++) {
      if (!answers[i]) throw new Error('dns query failed');
      emit(answers[i]);
    }
  };

  return {
    write(data) {
      chain = chain.then(() => handle(data)).catch(err => { stopped = true; throw err; });
      return chain;
    },
    async finish() {
      await chain;
      stopped = true;
      if (buffered.byteLength) throw new Error('dns: incomplete packet');
    },
  };
}

/** UDP(53) 的响应：把 DNS 应答直接写进响应体 */
function xhttpUdpResponse(session, source, headers) {
  const stream = new ReadableStream({
    async start(controller) {
      const responder = createDnsResponder(byte => controller.enqueue(byte), session.host, session.port);
      try {
        if (session.payload.byteLength) await responder.write(session.payload);
        for (;;) {
          const { done, value } = await readSome(source, CONFIG.chunk);
          if (done) break;
          if (value.byteLength) await responder.write(value);
        }
        await responder.finish();
      } catch (err) {
        log('xhttp udp error', err?.message || err);
      } finally {
        releaseLock(source.reader);
        try { controller.close(); } catch {}
      }
    },
    cancel() {
      try { source.reader.cancel(); } catch {}
      releaseLock(source.reader);
    },
  });
  return new Response(stream, { status: 200, headers });
}

/** 响应已返回后开始搬运：VLESS 响应头 → 上行 / 下行双向 pipe */
async function bridgeXhttp(session, source, request, remote, transform, output) {
  const upstreamAbort = new AbortController();
  const downstreamAbort = new AbortController();
  let outputReleased = false;
  let finished = false;
  let sides = 2;

  const cleanup = reason => {
    if (finished) return;
    finished = true;
    try { upstreamAbort.abort(reason); } catch {}
    try { downstreamAbort.abort(reason); } catch {}
    releaseLock(source.reader);
    tryClose(remote);
    if (!outputReleased) {
      outputReleased = true;
      try { output.abort(reason).catch(() => {}); } catch {}
      releaseLock(output);
    }
  };

  // 两个方向都结束才收摊（旧版下行一结束就 cleanup，会提前切断上行半关闭方向）
  const sideDone = () => { if (--sides <= 0) cleanup(); };

  try {
    if (session.responsePrefix.byteLength) await output.write(session.responsePrefix);
    outputReleased = true;
    releaseLock(output);

    const downstream = remote.readable
      .pipeTo(transform.writable, { signal: downstreamAbort.signal })
      .then(() => { try { upstreamAbort.abort(); } catch {} sideDone(); }, sideDone);

    if (session.payload.byteLength) {
      const writer = remote.writable.getWriter();
      try { await writer.write(session.payload); } finally { writer.releaseLock(); }
    }

    releaseLock(source.reader);
    request.body
      .pipeTo(remote.writable, { signal: upstreamAbort.signal })
      .then(sideDone, sideDone);
    downstream.catch(() => {});
  } catch (err) {
    cleanup(err);
  }
}

async function handleXhttp(request, uuidBytes, uuid, proxy, globalMode, url, options = {}) {
  if (!request.body) return xhttpError(400, 'empty body');
  if (!paddingAcceptable(extractXhttpPadding(request, uuid, url))) return xhttpError(400, 'bad padding');

  const source = byobReader(request.body);
  const timer = setTimeout(() => { try { source.reader.cancel(); } catch {} }, CONFIG.xhttpHeaderTimeout);

  let session;
  try {
    session = await readVlessHeader(source, uuidBytes);
  } catch (err) {
    clearTimeout(timer);
    releaseLock(source.reader);
    log('xhttp header error', err?.message || err);
    return xhttpError(400, err?.message || 'bad request');
  }
  clearTimeout(timer);

  if (session.udp && session.port !== 53) {
    releaseLock(source.reader);
    return xhttpError(400, 'udp only supports port 53');
  }

  const headers = new Headers(XHTTP_HEADERS);
  applyPaddingHeader(headers);

  if (session.udp) return xhttpUdpResponse(session, source, headers);

  // 先建连再返回响应：失败时给出干净的 502，而不是一条被中断的流
  const remote = await dialOutbound(session.host, session.port, proxy, globalMode, options);
  if (!remote) {
    releaseLock(source.reader);
    log('xhttp dial failed', session.host, session.port);
    return xhttpError(502, `dial failed (${session.host}:${session.port})`);
  }

  const highWaterMark = { highWaterMark: CONFIG.wsBackpressureBytes };
  const transform =
    typeof IdentityTransformStream === 'function'
      ? new IdentityTransformStream(highWaterMark, highWaterMark)
      : new TransformStream({}, highWaterMark, highWaterMark);
  const output = transform.writable.getWriter();

  const response = new Response(transform.readable, { status: 200, headers });
  void bridgeXhttp(session, source, request, remote, transform, output);
  return response;
}

/* ------------------------------- src/share.js ------------------------------- */
/**
 * 节点信息页（GET /sub、/uuid）：输出 ws / xhttp 链接与推荐的 xhttp extra。
 * 带访问控制（CONFIG.subAuth），默认要求携带正确 UUID，避免 Worker 变开放代理。
 */



/** 定长比较，避免通过响应时间侧信道逐字符猜 UUID */
const safeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

/**
 * UUID 可以从三处提供（任一命中即可）：
 *   ?uuid=<uuid>        → https://host/sub?uuid=xxx
 *   /<uuid>/sub         → https://host/<uuid>/sub
 *   X-Uuid: <uuid>      → 请求头
 */
const uuidAuthorized = (request, url, expected) => {
  const segments = url.pathname.split('/').filter(Boolean);
  const candidates = [
    url.searchParams.get('uuid'),
    request.headers.get('x-uuid'),
    segments.length >= 2 ? segments[0] : '',
  ];
  for (const candidate of candidates) {
    if (candidate && safeEqual(candidate.trim(), expected)) return true;
  }
  return false;
};

/**
 * 处理 /sub、/uuid；不是这两个路径则返回 null（交给入口继续分流）。
 */
function handleShareRequest(request, env, url) {
  // 接受两种形态：/sub、/uuid，以及带 UUID 前缀的 /<uuid>/sub、/<uuid>/uuid
  const segments = url.pathname.split('/').filter(Boolean);
  const last = segments[segments.length - 1];
  if (segments.length > 2 || (last !== 'sub' && last !== 'uuid')) return null;

  const text = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (CONFIG.subAuth === 'off') return new Response('cf-vpngate: not found', { status: 404, headers: text });

  const uuid = String(env?.UUID || globalThis.UUID || '').trim() || CONFIG.uuid;
  if (CONFIG.subAuth === 'uuid' && !uuidAuthorized(request, url, uuid)) {
    return new Response('cf-vpngate: not found', { status: 404, headers: text });
  }
  return new Response(buildShareText(request, env, url, uuid), { headers: text });
}

function buildShareText(request, env, url, uuid) {
  const host = request.headers.get('Host') || url.host;
  const backend = (url.searchParams.get('sstp') || url.searchParams.get('proxy') || '').trim() || CONFIG.proxyip;
  const path = encodeURIComponent(`/fdip=${backend}?ed=2560`);
  const common = `encryption=none&security=tls&host=${host}&sni=${host}&fp=chrome&allowInsecure=0`;

  const ws = `vless://${uuid}@${host}:443?path=${path}&${common}&type=ws#cf-vpngate-ws`;
  const xhttp = `vless://${uuid}@${host}:443?mode=stream-one&path=${path}&${common}&alpn=h2&type=xhttp#cf-vpngate-xhttp`;

  // uuid 只回显一次（用于 ?uuid= 的便捷复制），不再额外明文提示
  const hint = CONFIG.subAuth === 'uuid'
    ? `# 本页需携带 UUID 访问：${url.origin}/${uuid}/sub`
    : '# 提示：建议把 CONFIG.subAuth 设为 uuid，避免节点页被公开扫描';

  return [
    '# cf-vpngate',
    '',
    `# 当前落地：${backend}`,
    `# 修改落地：${url.origin}/sub?sstp=sstp://host:443&uuid=${uuid}  或  ${url.origin}/sub?proxy=1.2.3.4:443&uuid=${uuid}`,
    hint,
    '',
    '## vless-ws',
    ws,
    '',
    '## vless-xhttp（mode 固定 stream-one；extra 必须开启 noGRPCHeader）',
    xhttp,
    '',
    `## xhttp extra（xPaddingHeader / xPaddingKey 与 Worker 端 CONFIG 一致：${CONFIG.xhttpPaddingHeader} / ${CONFIG.xhttpPaddingKey}）`,
    XHTTP_EXTRA,
  ].join('\n');
}

/* ------------------------------- src/index.js ------------------------------- */
/**
 * Worker 入口：请求分流（WebSocket / XHTTP / 节点页 / 静默 204）。
 */








/** 落地是否需要强制走（CONFIG.allowClientGlobal=false 时忽略请求方传入值） */
const resolveGlobalMode = (request, url) => {
  const fromClient = request.headers.get('global') || url.searchParams.get('global') || '';
  return CONFIG.allowClientGlobal ? fromClient : CONFIG.globalMode;
};



export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();

      const isWebSocket = upgrade === 'websocket';
      // XHTTP：与 edgetunnel 一致，POST 一律按 XHTTP 处理；
      // 若客户端发了 gRPC 帧（noGRPCHeader=false），首包解析会失败并返回 400
      const isXhttp = !isWebSocket && request.method === 'POST';

      if (!isWebSocket && !isXhttp) {
        // XHTTP 的 packet-up / stream-up 会把下行做成 GET（带 x_session / x_seq），
        // 本实现只支持 stream-one：这里明确回 400，别让客户端只看到静默 204 无从定位
        if (url.searchParams.has('x_session') || url.searchParams.has('x_seq')) {
          log('XHTTP 仅支持 mode=stream-one（packet-up/stream-up 需要跨请求会话表）', url.pathname);
          return new Response(
            'cf-vpngate: XHTTP only supports mode=stream-one；请把客户端 mode 设为 stream-one（packet-up/stream-up 不支持）',
            { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
          );
        }
        // 非代理流量：/sub、/uuid 返回节点信息（受 CONFIG.subAuth 控制），其余静默 204
        const share = handleShareRequest(request, env, url);
        if (share) return share;
        return new Response(null, { status: 204 });
      }

      const uuid = String(env?.UUID || globalThis.UUID || '').trim() || CONFIG.uuid;
      const uuidBytes = getUuidBytes(uuid);
      const globalMode = resolveGlobalMode(request, url);
      // 落地：path 里的优先，否则用 CONFIG.proxyip
      const proxy = parsePathProxy(url) || CONFIG.proxyip;

      // 竞速拨号：由 ?race=1 / X-Race: 1 直接控制，不写就是不竞速
      const options = { race: parseFlag(url, request, 'race') };

      return isWebSocket
        ? await handleWebSocket(request, uuidBytes, proxy, globalMode, options)
        : await handleXhttp(request, uuidBytes, uuid, proxy, globalMode, url, options);
    } catch (err) {
      log('fetch error', err?.message || err);
      return new Response(null, { status: 500 });
    }
  },
};
