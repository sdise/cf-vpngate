/**
 * cf-vpngate
 * -----------------------------------------------------------------------------
 * 入站（前端）：VLESS over WebSocket / VLESS over XHTTP
 * 出站（后端）：SSTP（VPN Gate 公共节点）/ ProxyIP 直连 / !txt 列表 /
 *              socks5 / http(s) 代理
 *
 * 可直接作为 Cloudflare Worker 部署（需 `wrangler.toml`），
 * 也可整段粘贴到 Cloudflare Snippets / Dashboard 快速编辑器中使用。
 *
 * 设计要点：
 *   - 有冲突的实现细节以 jacobax/snippets 的 snippet.js 为准；
 *   - 入站只保留 VLESS（ws + xhttp），去掉 trojan / ss 入站与 ss2022 加解密；
 *   - 出站以 SSTP（VPN Gate）+ ProxyIP 为主，保留 !txt / socks5 / http(s) 以便链式落地；
 *   - UDP 仅支持 53 端口（DNS），由 Worker 转成 TCP 上的 DNS 查询再回写。
 */

import { connect } from 'cloudflare:sockets';

/* ==========================================================================
 * 1. 配置
 * ========================================================================== */

const CONFIG = {
  /** VLESS UUID：可用 Worker 变量 UUID / Snippet 全局 UUID 覆盖 */
  uuid: '495c7195-85b8-498a-bf20-2ea9ce9175b5',
  /** 默认落地（ProxyIP）：host:port / domain!txt / sstp:// / socks5:// / https:// */
  proxyip: 'proxyip.example.com!txt',
  /** auto=1 / auto=2 自适应 proxyip 的域名模板：`${colo}.${autoDomain}` */
  autoDomain: 'proxy.zjcloud.us.ci',
  /** 直连并发拨号数（>1 时取最快的一条，其余关闭） */
  race: 1,
  /** socket → WebSocket 的读块大小 */
  chunk: 65536,
  /** 下行（落地 → 客户端）组包上限 */
  dnPack: 65536,
  /** 下行剩余空间小于该值时立即冲刷，避免小包滞留 */
  dnTail: 2048,
  /** 下行延迟冲刷毫秒数 */
  dnMs: 2,
  /** 上行（客户端 → 落地）入队分片大小 */
  upPack: 65536,
  /** Early Data（sec-websocket-protocol / XHTTP 首片）最大长度 */
  maxED: 8192,
  /** 入站握手头解析的最大等待字节（超过即判定非法） */
  hsMax: 16384,
  /** XHTTP 首读 / 后续读的字节数 */
  xhInit: 32768,
  xhNext: 8192,
  /** SSTP 隧道内 TCP 分片大小（受 TCP 伪首部校验缓冲区 1432 限制，勿超过 1400） */
  mss: 1400,
  /** SSTP / PPP 的 PAP 认证信息（VPN Gate 公共节点固定为 vpn / vpn） */
  sstpUser: 'vpn',
  sstpPass: 'vpn',
  /** UDP(53) 转发的 TCP DNS 服务器（仅当客户端目标解析不出时兜底） */
  dnsServer: '1.1.1.1',
  dnsPort: 53,
  /** XHTTP：等待客户端首包（VLESS 头）的最长毫秒数 */
  xhttpHeaderTimeout: 15000,
  /** XHTTP padding：需与客户端 xhttp extra 的 xPadding* 一致 */
  xhttpPadding: true,
  xhttpPaddingHeader: 'X-Cache',
  xhttpPaddingKey: '_dc',
  xhttpPaddingRange: [100, 1000],
  /** 请求带 padding 时是否校验长度（严格模式；默认宽松，避免误伤客户端） */
  xhttpStrictPadding: false,
  /** 调试日志（Snippet 可在顶部改为 true 后用 `wrangler tail` 观察） */
  debug: false,
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
}`;

/**
 * XHTTP padding 的「头名 / 键名」。
 * 默认用 CONFIG 里的 `X-Cache` / `_dc`（与 extra 的 xPaddingHeader / xPaddingKey 对应），
 * 同时兼容 edgetunnel 由 UUID 派生的名字：uuid.slice(1,7) / '_' + uuid.slice(25,31)。
 */
const paddingIds = uuid => ({
  headers: [CONFIG.xhttpPaddingHeader, uuid.slice(1, 7)].filter(Boolean),
  keys: [CONFIG.xhttpPaddingKey, `_${uuid.slice(25, 31)}`].filter(Boolean),
});

/**
 * 取出请求中的 padding，支持客户端 xPaddingPlacement 的三种放置方式：
 *   queryInHeader / header → 值在 header 里（可能是 `https://x/?_dc=xxx` 形态的 URL）
 *   query                  → 值在请求 URL 的 query 里
 */
function extractXhttpPadding(request, uuid) {
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
  const url = new URL(request.url);
  for (const key of keys) {
    const hit = url.searchParams.get(key);
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
const randomPadding = length => {
  let out = '';
  for (let i = 0; i < length; i++) out += B62[Math.floor(Math.random() * B62.length)];
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

const EMPTY = new Uint8Array(0);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

const log = (...args) => { if (CONFIG.debug) console.log('[cf-vpngate]', ...args); };

/* ==========================================================================
 * 2. 通用工具
 * ========================================================================== */

const encode = str => encoder.encode(str);
const u16 = (buf, offset) => (buf[offset] << 8) | buf[offset + 1];
const u32 = (buf, offset) =>
  ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
const setU16 = (buf, offset, value) => { buf[offset] = (value >> 8) & 255; buf[offset + 1] = value & 255; };

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

/** 标准 Internet 校验和（IPv4 首部 / TCP 伪首部共用） */
const checksum = (data, offset, length) => {
  let sum = 0;
  for (let i = offset; i < offset + length - 1; i += 2) sum += u16(data, i);
  if (length & 1) sum += data[offset + length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
};

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

/* ==========================================================================
 * 3. DNS（DoH 解析 + TXT 列表，带缓存与并发去重）
 * ========================================================================== */

const DNS_CACHE = new Map();
const DNS_INFLIGHT = new Map();

async function dnsQuery(name, type) {
  const key = `${name}_${type}`;
  const now = Date.now();
  const cached = DNS_CACHE.get(key);
  if (cached) {
    if (now - cached.time < 180000) return cached.data;
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
      if (answers.length) {
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

/* ==========================================================================
 * 4. 落地（出站）地址解析
 * ========================================================================== */

/**
 * 解析落地地址：
 *   sstp://host:443            → SSTP（VPN Gate）
 *   socks5://user:pass@h:1080  → SOCKS5
 *   http(s)://user:pass@h:port → HTTP CONNECT
 *   1.2.3.4:443 / [v6]:443     → ProxyIP 直连
 *   纯域名                      → ProxyIP 直连（443）
 */
function parseProxyAddress(raw) {
  if (!raw) return null;
  const input = String(raw).trim();
  const generic = (scheme, plainPort, tlsPort) => {
    try {
      const secure = input.startsWith(`${scheme}s://`);
      const url = new URL(input);
      return {
        type: secure ? `${scheme}s` : scheme,
        host: url.hostname,
        port: parseInt(url.port, 10) || (secure ? tlsPort : plainPort),
        username: url.username ? decodeURIComponent(url.username) : '',
        password: url.password ? decodeURIComponent(url.password) : '',
      };
    } catch { return null; }
  };

  if (input.startsWith('sstp://')) {
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
  if (input.startsWith('socks://') || input.startsWith('socks5://')) {
    try {
      const url = new URL(input.replace(/^socks:\/\//, 'socks5://'));
      return {
        type: 'socks5',
        host: url.hostname,
        port: parseInt(url.port, 10) || 1080,
        username: url.username ? decodeURIComponent(url.username) : '',
        password: url.password ? decodeURIComponent(url.password) : '',
      };
    } catch { return null; }
  }
  if (input.startsWith('http://') || input.startsWith('https://')) return generic('http', 80, 443);

  const bracketed = input.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    const port = parseInt(bracketed[2], 10);
    return { type: 'direct', host: bracketed[1], port: !isNaN(port) && port > 0 ? port : 443 };
  }
  const colon = input.lastIndexOf(':');
  if (colon > 0) {
    const host = input.slice(0, colon);
    const port = parseInt(input.slice(colon + 1), 10);
    if (!isNaN(port) && port > 0 && port <= 65535) return { type: 'direct', host, port };
  }
  return { type: 'direct', host: input, port: 443 };
}

/* ==========================================================================
 * 5. 出站连接器
 * ========================================================================== */

/** 半开直连（保留半关闭能力，便于落地侧 FIN 之后的残余数据回传） */
async function tcpConnect(host, port) {
  const socket = connect({ hostname: String(host).replace(/^\[|\]$/g, ''), port }, { allowHalfOpen: true });
  try { await socket.opened; return socket; } catch (err) { tryClose(socket); throw err; }
}

/** 并发拨号取最快（CONFIG.race > 1 时启用） */
async function raceConnect(host, port) {
  if (CONFIG.race < 2) return tcpConnect(host, port);
  let winner = null;
  const tasks = [];
  for (let i = 0; i < CONFIG.race; i++) {
    tasks.push(
      tcpConnect(host, port).then(socket => {
        if (winner) { tryClose(socket); return Promise.reject(0); }
        winner = socket;
        return socket;
      }),
    );
  }
  try { return await Promise.any(tasks); } catch { throw new Error(`race connect failed: ${host}:${port}`); }
}

/** SOCKS5 客户端（含用户名密码认证） */
async function socksConnect(proxy, targetHost, targetPort) {
  let socket;
  try {
    socket = await tcpConnect(proxy.host, proxy.port);
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    await writer.write(proxy.username && proxy.password ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]));
    const greeting = await reader.read();
    if (greeting.done || greeting.value.byteLength < 2) throw new Error('socks5: bad greeting');
    const method = new Uint8Array(greeting.value)[1];

    if (method === 2) {
      const user = encode(proxy.username);
      const pass = encode(proxy.password);
      const auth = new Uint8Array(3 + user.length + pass.length);
      auth[0] = 1;
      auth[1] = user.length;
      auth.set(user, 2);
      auth[2 + user.length] = pass.length;
      auth.set(pass, 3 + user.length);
      await writer.write(auth);
      const authResp = await reader.read();
      if (authResp.done || new Uint8Array(authResp.value)[1] !== 0) throw new Error('socks5: auth failed');
    } else if (method !== 0) {
      throw new Error('socks5: no acceptable method');
    }

    const hostBytes = encode(targetHost);
    const request = new Uint8Array(7 + hostBytes.length);
    request.set([5, 1, 0, 3, hostBytes.length]);
    request.set(hostBytes, 5);
    new DataView(request.buffer).setUint16(5 + hostBytes.length, targetPort, false);
    await writer.write(request);

    const reply = await reader.read();
    if (reply.done || new Uint8Array(reply.value)[1] !== 0) throw new Error('socks5: connect rejected');

    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (err) {
    tryClose(socket);
    throw err;
  }
}

/** HTTP / HTTPS CONNECT 代理 */
async function httpConnect(proxy, targetHost, targetPort) {
  let socket;
  try {
    socket = connect(
      { hostname: proxy.host, port: proxy.port },
      { secureTransport: proxy.type === 'https' ? 'on' : 'off', allowHalfOpen: true },
    );
    await socket.opened;

    let request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
    if (proxy.username) {
      request += `Proxy-Authorization: Basic ${btoa(`${proxy.username}:${proxy.password || ''}`)}\r\n`;
    }
    request += 'User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n';

    const writer = socket.writable.getWriter();
    await writer.write(encode(request));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    let buffer = EMPTY;
    for (;;) {
      const { done, value } = await reader.read();
      if (done || !value) throw new Error('http proxy: closed');
      buffer = concat(buffer, value);
      if (buffer.length >= 12 && buffer[9] !== 50) throw new Error('http proxy: non-2xx'); // '2' === 50

      let headerEnd = -1;
      for (let i = 0; i <= buffer.length - 4; i++) {
        if (buffer[i] === 13 && buffer[i + 1] === 10 && buffer[i + 2] === 13 && buffer[i + 3] === 10) { headerEnd = i + 4; break; }
      }
      if (headerEnd !== -1) {
        releaseLock(reader);
        const leftover = buffer.subarray(headerEnd);
        if (leftover.length) {
          // 代理在响应尾部夹带了目标数据，用 TransformStream 接回
          const { readable, writable } = new TransformStream();
          const bridge = writable.getWriter();
          bridge.write(leftover);
          bridge.releaseLock();
          socket.readable.pipeTo(writable).catch(() => {});
          return { readable, writable: socket.writable, close: () => tryClose(socket) };
        }
        return socket;
      }
      if (buffer.length > 8192) throw new Error('http proxy: header too large');
    }
  } catch (err) {
    tryClose(socket);
    throw err;
  }
}

/* ------------------------------- SSTP ---------------------------------- */

const PPP_LCP = 0xc021;   // Link Control Protocol
const PPP_PAP = 0xc023;   // Password Authentication Protocol
const PPP_IPCP = 0x8021;  // IP Control Protocol
const PPP_IPV4 = 0x0021;  // IPv4 数据报文

/**
 * SSTP 客户端：完成 SSTP_DUPLEX_POST 建链 + PPP(LCP/PAP/IPCP) 协商，
 * 拿到 PPP 分配的虚拟 IPv4。
 */
function createSstpClient(username, password) {
  let socket = null;
  let reader = null;
  let writer = null;
  let host = '';
  let buffer = EMPTY;
  let pppId = 1;
  let readBuffer = new ArrayBuffer(16384);

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

  /** 读取一个 SSTP 报文；ms 为超时（长连接等待期放宽到 60s） */
  const readPacket = async (ms = 10000) => {
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
    close: () => [reader, writer, socket].forEach(tryClose),
  };
}

/** 在 PPP 之上手搓的最小 IPv4/TCP 栈 */
function createTcpOverPPP(sstp, sourceIp, targetIp, targetPort) {
  const sourcePort = 10000 + (randomU16() % 50000);
  const sourceBytes = new Uint8Array(sourceIp.split('.').map(Number));
  const targetBytes = new Uint8Array(targetIp.split('.').map(Number));
  let seq = randomU32();
  let ack = 0;

  const ipHeader = new Uint8Array(20);
  ipHeader.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); // v4/IHL5, DF, TTL64, TCP
  ipHeader.set(sourceBytes, 12);
  ipHeader.set(targetBytes, 16);

  // TCP 伪首部（12 + 报文长度，缓冲区 1432 ⇒ MSS 上限 1400）
  const pseudo = new Uint8Array(1432);
  pseudo.set(sourceBytes);
  pseudo.set(targetBytes, 4);
  pseudo[9] = 6;

  const frame = (flags, data = EMPTY) => {
    const payloadLength = data.length;
    const tcpLength = 20 + payloadLength;
    const ipLength = 20 + tcpLength;
    const size = 8 + ipLength;
    const packet = new Uint8Array(size);
    const view = new DataView(packet.buffer);

    packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03, 0x00, 0x21]);
    packet.set(ipHeader, 8);
    view.setUint16(10, ipLength);
    view.setUint16(12, randomU16());
    view.setUint16(18, checksum(packet, 8, 20));
    view.setUint16(28, sourcePort);
    view.setUint16(30, targetPort);
    view.setUint32(32, seq);
    view.setUint32(36, ack);
    packet[40] = 0x50; // data offset = 5 * 4
    packet[41] = flags;
    view.setUint16(42, 65535); // window
    if (payloadLength) packet.set(data, 48);

    pseudo[10] = tcpLength >> 8;
    pseudo[11] = tcpLength & 0xff;
    pseudo.set(packet.subarray(28, 28 + tcpLength), 12);
    view.setUint16(44, checksum(pseudo, 0, 12 + tcpLength));
    return packet;
  };

  const match = ip => {
    if (ip.length < 40 || ip[9] !== 6) return null;
    const ihl = (ip[0] & 0x0f) * 4;
    if (u16(ip, ihl) !== targetPort || u16(ip, ihl + 2) !== sourcePort) return null;
    return { flags: ip[ihl + 13], seq: u32(ip, ihl + 4), offset: ihl + ((ip[ihl + 12] >> 4) & 0x0f) * 4 };
  };

  const handshake = async () => {
    await sstp.writer.write(frame(0x02)); // SYN
    seq = (seq + 1) >>> 0;
    for (let i = 0; i < 30; i++) {
      const packet = await sstp.readPacket();
      if (packet.ctrl) continue;
      const ppp = sstp.parsePPP(packet.body);
      if (!ppp || ppp.protocol !== PPP_IPV4) continue;
      const info = match(ppp.ip);
      if (!info || (info.flags & 0x12) !== 0x12) continue; // 需要 SYN+ACK
      ack = (info.seq + 1) >>> 0;
      sstp.writer.write(frame(0x10)); // ACK
      return true;
    }
    throw new Error('sstp: tcp handshake timeout');
  };

  return {
    frame,
    match,
    handshake,
    get seq() { return seq; },
    set seq(value) { seq = value; },
    get ack() { return ack; },
    set ack(value) { ack = value; },
  };
}

/**
 * SSTP 出站：连上 SSTP 服务器 → PPP 拿虚拟 IP → 手搓 TCP 连目标
 * 返回 { readable, writable, close }，失败返回 null。
 */
async function sstpConnect(server, targetHost, targetPort) {
  const client = createSstpClient(server.username, server.password);
  const close = () => client.close();
  try {
    const targetIp = await resolveIPv4(targetHost);
    await client.connect(server.host, server.port);
    const myIp = await client.establish();
    const tcp = createTcpOverPPP(client, myIp, targetIp, targetPort);
    await tcp.handshake();

    let controller = null;
    const readable = new ReadableStream({ start: stream => { controller = stream; }, cancel: close });

    (async () => {
      try {
        let pending = [];
        let pendingBytes = 0;
        const flush = () => {
          if (!pendingBytes) return;
          controller.enqueue(pending.length === 1 ? pending[0] : concat(...pending));
          pending = [];
          pendingBytes = 0;
          client.writer.write(tcp.frame(0x10)).catch(() => {}); // 纯 ACK
        };
        for (;;) {
          const packet = await client.readPacket(60000);
          if (packet.ctrl) continue;
          const ppp = client.parsePPP(packet.body);
          if (!ppp || ppp.protocol !== PPP_IPV4) continue;
          const info = tcp.match(ppp.ip);
          if (!info) continue;

          if (info.offset < ppp.ip.length) {
            const data = ppp.ip.subarray(info.offset);
            if (data.length) {
              tcp.ack = (info.seq + data.length) >>> 0;
              pending.push(new Uint8Array(data));
              pendingBytes += data.length;
            }
          }
          if (info.flags & 0x01) { // FIN：冲刷后回 FIN+ACK 并结束
            flush();
            tcp.ack = (tcp.ack + 1) >>> 0;
            client.writer.write(tcp.frame(0x11)).catch(() => {});
            controller.close();
            return;
          }
          // 隧道内没有更多待读数据，或已攒够一个下行包，就交给上层
          if (client.buffer.length < 4 || pendingBytes >= 32768) flush();
        }
      } catch {
        try { controller.close(); } catch {}
      }
    })();

    const writable = new WritableStream({
      async write(chunk) {
        const data = toU8(chunk);
        if (data.length <= CONFIG.mss) {
          await client.writer.write(tcp.frame(0x18, data)); // PSH+ACK
          tcp.seq = (tcp.seq + data.length) >>> 0;
          return;
        }
        const frames = [];
        for (let offset = 0; offset < data.length; offset += CONFIG.mss) {
          const segment = data.subarray(offset, Math.min(offset + CONFIG.mss, data.length));
          frames.push(tcp.frame(0x18, segment));
          tcp.seq = (tcp.seq + segment.length) >>> 0;
        }
        await client.writer.write(concat(...frames));
      },
      close: () => client.writer.write(tcp.frame(0x11)).catch(() => {}), // FIN+ACK
      abort: close,
    });

    return { readable, writable, close };
  } catch (err) {
    log('sstp failed', server.host, server.port, err?.message || err);
    close();
    return null;
  }
}

/* ==========================================================================
 * 6. 统一出站调度
 * ========================================================================== */

let txtDomain = null;
let txtEntries = null;

/**
 * @param {string} targetHost   客户端请求的目标
 * @param {number} targetPort
 * @param {string|Function} proxy  落地配置（字符串或惰性函数）
 * @param {string} globalMode  '1' 表示强制走落地，否则先尝试直连再回落
 */
async function dialOutbound(targetHost, targetPort, proxy, globalMode) {
  if (globalMode !== '1') {
    try { return await raceConnect(targetHost, targetPort); } catch { /* 回落到 proxyip */ }
  }

  const raw = String((typeof proxy === 'function' ? proxy() : proxy) || CONFIG.proxyip).trim();

  const pickEntry = async () => {
    if (raw.toLowerCase().endsWith('!txt')) {
      const domain = raw.slice(0, -4).trim();
      try {
        if (txtDomain !== domain || !txtEntries) {
          const list = await resolveTXT(domain);
          if (list.length) { txtEntries = list; txtDomain = domain; }
        }
        if (txtEntries?.length) {
          const picked = parseProxyAddress(txtEntries[Math.floor(Math.random() * txtEntries.length)]);
          if (picked) return picked;
        }
      } catch { /* 解析失败则把域名当直连 */ }
      return { type: 'direct', host: domain, port: 443 };
    }
    return parseProxyAddress(raw) || { type: 'direct', host: raw, port: 443 };
  };

  const entry = await pickEntry();
  log('dial', targetHost, targetPort, 'via', entry.type, entry.host, entry.port);

  try {
    if (entry.type === 'socks5') return await socksConnect(entry, targetHost, targetPort);
    if (entry.type === 'http' || entry.type === 'https') return await httpConnect(entry, targetHost, targetPort);
    if (entry.type === 'sstp') return await sstpConnect(entry, targetHost, targetPort);
    // ProxyIP：直连该 IP/域名，由它按 SNI 反代到真正的目标
    return await raceConnect(entry.host, entry.port);
  } catch (err) {
    log('dial error', err?.message || err);
    return null;
  }
}

/* ==========================================================================
 * 7. VLESS 入站解析
 * ========================================================================== */

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

/** 握手阶段判定：0=数据不足 1=VLESS 3=非法 */
function detectInbound(buffer, uuidBytes) {
  const limit = Math.min(buffer.byteLength, 17);
  for (let i = 1; i < limit; i++) if (buffer[i] !== uuidBytes[i - 1]) return 3;
  if (parseVlessHeader(buffer, uuidBytes)) return 1;
  return buffer.byteLength < CONFIG.hsMax ? 0 : 3;
}

/* ==========================================================================
 * 8. UDP(53) → TCP DNS
 * ========================================================================== */

async function dnsOverTcp(query, host = CONFIG.dnsServer, port = CONFIG.dnsPort) {
  const request = toU8(query);
  for (let attempt = 0; attempt < 2; attempt++) {
    let socket;
    try {
      socket = await raceConnect(host, port);
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
      return hasLengthPrefix ? concat(header, body) : body;
    } catch {
      if (attempt === 1) return null;
    } finally {
      tryClose(socket);
    }
  }
  return null;
}

/* ==========================================================================
 * 9. 数据队列与下行发送
 * ========================================================================== */

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
    compact();
    return item;
  };

  return {
    empty: isEmpty,
    get size() { return bytes; },
    get wait() { return waiter; },
    clear() {
      items = []; head = 0; bytes = 0;
      wake?.(); wake = waiter = null;
    },
    push(chunk) {
      const length = chunk?.byteLength || 0;
      if (!length || bytes + length > 8388608) return false; // 8MB 上限，防内存爆
      items.push(chunk);
      bytes += length;
      if (bytes >= 1048576) waiter ||= new Promise(resolve => { wake = resolve; }); // 反压信号
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
        out.set(chunk, offset);
        offset += chunk.byteLength;
      }
      compact();
      return out.slice(0, total);
    },
    drain() { if (bytes <= 262144) { wake?.(); wake = waiter = null; } },
  };
}

/** 下行发送器：攒包 + 背压感知，减少 WebSocket 小包 */
function createDownstreamSender(ws) {
  const maxPack = CONFIG.dnPack;
  const tail = CONFIG.dnTail;
  const queue = createQueue(maxPack);
  let timer = 0;

  const emit = chunk => { if (ws.readyState === WebSocket.OPEN) ws.send(chunk); };
  const flush = () => {
    if (timer) { clearTimeout(timer); timer = 0; }
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
      while (offset < length) {
        const room = maxPack - queue.size;
        const size = Math.min(room, length - offset);
        if (!size) { flush(); continue; }
        const slice = offset || size !== length ? data.subarray(offset, offset + size) : data;
        if (!queue.push(slice)) { flush(); if (!queue.push(slice)) break; }
        offset += size;
        if (queue.size >= maxPack || maxPack - queue.size < tail || !ws.bufferedAmount) flush();
        else timer ||= setTimeout(flush, queue.size >= maxPack >> 1 ? CONFIG.dnMs : 0);
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
    while (ws.readyState === WebSocket.OPEN && ws.bufferedAmount > 262144) {
      const delay = ws.bufferedAmount > 524288 ? 8 : 2;
      await (globalThis.scheduler?.wait?.(delay) ?? new Promise(resolve => setTimeout(resolve, delay)));
      if (ws.bufferedAmount <= 65536) break;
    }
  };
  const finish = () => {
    releaseLock(reader);
    try { ws.close(1000, ''); } catch {}
  };

  let buffer = new ArrayBuffer(CONFIG.chunk);
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
        buffer = new ArrayBuffer(CONFIG.chunk);
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

/* ==========================================================================
 * 10. Early Data / 路径解析
 * ========================================================================== */

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
 * 解析 path：`/fdip=<落地>?ed=2560`
 * @returns {{ proxy: string|null, embeddedQuery: string }}
 */
function parsePath(url) {
  let raw = url.pathname + (url.search || '');
  if (raw.startsWith('/')) raw = raw.slice(1);
  try { raw = decodeURIComponent(raw); } catch { /* 保持原样 */ }

  const queryAt = raw.indexOf('?');
  const main = queryAt < 0 ? raw : raw.slice(0, queryAt);
  const embeddedQuery = queryAt < 0 ? '' : raw.slice(queryAt + 1);

  const equalAt = main.indexOf('=');
  if (equalAt <= 0) return { proxy: null, embeddedQuery };

  const value = main.slice(equalAt + 1).trim();
  if (!value) return { proxy: null, embeddedQuery };

  const schemeMatch = value.match(/^((?:socks5?|https?|sstp):\/\/[^/?#]+(?:\/[^?#]*)?)/i);
  return {
    proxy: schemeMatch
      ? schemeMatch[1]
      : value.indexOf('/') >= 0
        ? value.slice(0, value.indexOf('/')).trim()
        : value,
    embeddedQuery,
  };
}

/* ==========================================================================
 * 11. 入站：WebSocket
 * ========================================================================== */

async function handleWebSocket(request, uuidBytes, resolveProxy, globalMode) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.binaryType = 'arraybuffer';
  server.accept({ allowHalfOpen: true });

  const remote = { socket: null, writer: null };
  const queue = createQueue(CONFIG.upPack);

  let closed = false;
  let running = false;
  let handshakeDone = false;
  let dnsMode = false;
  let dnsTarget = null;
  let earlyBuffer = null;
  let timer = setTimeout(() => { if (!handshakeDone) close(1000); }, 15000);

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

          const socket = await dialOutbound(session.host, session.port, resolveProxy, globalMode);
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
      const state = detectInbound(earlyBuffer, uuidBytes);
      if (!state) return; // 头还没收全
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

/* ==========================================================================
 * 12. 入站：XHTTP
 * ========================================================================== */

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
 */
async function readVlessHeader(source, uuidBytes) {
  let buffer = EMPTY;
  for (;;) {
    if (buffer.byteLength >= 17 && !matchUuid(buffer, uuidBytes)) {
      throw new Error('bad vless header；XHTTP 请设置 noGRPCHeader=true（或 Content-Type: application/octet-stream）');
    }
    const session = parseVlessHeader(buffer, uuidBytes);
    if (session) return session;
    if (buffer.byteLength >= CONFIG.hsMax) throw new Error('header too large');
    const want = CONFIG.hsMax - buffer.byteLength;
    const size = Math.min(buffer.byteLength === 0 ? CONFIG.xhInit : CONFIG.xhNext, want);
    if (size <= 0) throw new Error('bad header');
    const { done, value } = await readSome(source, size);
    if (done) throw new Error('eof before vless header');
    if (value.byteLength) buffer = buffer.byteLength ? concat(buffer, value) : value;
  }
}

/** XHTTP 的 UDP(53)：按 2 字节长度前缀分包，逐条走 TCP DNS 后写进响应流 */
function createDnsResponder(emit, dnsHost, dnsPort) {
  let buffered = EMPTY;
  let chain = Promise.resolve();
  let stopped = false;

  const handle = async data => {
    if (stopped || !data?.byteLength) return;
    const chunk = toU8(data);
    buffered = buffered.byteLength ? concat(buffered, chunk) : chunk;
    let offset = 0;
    while (buffered.byteLength - offset >= 2) {
      const end = offset + 2 + ((buffered[offset] << 8) | buffered[offset + 1]);
      if (buffered.byteLength < end) break;
      const answer = await dnsOverTcp(buffered.slice(offset, end), dnsHost, dnsPort);
      if (!answer) throw new Error('dns query failed');
      emit(answer);
      offset = end;
    }
    buffered = offset < buffered.byteLength ? buffered.slice(offset) : EMPTY;
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

  try {
    if (session.responsePrefix.byteLength) await output.write(session.responsePrefix);
    outputReleased = true;
    releaseLock(output);

    const downstream = remote.readable.pipeTo(transform.writable, { signal: downstreamAbort.signal });
    if (session.payload.byteLength) {
      const writer = remote.writable.getWriter();
      try { await writer.write(session.payload); } finally { writer.releaseLock(); }
    }

    releaseLock(source.reader);
    request.body.pipeTo(remote.writable, { signal: upstreamAbort.signal }).catch(cleanup);
    downstream.then(() => cleanup(), cleanup);
  } catch (err) {
    cleanup(err);
  }
}

async function handleXhttp(request, uuidBytes, uuid, resolveProxy, globalMode) {
  if (!request.body) return xhttpError(400, 'empty body');
  if (!paddingAcceptable(extractXhttpPadding(request, uuid))) return xhttpError(400, 'bad padding');

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
  const remote = await dialOutbound(session.host, session.port, resolveProxy, globalMode);
  if (!remote) {
    releaseLock(source.reader);
    log('xhttp dial failed', session.host, session.port);
    return xhttpError(502, `dial failed (${session.host}:${session.port})`);
  }

  const highWaterMark = { highWaterMark: 262144 };
  const transform =
    typeof IdentityTransformStream === 'function'
      ? new IdentityTransformStream(highWaterMark, highWaterMark)
      : new TransformStream({}, highWaterMark, highWaterMark);
  const output = transform.writable.getWriter();

  const response = new Response(transform.readable, { status: 200, headers });
  void bridgeXhttp(session, source, request, remote, transform, output);
  return response;
}

/* ==========================================================================
 * 13. 节点信息页（GET /sub、/uuid）
 * ========================================================================== */

function buildShareText(request, env, url) {
  const uuid = String(env?.UUID || globalThis.UUID || '').trim() || CONFIG.uuid;
  const host = request.headers.get('Host') || url.host;
  const backend = (url.searchParams.get('sstp') || url.searchParams.get('proxy') || '').trim() || CONFIG.proxyip;
  const path = encodeURIComponent(`/fdip=${backend}?ed=2560`);
  const common = `encryption=none&security=tls&host=${host}&sni=${host}&fp=chrome&allowInsecure=0`;

  const ws = `vless://${uuid}@${host}:443?path=${path}&${common}&type=ws#cf-vpngate-ws`;
  const xhttp = `vless://${uuid}@${host}:443?mode=stream-one&path=${path}&${common}&alpn=h2&type=xhttp#cf-vpngate-xhttp`;

  return [
    '# cf-vpngate',
    '',
    `# 当前落地：${backend}`,
    `# 修改落地：${url.origin}/sub?sstp=sstp://host:443  或  ${url.origin}/sub?proxy=1.2.3.4:443`,
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

/* ==========================================================================
 * 14. 入口
 * ========================================================================== */

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
        // 非代理流量：/sub、/uuid 返回节点信息，其余静默 204
        const path = url.pathname.replace(/\/+$/, '');
        if (path === '/sub' || path === '/uuid') {
          return new Response(buildShareText(request, env, url), {
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          });
        }
        return new Response(null, { status: 204 });
      }

      const uuid = String(env?.UUID || globalThis.UUID || '').trim() || CONFIG.uuid;
      const uuidBytes = getUuidBytes(uuid);
      const globalMode = request.headers.get('global') || url.searchParams.get('global') || '';

      const resolveProxy = () => {
        const { proxy, embeddedQuery } = parsePath(url);
        const embedded = new URLSearchParams(embeddedQuery);
        const auto = url.searchParams.get('auto') || embedded.get('auto');
        const colo = (request.cf?.colo || '').toLowerCase();
        const zj = `${colo}.${CONFIG.autoDomain}`;
        const hasDefault = Boolean(CONFIG.proxyip) && !/example/i.test(CONFIG.proxyip);
        const fallback = hasDefault ? CONFIG.proxyip : zj;

        if (auto === '1') return colo === 'hkg' ? proxy || fallback : zj;
        if (auto === '2') return zj;
        return proxy || fallback;
      };

      return isWebSocket
        ? await handleWebSocket(request, uuidBytes, resolveProxy, globalMode)
        : await handleXhttp(request, uuidBytes, uuid, resolveProxy, globalMode);
    } catch (err) {
      log('fetch error', err?.message || err);
      return new Response(null, { status: 500 });
    }
  },
};
