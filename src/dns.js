/**
 * DNS：DoH 解析（缓存 + 并发去重 + 负缓存）+ UDP(53) 转 TCP 的 DNS 查询（带应答缓存）。
 *
 * 缓存全部是 isolate 级内存缓存（不依赖 KV / Cache API），因此在 Snippets 下同样可用。
 */

import { CONFIG } from './config.js';
import { EMPTY, IPV4_RE, concat, toU8, tryClose, u16 } from './utils.js';
import { tcpConnect } from './net.js';

const DNS_CACHE = new Map();
const DNS_INFLIGHT = new Map();

export async function dnsQuery(name, type) {
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
export const resolveIPv4 = async host => {
  if (IPV4_RE.test(host)) return host;
  const list = (await dnsQuery(host, 'A')).filter(a => a.type === 1).map(a => a.data);
  if (!list.length) throw new Error(`resolve failed: ${host}`);
  return list[0];
};

/** 解析 TXT 记录，值按逗号 / 换行切分成候选列表 */
export const resolveTXT = async host => {
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
export async function dnsOverTcp(query, host = CONFIG.dnsServer, port = CONFIG.dnsPort) {
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
