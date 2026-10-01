/**
 * VLESS 入站解析：地址编解码、请求头解析、握手探测、Early Data、path 落地解析。
 */

import { CONFIG } from './config.js';
import { decoder, u16 } from './utils.js';

export const formatAddress = (type, bytes) =>
  type === 1
    ? `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`
    : type === 3
      ? decoder.decode(bytes)
      : `[${Array.from({ length: 8 }, (_, i) => u16(bytes, i * 2).toString(16)).join(':')}]`;

export const parseAddress = (buffer, offset, type) => {
  const length = type === 3 ? buffer[offset++] : type === 1 ? 4 : type === 4 ? 16 : 0;
  if (!length || offset + length > buffer.length) return null;
  return { bytes: buffer.subarray(offset, offset + length), offset: offset + length };
};

/** UUID 比对：VLESS 头的第 1~16 字节 */
export const matchUuid = (buffer, uuidBytes) => {
  for (let i = 0; i < 16; i++) if (buffer[i + 1] !== uuidBytes[i]) return false;
  return true;
};

/** VLESS 请求头 → { host, port, payload, responsePrefix, udp } */
export function parseVlessHeader(buffer, uuidBytes) {
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
export function detectInbound(buffer, uuidBytes, prefixChecked = false) {
  if (!prefixChecked) {
    const limit = Math.min(buffer.byteLength, 17);
    for (let i = 1; i < limit; i++) if (buffer[i] !== uuidBytes[i - 1]) return 3;
  }
  if (parseVlessHeader(buffer, uuidBytes)) return 1;
  return buffer.byteLength < CONFIG.hsMax ? 0 : 3;
}

/** 从 sec-websocket-protocol（早期数据）与 Referer 中取出 base64url 数据 */
export function extractEarlyData(request) {
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
export function parsePathProxy(url) {
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
export function parseFlag(url, request, key) {
  const raw = url.searchParams.get(key) ?? request?.headers?.get(`x-${key}`) ?? '';
  const text = String(raw).trim().toLowerCase();
  return text === '1' || text === 'true' || text === 'on' || text === 'yes';
}


