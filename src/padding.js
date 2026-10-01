/**
 * XHTTP padding（对齐 edgetunnel）。
 * 请求侧提取 + 可选严格校验，响应侧回填随机 padding。
 */

import { CONFIG } from './config.js';
import { randomBytes } from './utils.js';

/** paddingIds 随 uuid 缓存：避免每请求都做 slice / filter / 数组分配 */
const idCache = new Map();

/**
 * XHTTP padding 的「头名 / 键名」。
 * 默认用 CONFIG 里的 `a290fd` / `_d8d344`（与 extra 的 xPaddingHeader / xPaddingKey 对应），
 * 同时兼容 edgetunnel 由 UUID 派生的名字：uuid.slice(1,7) / '_' + uuid.slice(25,31)。
 */
export function paddingIds(uuid) {
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
export function extractXhttpPadding(request, uuid, url) {
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
export function paddingAcceptable(padding) {
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
export function applyPaddingHeader(headers) {
  if (!CONFIG.xhttpPadding) return;
  try {
    const [min, max] = CONFIG.xhttpPaddingRange;
    const url = new URL('https://x.invalid/');
    url.searchParams.set(CONFIG.xhttpPaddingKey, randomPadding(min + Math.floor(Math.random() * (max - min + 1))));
    headers.set(CONFIG.xhttpPaddingHeader, url.toString());
  } catch { /* 头名非法则忽略 */ }
}
