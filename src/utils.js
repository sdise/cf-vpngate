/**
 * 通用工具：字节读写、拼接、校验和、UUID、资源释放。
 * 全部为纯函数 / 无状态，供热路径高频调用。
 */

export const EMPTY = new Uint8Array(0);
export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
export const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

export const encode = str => encoder.encode(str);
export const u16 = (buf, offset) => (buf[offset] << 8) | buf[offset + 1];
export const u32 = (buf, offset) =>
  ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;

export const setU16 = (buf, offset, value) => { buf[offset] = (value >> 8) & 255; buf[offset + 1] = value & 255; };
export const setU32 = (buf, offset, value) => {
  buf[offset] = (value >>> 24) & 255;
  buf[offset + 1] = (value >>> 16) & 255;
  buf[offset + 2] = (value >>> 8) & 255;
  buf[offset + 3] = value & 255;
};

export const randomBytes = n => crypto.getRandomValues(new Uint8Array(n));
export const randomU16 = () => u16(randomBytes(2), 0);
export const randomU32 = () => u32(randomBytes(4), 0);

export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};

/** 任意 ArrayBuffer / ArrayBufferView → Uint8Array（零拷贝视图） */
export const toU8 = value =>
  value instanceof Uint8Array
    ? value
    : ArrayBuffer.isView(value)
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : new Uint8Array(value);

/** 关闭 socket / reader / writer：有 cancel 用 cancel，否则用 close */
export const tryClose = target => {
  try { const result = target?.cancel?.(); if (result === undefined) target?.close?.(); } catch {}
};
export const releaseLock = target => { try { target?.releaseLock?.(); } catch {} };

/**
 * 标准 Internet 校验和（IPv4 首部 / TCP 伪首部共用）。
 * 按 32 位宽累加再折叠——比逐 16 位累加少一半循环次数，结果等价（模 2^16-1 一致）。
 */
export const checksum = (data, offset, length) => {
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
export const seqLT = (a, b) => ((a - b) | 0) < 0;
export const seqLE = (a, b) => a === b || ((a - b) | 0) < 0;

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
export const getUuidBytes = uuid => {
  let bytes = uuidCache.get(uuid);
  if (!bytes) { bytes = uuidToBytes(uuid); uuidCache.set(uuid, bytes); }
  return bytes;
};

/** 带超时的 promise：超时后 reject，不取消原任务（调用方自行收尾） */
export const withTimeout = (promise, ms, message) => {
  if (!ms || ms <= 0) return promise;
  let timer;
  const guard = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || 'timeout')), ms); });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
};
