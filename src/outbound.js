/**
 * 出站调度：只有 SSTP 与 ProxyIP 两种落地。
 */

import { CONFIG, log } from './config.js';
import { tryClose } from './utils.js';
import { resolveTXT } from './dns.js';
import { tcpConnect } from './net.js';
import { sstpConnect } from './sstp/pool.js';

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
export function parseProxyAddress(raw) {
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
export async function raceDial(dialers) {
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
export function portAllowed(port) {
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
