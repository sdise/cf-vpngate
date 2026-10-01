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

import { CONFIG, log } from '../config.js';
import { randomU16, withTimeout } from '../utils.js';
import { resolveIPv4 } from '../dns.js';
import { PPP_IPV4, createSstpClient } from './client.js';
import { createTcpStream, parseIpTcp } from './tcp.js';

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
export async function sstpConnect(server, targetHost, targetPort, timeoutMs = 0) {
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
