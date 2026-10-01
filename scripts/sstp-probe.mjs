/**
 * SSTP 实测探针：连一个真实的 SSTP（VPN Gate / SoftEther）节点，量出各阶段耗时，
 * 用来**实测**决定超时参数，而不是拍脑袋写 3s。
 *
 *   node scripts/sstp-probe.mjs sstp://vpn1234.opengw.net:443
 *   node scripts/sstp-probe.mjs --host vpn1234.opengw.net --port 443 --n 3 --streams 3
 *   node scripts/sstp-probe.mjs sstp://vpn1234.opengw.net:443 --target www.example.com --target-port 443
 *   node scripts/sstp-probe.mjs sstp://public-vpn-68.opengw.net:443 --exit-ip
 *
 * --exit-ip 是另一种口径：**不走 workerd**，直接用 Node 原生 socket 建 SSTP 隧道，
 * 在隧道内访问 https://api.ip.sb/ip，并与本机直连出口做对照。
 * 本机处于受限网络（到节点必须经 TUN / 127.0.0.1:1080 代理）时，workerd 的 connect()
 * 不走 TUN 因而连不上节点，此时这是唯一能在本地跑通的「出口 IP」验证。
 * 硬性判据只有「隧道出口 ≠ 直连出口」；与 vpngate.csv 里节点 IP 的关系只作参考打印
 * （节点接入地址与出网地址本就不必相同，域名解析也可能已变更）。
 *
 * 测什么：
 *   dns   域名解析
 *   tcp   TCP 建连
 *   tls   TLS 握手（SSTP 必须跑在 TLS 上）
 *   sstp  SSTP_DUPLEX_POST + PPP(LCP/PAP/IPCP)，拿到虚拟 IPv4
 *   inner 隧道内 TCP 三次握手（SYN → SYN+ACK）＝ 目标真的可达
 *   reuse 复用同一条隧道再开一条流的 inner 耗时 ← 隧道复用省掉的就是前面那几项
 *
 * 复用 src/utils.js 的字节/校验和工具，其余（SSTP/PPP 建链）在本文件内独立实现，
 * 因为 src 里的 client 依赖 cloudflare:sockets，Node 下跑不了。
 */

import tls from 'node:tls';
import dns from 'node:dns/promises';
import nodeCrypto from 'node:crypto';
import { once } from 'node:events';
import { Duplex, Readable, Writable } from 'node:stream';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { defaultCsvPath, loadVpngateCsv, lookupNode, relationToNode } from './vpngate-csv.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { u16, u32, setU16, setU32, checksum, concat } =
  await import(pathToFileURL(join(ROOT, 'src', 'utils.js')).href);
// 隧道内的完整 TCP 栈（Worker 与探针共用同一份实现），--exit-ip 模式直接复用它
const { createTcpStream, parseIpTcp: parseIpTcpStack } =
  await import(pathToFileURL(join(ROOT, 'src', 'sstp', 'tcp.js')).href);

/* ----------------------------- 参数 ----------------------------- */

const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const has = name => argv.includes(`--${name}`);

const positional = argv.find(a => !a.startsWith('--'));
let host = arg('host', '');
let port = Number(arg('port', 443));
let user = arg('user', 'vpn');
let pass = arg('pass', 'vpn');

if (positional) {
  // sstp://[user:pass@]host:port
  const text = positional.replace(/^sstp:\/\//i, '');
  const at = text.lastIndexOf('@');
  if (at >= 0) {
    const cred = text.slice(0, at).split(':');
    user = decodeURIComponent(cred[0] || 'vpn');
    pass = decodeURIComponent(cred[1] || 'vpn');
  }
  const rest = at >= 0 ? text.slice(at + 1) : text;
  const colon = rest.lastIndexOf(':');
  if (colon > 0 && /^\d+$/.test(rest.slice(colon + 1))) {
    host = rest.slice(0, colon);
    port = Number(rest.slice(colon + 1));
  } else {
    host = rest;
  }
}

const ROUNDS = Math.max(1, Number(arg('n', 3)));
const STREAMS = Math.max(1, Number(arg('streams', 3)));
const TARGET = arg('target', 'www.example.com');
const TARGET_PORT = Number(arg('target-port', 443));
const STEP_TIMEOUT = Number(arg('timeout', 30000));

/** --exit-ip：走真实 SSTP 隧道访问 api.ip.sb，把出口 IP 与 vpngate.csv 里的 IP 对比 */
const EXIT_IP = has('exit-ip');
const API_HOST = arg('api', 'api.ip.sb');
const CSV_PATH = arg('csv', process.env.VPNGATE_CSV || '');

if (!host) {
  console.error('用法：node scripts/sstp-probe.mjs sstp://user:pass@host:443 [--n 3] [--streams 3] [--target www.example.com]');
  console.error('      node scripts/sstp-probe.mjs sstp://public-vpn-68.opengw.net:443 --exit-ip');
  process.exit(1);
}

/* ----------------------------- SSTP / PPP ----------------------------- */

const PPP_LCP = 0xc021;
const PPP_PAP = 0xc023;
const PPP_IPCP = 0x8021;
const PPP_IPV4 = 0x0021;

const enc = new TextEncoder();

const sstpData = frame => {
  const size = 6 + frame.length;
  const packet = new Uint8Array(size);
  packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03]);
  packet.set(frame, 6);
  return packet;
};

const sstpControl = (messageType, attributes = []) => {
  const total = attributes.reduce((sum, a) => sum + 4 + a.data.length, 0);
  const packet = new Uint8Array(8 + total);
  packet[0] = 0x10;
  packet[1] = 0x01;
  setU16(packet, 2, (8 + total) | 0x8000);
  setU16(packet, 4, messageType);
  setU16(packet, 6, attributes.length);
  attributes.reduce((offset, a) => {
    packet[offset + 1] = a.id;
    setU16(packet, offset + 2, 4 + a.data.length);
    packet.set(a.data, offset + 4);
    return offset + 4 + a.data.length;
  }, 8);
  return packet;
};

const pppFrame = (protocol, code, id, options = []) => {
  const total = options.reduce((sum, o) => sum + 2 + o.data.length, 0);
  const frame = new Uint8Array(6 + total);
  setU16(frame, 0, protocol);
  frame[2] = code;
  frame[3] = id;
  setU16(frame, 4, 4 + total);
  options.reduce((offset, o) => {
    frame[offset] = o.type;
    frame[offset + 1] = 2 + o.data.length;
    frame.set(o.data, offset + 2);
    return offset + 2 + o.data.length;
  }, 6);
  return frame;
};

const papFrame = (id, account, credit) => {
  const u = enc.encode(account);
  const p = enc.encode(credit);
  const tail = 6 + u.length + p.length;
  const frame = new Uint8Array(2 + tail);
  setU16(frame, 0, PPP_PAP);
  frame[2] = 1;
  frame[3] = id;
  setU16(frame, 4, tail);
  frame[6] = u.length;
  frame.set(u, 7);
  frame[7 + u.length] = p.length;
  frame.set(p, 8 + u.length);
  return frame;
};

const parsePPP = data => {
  const offset = data.length >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
  if (data.length - offset < 4) return null;
  const protocol = u16(data, offset);
  if (protocol === PPP_IPV4) return { protocol, ip: data.subarray(offset + 2) };
  return data.length - offset >= 6
    ? {
      protocol,
      code: data[offset + 2],
      id: data[offset + 3],
      payload: data.subarray(offset + 6),
      raw: data.subarray(offset),
    }
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

/* ----------------------------- 隧道内的 IPv4/TCP ----------------------------- */

const buildTcpPacket = ({ src, dst, sport, dport, seq, ack, flags, payload = new Uint8Array(0) }) => {
  const tcpLength = 20 + payload.length;
  const ipLength = 20 + tcpLength;
  const size = 8 + ipLength;
  const packet = new Uint8Array(size);
  packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03, 0x00, 0x21]);
  packet.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6], 8);
  packet.set(src.split('.').map(Number), 20);
  packet.set(dst.split('.').map(Number), 24);
  setU16(packet, 10, ipLength);
  setU16(packet, 12, Math.floor(Math.random() * 65535));
  setU16(packet, 18, checksum(packet, 8, 20));
  setU16(packet, 28, sport);
  setU16(packet, 30, dport);
  setU32(packet, 32, seq);
  setU32(packet, 36, ack);
  packet[40] = 0x50;
  packet[41] = flags;
  setU16(packet, 42, 65535);
  if (payload.length) packet.set(payload, 48);
  const pseudo = new Uint8Array(12 + tcpLength);
  pseudo.set(packet.subarray(20, 28));
  pseudo[9] = 6;
  setU16(pseudo, 10, tcpLength);
  pseudo.set(packet.subarray(28, 28 + tcpLength), 12);
  setU16(packet, 44, checksum(pseudo, 0, pseudo.length));
  return packet;
};

const parseIpTcp = ip => {
  if (ip.length < 20 || ip[9] !== 6) return null;
  const ihl = (ip[0] & 0x0f) * 4;
  if (ip.length < ihl + 20) return null;
  return {
    sport: u16(ip, ihl),
    dport: u16(ip, ihl + 2),
    seq: u32(ip, ihl + 4),
    ackNum: u32(ip, ihl + 8),
    flags: ip[ihl + 13],
  };
};

/* ----------------------------- 连接与测量 ----------------------------- */

/** 从 socket 里按字节取数据的读取器 */
function makeReader(socket) {
  let pending = Buffer.alloc(0);
  let notify = null;
  let ended = false;
  let failed = null;

  socket.on('data', chunk => {
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    if (notify) { const cb = notify; notify = null; cb(); }
  });
  socket.on('end', () => { ended = true; if (notify) { const cb = notify; notify = null; cb(); } });
  socket.on('error', err => { failed = err; if (notify) { const cb = notify; notify = null; cb(); } });

  const need = async n => {
    for (;;) {
      if (pending.length >= n) {
        const out = pending.subarray(0, n);
        pending = pending.subarray(n);
        return new Uint8Array(out);
      }
      if (failed) throw failed;
      if (ended) throw new Error('sstp: eof');
      await new Promise(r => { notify = r; });
    }
  };
  const readLine = async () => {
    for (;;) {
      const index = pending.indexOf(10);
      if (index >= 0) {
        const line = pending.subarray(0, index).toString('utf8');
        pending = pending.subarray(index + 1);
        return line.replace(/\r$/, '');
      }
      if (failed) throw failed;
      if (ended) throw new Error('sstp: eof');
      await new Promise(r => { notify = r; });
    }
  };
  const readPacket = async () => {
    const header = await need(4);
    const length = u16(header, 2) & 0x0fff;
    return { ctrl: (header[1] & 1) === 1, body: length > 4 ? await need(length - 4) : new Uint8Array(0) };
  };
  return { need, readLine, readPacket };
}

function deadline(promise, ms, socket, label) {
  return new Promise((res, rej) => {
    const timer = setTimeout(() => {
      try { socket.destroy(); } catch {}
      rej(new Error(`${label} 超时 ${ms}ms`));
    }, ms);
    promise.then(v => { clearTimeout(timer); res(v); }, e => { clearTimeout(timer); rej(e); });
  });
}

const randomU32 = () => Math.floor(Math.random() * 0xffffffff) >>> 0;

async function openTunnel(r) {
  const t0 = Date.now();
  const address = await deadline(dns.lookup(r.host), STEP_TIMEOUT, { destroy() {} }, 'dns');
  const dnsMs = Date.now() - t0;

  const t1 = Date.now();
  const socket = tls.connect({
    host: address.address,
    port: r.port,
    // IP 形式不设 SNI（RFC 6066 不允许，Node 会告警）
    servername: /^\d+\.\d+\.\d+\.\d+$/.test(r.host) ? undefined : r.host,
    rejectUnauthorized: false,   // VPN Gate 节点普遍是自签证书
  });
  await deadline(once(socket, 'connect'), STEP_TIMEOUT, socket, 'tcp');
  const tcpMs = Date.now() - t1;

  const t2 = Date.now();
  await deadline(once(socket, 'secureConnect'), STEP_TIMEOUT, socket, 'tls');
  const tlsMs = Date.now() - t2;

  const io = makeReader(socket);
  const protocolId = new Uint8Array(2);
  setU16(protocolId, 0, 1);
  const mru = new Uint8Array(2);
  setU16(mru, 0, 1500);

  let pppId = 1;
  const t3 = Date.now();
  socket.write(Buffer.from(concat(
    enc.encode(
      `SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n` +
      `Host: ${r.host}\r\n` +
      `Content-Length: 18446744073709551615\r\n` +
      `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`,
    ),
    sstpControl(0x0001, [{ id: 1, data: protocolId }]),
    sstpData(pppFrame(PPP_LCP, 1, pppId++, [{ type: 1, data: mru }])),
  )));

  const status = await deadline(io.readLine(), STEP_TIMEOUT, socket, 'sstp 状态行');
  while ((await deadline(io.readLine(), STEP_TIMEOUT, socket, 'sstp 头')) !== '');
  if (!status.includes('200')) throw new Error(`sstp: http ${status}`);

  let myIp = null;
  let cryptoBinding = false;
  for (let round = 0; round < 40 && !myIp; round++) {
    const packet = await deadline(io.readPacket(), STEP_TIMEOUT, socket, 'sstp 握手');
    if (has('debug')) {
      console.log(`  [trace] ctrl=${packet.ctrl} len=${packet.body.length + 4} ` +
        `${packet.ctrl ? `msg=${u16(packet.body, 0)}` : `proto=0x${(parsePPP(packet.body)?.protocol ?? 0).toString(16)}`}`);
    }
    if (packet.ctrl) {
      // SSTP 控制帧：CONNECT_ACK(2) 里可能带 CRYPT_BINDING_REQ(attr 4)。
      // 实测 VPN Gate 节点**并不强制**：不应答（--ignore-cb）同样能完成 PPP 协商并建链。
      // 这里应答只是更规范；Workers 拿不到对端证书，两边都能连上。
      if (packet.body.length >= 4 && u16(packet.body, 0) === 2 && u16(packet.body, 2) > 0) {
        const attr = packet.body.subarray(4);
        const id = attr[1];
        const length = u16(attr, 2);
        const data = attr.subarray(4, length);
        if (id === 4 && data.length >= 36) {
          cryptoBinding = true;
          // --ignore-cb：故意不应答 crypto binding，用来实测「服务端是否真的强制它」
          if (!has('ignore-cb')) {
            const nonce = data.subarray(4, 36);
            const certDer = socket.getPeerCertificate().raw;
            const certHash = nodeCrypto.createHash('sha256').update(certDer).digest();
            const mac = nodeCrypto.createHmac('sha256', nonce).update(certHash).digest();
            socket.write(Buffer.from(concat(
              sstpControl(0x0001, [
                { id: 1, data: protocolId },
                { id: 3, data: concat(new Uint8Array([0, 0, 0, 2]), new Uint8Array(mac)) },
              ]),
              sstpData(pppFrame(PPP_LCP, 1, pppId++, [{ type: 1, data: mru }])),
            )));
          }
        }
      }
      continue;
    }
    const ppp = parsePPP(packet.body);
    if (!ppp) continue;
    if (ppp.protocol === PPP_LCP && ppp.code === 1) {
      const ack = new Uint8Array(ppp.raw);
      ack[2] = 2;
      socket.write(Buffer.from(sstpData(ack)));
      socket.write(Buffer.from(sstpData(papFrame(pppId++, r.user, r.pass))));
    } else if (ppp.protocol === PPP_PAP && ppp.code === 2) {
      socket.write(Buffer.from(sstpData(pppFrame(PPP_IPCP, 1, pppId++, [{ type: 3, data: new Uint8Array(4) }]))));
    } else if (ppp.protocol === PPP_IPCP && ppp.code === 1) {
      // 服务端主动发来 IPCP Configure-Request：先 Ack，IP 由后面的 Nak/Ack 携带
      const ack = new Uint8Array(ppp.raw);
      ack[2] = 2;
      socket.write(Buffer.from(sstpData(ack)));
    } else if (ppp.protocol === PPP_IPCP && (ppp.code === 3 || ppp.code === 2)) {
      const option = parseOptions(ppp.payload).find(o => o.type === 3);
      if (option) {
        myIp = [...option.data].join('.');
        socket.write(Buffer.from(sstpData(pppFrame(PPP_IPCP, 1, pppId++, [{ type: 3, data: option.data }]))));
      }
    }
  }
  if (!myIp) throw new Error('sstp: 没能从 IPCP 拿到 IP');
  const sstpMs = Date.now() - t3;

  return { socket, io, myIp, peer: address.address, dnsMs, tcpMs, tlsMs, sstpMs, cryptoBinding };
}

/** 隧道内一次 TCP 三次握手 */
async function innerHandshake(tunnel, targetIp, targetPort, sourcePort) {
  const seq0 = randomU32();
  const t0 = Date.now();
  tunnel.socket.write(Buffer.from(buildTcpPacket({
    src: tunnel.myIp, dst: targetIp, sport: sourcePort, dport: targetPort, seq: seq0, ack: 0, flags: 0x02,
  })));
  for (let i = 0; i < 30; i++) {
    const packet = await deadline(tunnel.io.readPacket(), STEP_TIMEOUT, tunnel.socket, '隧道内握手');
    if (packet.ctrl) continue;
    const ppp = parsePPP(packet.body);
    if (!ppp || ppp.protocol !== PPP_IPV4) continue;
    const info = parseIpTcp(ppp.ip);
    if (!info || info.dport !== sourcePort || info.sport !== targetPort) continue;
    if ((info.flags & 0x12) !== 0x12) continue;   // 需要 SYN+ACK
    tunnel.socket.write(Buffer.from(buildTcpPacket({
      src: tunnel.myIp, dst: targetIp, sport: sourcePort, dport: targetPort,
      seq: (seq0 + 1) >>> 0, ack: (info.seq + 1) >>> 0, flags: 0x10,
    })));
    return Date.now() - t0;
  }
  throw new Error('隧道内 TCP 握手超时');
}

/* --------------------- --exit-ip：隧道出口 IP 对比 vpngate.csv --------------------- */

/** 极简 HTTP 响应解析：只取状态码与正文（正文兼容 chunked） */
function parseHttpResponse(raw) {
  const sep = raw.indexOf('\r\n\r\n');
  if (sep < 0) return { status: 0, body: '' };
  const head = raw.subarray(0, sep).toString('latin1');
  const status = Number((head.match(/^HTTP\/1\.[01] (\d{3})/) || [])[1] || 0);
  let body = raw.subarray(sep + 4);
  if (/transfer-encoding:\s*chunked/i.test(head)) body = dechunk(body);
  return { status, body: body.toString('utf8').trim() };
}

function dechunk(buf) {
  const parts = [];
  let i = 0;
  while (i < buf.length) {
    const nl = buf.indexOf('\r\n', i);
    if (nl < 0) break;
    const size = parseInt(buf.subarray(i, nl).toString('latin1').split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size <= 0) break;
    parts.push(buf.subarray(nl + 2, nl + 2 + size));
    i = nl + 2 + size + 2;
  }
  return Buffer.concat(parts);
}

/** 把 SSTP 隧道包成 createTcpStream 需要的句柄（契约同 src/sstp/pool.js 的 tunnel） */
function makeTunnelHandle(socket, myIp) {
  const streams = new Map();
  let nextPort = 10000 + Math.floor(Math.random() * 50000);
  return {
    streams,
    alive: true,
    sourceBytes: new Uint8Array(myIp.split('.').map(Number)),
    allocPort() {
      for (let i = 0; i < 50000; i++) {
        const candidate = 10000 + ((nextPort++ - 10000) % 50000);
        if (!streams.has(candidate)) return candidate;
      }
      throw new Error('没有可用源端口');
    },
    write(bytes) { socket.write(Buffer.from(bytes)); return Promise.resolve(); },
    removeStream(port) { streams.delete(port); },
  };
}

/** 在既有隧道里开一条 TCP 流，其上跑 TLS + 一个 HTTP GET，返回 { status, body } */
async function httpsViaTunnel(tunnel, targetIp, hostName, reqPath) {
  const handle = makeTunnelHandle(tunnel.socket, tunnel.myIp);
  const stream = createTcpStream(handle, targetIp, 443);
  handle.streams.set(stream.sourcePort, stream);

  // 隧道读循环：唯一消费 socket 的地方，按目的端口分发（与 pool.js 的 run() 一致）
  const pump = (async () => {
    for (;;) {
      const packet = await tunnel.io.readPacket();
      if (packet.ctrl) continue;
      const ppp = parsePPP(packet.body);
      if (!ppp || ppp.protocol !== PPP_IPV4) continue;
      const info = parseIpTcpStack(ppp.ip);
      if (!info) continue;
      const target = handle.streams.get(info.dstPort);
      if (!target) continue;
      target.deliver(info, ppp.ip);
      target.checkRetransmit();
    }
  })().catch(() => { /* 隧道关闭时结束读循环 */ });

  const duplex = Duplex.from({
    readable: Readable.fromWeb(stream.readable),
    writable: Writable.fromWeb(stream.writable),
  });

  try {
    await stream.handshake(STEP_TIMEOUT);
    const sock = tls.connect({ socket: duplex, servername: hostName, rejectUnauthorized: false });
    await deadline(once(sock, 'secureConnect'), STEP_TIMEOUT, sock, 'tls');

    sock.write(
      `GET ${reqPath} HTTP/1.1\r\nHost: ${hostName}\r\nUser-Agent: curl/8.0\r\n` +
      `Accept: */*\r\nConnection: close\r\n\r\n`,
    );
    const raw = await deadline(new Promise((resolve, reject) => {
      const chunks = [];
      sock.on('data', chunk => chunks.push(chunk));
      sock.once('end', () => resolve(Buffer.concat(chunks)));
      sock.once('error', reject);
    }), STEP_TIMEOUT, sock, 'http');

    return parseHttpResponse(raw);
  } finally {
    try { duplex.destroy(); } catch {}
    try { stream.destroy(); } catch {}
    void pump;
  }
}

/** 解析 API 主机名：先系统解析（会走 TUN），失败再退回公共 DNS */
async function resolveApiIp(hostName) {
  try {
    return (await dns.lookup(hostName, { family: 4 })).address;
  } catch {
    const resolver = new dns.Resolver();
    resolver.setServers(['1.1.1.1', '8.8.8.8', '223.5.5.5']);
    const list = await resolver.resolve4(hostName);
    return list[0];
  }
}

const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * `--exit-ip`：不经 workerd，直接用 Node 原生 socket 建 SSTP 隧道，
 * 在隧道内访问 https://api.ip.sb/ip，把出口 IP 与 vpngate.csv 里该节点的 IP 对比。
 * 本机在受限网络（需 TUN / 127.0.0.1:1080 才能到节点）时，这是唯一能本地跑通的口径。
 */
async function runExitIpCheck() {
  const csvFile = CSV_PATH || defaultCsvPath();
  let csvMap = null;
  if (csvFile) {
    try { csvMap = loadVpngateCsv(csvFile); } catch { /* CSV 不可用则只做展示 */ }
  }
  const hit = lookupNode(csvMap, host);
  const expectedIp = IPV4_LITERAL.test(host) ? host : hit?.ip || null;

  console.log('=== SSTP 隧道出口 IP 对比（不经 workerd，走 Node 原生 socket）===\n');
  console.log(`节点          sstp://${host}:${port}`);
  console.log(`CSV 期望 IP   ${expectedIp
    ? `${expectedIp}   [${hit ? `vpngate.csv ${hit.country} ${hit.speed} Mbps` : '--node 本身就是 IP'}]`
    : `未知（${csvFile || '未找到 vpngate.csv'} 里没有 ${host}）`}`);
  console.log(`API           https://${API_HOST}/ip`);

  // 对照：不经隧道的直连出口（本机会走 TUN）。只用来证明「隧道确实换了出口」
  let directIp = null;
  try {
    const r = await fetch(`https://${API_HOST}/ip`, { signal: AbortSignal.timeout(15000) });
    directIp = (await r.text()).trim();
    console.log(`本机直连出口  ${directIp}   （对照，未经隧道）`);
  } catch (err) {
    console.log(`本机直连出口  取不到（${err?.name || err?.message}），跳过对照`);
  }

  const apiIp = await resolveApiIp(API_HOST);
  console.log(`API 解析      ${API_HOST} = ${apiIp}\n`);

  const tunnel = await openTunnel({ host, port, user, pass });
  try {
    console.log(`实际拨到      ${tunnel.peer}:${port}   （本地解析 ${host} 的结果）`);
    console.log(
      `隧道已建      虚拟 IP = ${tunnel.myIp}  ` +
      `(dns=${tunnel.dnsMs} tcp=${tunnel.tcpMs} tls=${tunnel.tlsMs} sstp=${tunnel.sstpMs} ms)`,
    );
    const res = await httpsViaTunnel(tunnel, apiIp, API_HOST, '/ip');
    const exitIp = res.body;
    console.log(`出口 IP       ${exitIp}   (HTTP ${res.status})`);

    if (res.status !== 200 || !IPV4_LITERAL.test(exitIp)) {
      console.error(`\n❌ 失败  隧道内未拿到合法 IP（status=${res.status} body=${JSON.stringify(exitIp)}）`);
      process.exitCode = 1;
      return;
    }

    // 硬性断言只有一条：隧道出口 ≠ 直连出口。
    // 与 CSV 里节点 IP 的关系**只作参考**——节点的接入地址与出网地址本就不必相同（节点 NAT），
    // 且 opengw.net 的域名解析可能随时间变更，拿它当判据会误报。
    if (directIp && exitIp === directIp) {
      console.error(`\n❌ 失败  隧道出口 IP 与本机直连相同（${exitIp}），隧道没有换出口`);
      process.exitCode = 1;
      return;
    }
    if (directIp) console.log(`与直连对比    ${exitIp} ≠ ${directIp}  ✔`);
    console.log(`参考：节点 IP ${expectedIp || `未知（${csvFile || '未找到 vpngate.csv'} 里没有 ${host}）`}`);
    if (expectedIp) console.log(`参考：出口 vs 节点  ${relationToNode(exitIp, expectedIp).label}`);
    console.log(`\n✅ 通过  隧道出口 IP ${exitIp}${directIp ? `（直连为 ${directIp}）` : ''}`);
  } finally {
    try { tunnel.socket.destroy(); } catch {}
  }
}

/* ----------------------------- 统计与建议 ----------------------------- */

const p95 = list => {
  const sorted = [...list].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)];
};
const round = ms => Math.ceil(ms / 100) * 100;

async function main() {
  if (EXIT_IP) return runExitIpCheck();

  console.log(`目标节点：sstp://${host}:${port}   隧道内目标：${TARGET}:${TARGET_PORT}`);
  console.log(`轮数 ${ROUNDS}，每轮隧道内 ${STREAMS} 条流，单步超时 ${STEP_TIMEOUT}ms\n`);

  const targetIp = await dns.lookup(TARGET).then(a => a.address).catch(() => null);
  if (!targetIp) { console.error(`无法解析 ${TARGET}`); process.exit(1); }

  const rows = [];
  for (let i = 0; i < ROUNDS; i++) {
    let tunnel = null;
    try {
      tunnel = await openTunnel({ host, port, user, pass });
      const inner = [];
      for (let s = 0; s < STREAMS; s++) {
        inner.push(await innerHandshake(tunnel, targetIp, TARGET_PORT, 10000 + s));
      }
      const row = {
        dns: tunnel.dnsMs, tcp: tunnel.tcpMs, tls: tunnel.tlsMs, sstp: tunnel.sstpMs,
        inner: inner[0], reuse: inner.slice(1), cold: tunnel.tcpMs + tunnel.tlsMs + tunnel.sstpMs + inner[0],
      };
      rows.push(row);
      console.log(
        `第 ${i + 1} 轮  dns=${row.dns}  tcp=${row.tcp}  tls=${row.tls}  sstp=${row.sstp}  ` +
        `inner=${row.inner}  reuse=[${row.reuse.join(', ')}]  冷启动合计=${row.cold} ms  ` +
        `虚拟IP=${tunnel.myIp}${tunnel.cryptoBinding ? '  ⚠ 该节点要求 SSTP crypto binding' : ''}`,
      );
    } catch (err) {
      console.log(`第 ${i + 1} 轮  失败：${err.message}`);
      if (has('debug')) console.log(err.stack);
    } finally {
      if (tunnel) { try { tunnel.socket.destroy(); } catch {} }
    }
  }

  if (!rows.length) { console.error('\n没有成功样本，无法给出建议'); process.exit(1); }

  const allReuse = rows.flatMap(r => r.reuse);
  const cold = p95(rows.map(r => r.cold));
  const sstpBuild = p95(rows.map(r => r.tcp + r.tls + r.sstp));
  const inner = p95(rows.map(r => r.inner));
  const reuse = allReuse.length ? p95(allReuse) : inner;

  if (rows.some(r => r.cryptoBinding)) {
    console.log('\nℹ 服务端发送了 SSTP Crypto-Binding Req（attr 4）。');
    console.log('  实测（--ignore-cb）：VPN Gate 节点并不强制应答，不应答同样能建成隧道，');
    console.log('  所以 crypto binding 不是 cf-vpngate 连不上的原因（Worker 拿不到对端证书也无妨）。');
  }

  console.log('\n—— 实测建议（p95 × 安全系数，向上取整到 100ms）——');
  console.log(`  sstpConnectMs   ≈ ${round(sstpBuild * 1.5)}    // TCP+TLS+SSTP 建链：${Math.round(sstpBuild)}ms`);
  console.log(`  sstpHandshakeMs ≈ ${round(inner * 3)}     // 隧道内握手：${Math.round(inner)}ms`);
  console.log(`  dialTimeoutMs   ≈ ${round(Math.max(reuse * 3, 300))}    // 隧道常热时：reuse ${Math.round(reuse)}ms × 3`);
  console.log(`                  ≈ ${round(cold * 1.2)}    // 隧道常冷（每次新建）时：冷启动 ${Math.round(cold)}ms × 1.2`);
  console.log('\n说明：dialTimeoutMs 决定「落地多久没成才回落直连」。');
  console.log('  · 隧道复用命中（常态）→ 只需覆盖 reuse，取小值，首包更快；');
  console.log('  · 若隔离区常被回收、SSTP 多为冷启动 → 取大值，否则落地永远抢不到机会。');
  console.log('  · 落地长期不可达时，dialFailThreshold / dialFailCooldownMs 会临时跳过落地，不必把 dialTimeoutMs 压太小。');
}

main().catch(err => { console.error('探针异常：', err.message); process.exit(1); });
