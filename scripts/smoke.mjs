/**
 * 纯逻辑冒烟测试（不需要 wrangler / 网络 / Cloudflare 运行时）。
 *
 *   node scripts/smoke.mjs      # 或 npm test
 *
 * 覆盖：checksum 优化等价性、seq 回绕比较、隧道内 TCP 栈（建帧/握手/收包/乱序丢弃/分片）、
 *       落地与 path 解析、VLESS 头解析、/sub 访问控制。
 *
 * cloudflare:sockets 无法在 Node 里加载，用一个 stub 顶替（写到 CACHE_DIR）。
 */

import { register } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = pathToFileURL(join(ROOT, 'src') + '\\').href;
const CACHE_DIR = process.env.CACHE_DIR || 'Z:\\Temp';

mkdirSync(CACHE_DIR, { recursive: true });
const stub = join(CACHE_DIR, 'cf-sockets-stub.mjs');
const loader = join(CACHE_DIR, 'cf-sockets-loader.mjs');
writeFileSync(stub, `export const connect = () => { throw new Error('cloudflare:sockets 不可用'); };\n`);
writeFileSync(
  loader,
  `import { pathToFileURL } from 'node:url';\n` +
  `const STUB = pathToFileURL(${JSON.stringify(stub)}).href;\n` +
  `export async function resolve(specifier, context, next) {\n` +
  `  if (specifier === 'cloudflare:sockets') return { url: STUB, shortCircuit: true };\n` +
  `  return next(specifier, context);\n}\n`,
);
register(pathToFileURL(loader));

const { CONFIG } = await import(SRC + 'config.js');
const utils = await import(SRC + 'utils.js');
const { parseIpTcp, createTcpStream } = await import(SRC + 'sstp/tcp.js');
const { parseProxyAddress, raceDial } = await import(SRC + 'outbound.js');
const { parsePathProxy, parseFlag, detectInbound, parseVlessHeader } = await import(SRC + 'vless.js');
const { handleShareRequest } = await import(SRC + 'share.js');

let pass = 0, fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log('  ok   ' + name); } else { fail++; console.log('  FAIL  ' + name); }
};

/* ---------- 1. checksum 32 位宽优化是否与逐 16 位参考实现等价 ---------- */
const refChecksum = (data, offset, length) => {
  let sum = 0;
  for (let i = offset; i < offset + length - 1; i += 2) sum += ((data[i] << 8) | data[i + 1]);
  if (length & 1) sum += data[offset + length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
};
{
  let same = true;
  for (let t = 0; t < 500; t++) {
    const len = 1 + Math.floor(Math.random() * 300);
    const buf = new Uint8Array(len);
    crypto.getRandomValues(buf);
    if (utils.checksum(buf, 0, len) !== refChecksum(buf, 0, len)) { same = false; break; }
  }
  ok('checksum 与参考实现一致（含奇长度）', same);
}

/* ---------- 2. seq 回绕比较 ---------- */
ok(
  'seqLT 回绕正确',
  utils.seqLT(1, 2) && utils.seqLT(0xfffffffe, 0xffffffff) && utils.seqLT(0xfffffffe, 2) && !utils.seqLT(2, 0xfffffffe),
);

/* ---------- 3. 隧道内 TCP 栈 ---------- */
const ipOf = '10.1.0.5';
const buildIpPacket = ({ srcPort, dstPort, seq, ack, flags, payload = new Uint8Array(0) }) => {
  const tcpLen = 20 + payload.length;
  const ipLen = 20 + tcpLen;
  const ip = new Uint8Array(ipLen);
  ip.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]);
  ip.set(ipOf.split('.').map(Number), 12);
  ip.set([8, 8, 8, 8], 16);
  utils.setU16(ip, 2, ipLen);
  utils.setU16(ip, 18, utils.checksum(ip, 0, 20));
  utils.setU16(ip, 20, srcPort);
  utils.setU16(ip, 22, dstPort);
  utils.setU32(ip, 24, seq);
  utils.setU32(ip, 28, ack);
  ip[32] = 0x50; ip[33] = flags;
  utils.setU16(ip, 34, 65535);
  if (payload.length) ip.set(payload, 40);
  const pseudo = new Uint8Array(12 + tcpLen);
  pseudo.set(ip.subarray(12, 20));
  pseudo[9] = 6;
  utils.setU16(pseudo, 10, tcpLen);
  pseudo.set(ip.subarray(20, 20 + tcpLen), 12);
  utils.setU16(ip, 36, utils.checksum(pseudo, 0, pseudo.length));
  return ip;
};

const makeTunnel = () => {
  const written = [];
  return {
    written,
    sourceBytes: new Uint8Array(ipOf.split('.').map(Number)),
    alive: true,
    allocPort: () => 40000,
    removeStream: () => {},
    write: bytes => { written.push(bytes); return Promise.resolve(); },
  };
};

{
  const tunnel = makeTunnel();
  const stream = createTcpStream(tunnel, '8.8.8.8', 443);

  const synPromise = stream.handshake();
  const syn = tunnel.written[0];
  const synIp = syn.subarray(8);
  const synInfo = parseIpTcp(synIp);
  ok('SYN 帧：源/目的端口正确', synInfo.srcPort === 40000 && synInfo.dstPort === 443);
  ok('SYN 帧：flags = SYN', synInfo.flags === 0x02);
  ok('SYN 帧：IPv4 校验和自校验为 0', refChecksum(synIp, 0, 20) === 0);

  const serverSeq = 5000;
  const synAck = buildIpPacket({ srcPort: 443, dstPort: 40000, seq: serverSeq, ack: synInfo.seq + 1, flags: 0x12 });
  stream.deliver(parseIpTcp(synAck), synAck);
  const handshaked = await synPromise.then(() => true, () => false);
  ok('收到 SYN+ACK 后握手完成', handshaked && stream.state === 'established');
  ok('握手后回了一个 ACK', tunnel.written.length >= 2);

  const reader = stream.readable.getReader();
  const payload = new Uint8Array([1, 2, 3, 4, 5]);
  const dataPkt = buildIpPacket({ srcPort: 443, dstPort: 40000, seq: serverSeq + 1, ack: 0, flags: 0x18, payload });
  stream.deliver(parseIpTcp(dataPkt), dataPkt);
  const got = await reader.read();
  ok('按序数据被交付', got.value && got.value.length === 5 && got.value[4] === 5);

  // 重复段 / 乱序段必须丢弃（旧版会当成新数据写进上层，导致数据损坏）
  const dupPkt = buildIpPacket({ srcPort: 443, dstPort: 40000, seq: serverSeq + 1, ack: 0, flags: 0x18, payload });
  stream.deliver(parseIpTcp(dupPkt), dupPkt);
  const ooPkt = buildIpPacket({ srcPort: 443, dstPort: 40000, seq: serverSeq + 99, ack: 0, flags: 0x18, payload });
  stream.deliver(parseIpTcp(ooPkt), ooPkt);
  const after = await Promise.race([reader.read(), new Promise(r => setTimeout(() => r({ value: null }), 50))]);
  ok('重复段与乱序段被丢弃', after.value == null);

  const writer = stream.writable.getWriter();
  const before = tunnel.written.length;
  await writer.write(new Uint8Array(3000));
  const merged = tunnel.written.slice(before).reduce((n, b) => n + b.length, 0);
  ok('上行 3000 字节按 mss=1400 分片', merged > 3000 && merged >= 8 * 2 + 20 * 2 + 3000);
  writer.releaseLock();
  await reader.cancel().catch(() => {});
}

/* ---------- 3b. 重传必须沿用原始 seq、携带当前 ack；握手后不再重传 SYN ---------- */
{
  const tunnel = makeTunnel();
  const stream = createTcpStream(tunnel, '8.8.8.8', 443);
  const serverSeq = 7000;

  // 握手：handshake() 会同步写出 SYN，之后才能取到它
  const handshakePromise = stream.handshake();
  const synInfo = parseIpTcp(tunnel.written[0].subarray(8));
  const synAck = buildIpPacket({ srcPort: 443, dstPort: 40000, seq: serverSeq, ack: synInfo.seq + 1, flags: 0x12 });
  stream.deliver(parseIpTcp(synAck), synAck);
  await handshakePromise;

  // ① 握手完成后 SYN 不应再被重传（SYN-ACK 的 ackNum 必须正确清掉 unacked）
  CONFIG.sstpRtoMs = 0;
  const afterHandshake = tunnel.written.length;
  stream.checkRetransmit();
  ok('握手完成后不再重传 SYN', tunnel.written.length === afterHandshake);

  // ② 先发 100 字节（此时 ack 只消化了 SYN）
  const writer = stream.writable.getWriter();
  const beforeData = tunnel.written.length;
  await writer.write(new Uint8Array(100));
  const dataFrame = parseIpTcp(tunnel.written[beforeData].subarray(8));
  const origSeq = dataFrame.seq;
  ok('数据帧的 ack = 对端 seq+1（仅 SYN）', dataFrame.ackNum === serverSeq + 1);

  // ③ 再收到 5 字节 → 我们这边的 ack 前进 5（ack 号要回显我们的 seq，模拟真实对端）
  const payload = new Uint8Array([9, 8, 7, 6, 5]);
  const dataPkt = buildIpPacket({
    // 只确认前 40 字节 → 100 字节那段仍未确认，应当留在重传队列里
    srcPort: 443, dstPort: 40000, seq: serverSeq + 1, ack: origSeq + 40, flags: 0x18, payload,
  });
  stream.deliver(parseIpTcp(dataPkt), dataPkt);

  // ④ 强制重传：必须沿用原始 seq，但 ack 是**当前**的（5001+5）
  const beforeRt = tunnel.written.length;
  stream.checkRetransmit();
  const rtFrames = tunnel.written.slice(beforeRt).filter(f => parseIpTcp(f.subarray(8))?.flags === 0x18);
  ok('触发了重传', rtFrames.length >= 1);
  const rt = parseIpTcp(rtFrames[0].subarray(8));
  ok('重传帧沿用原始 seq', rt.seq === origSeq);
  ok('重传帧携带当前 ack（而非旧值）', rt.ackNum === serverSeq + 1 + payload.length);
  CONFIG.sstpRtoMs = 1000;

  writer.releaseLock();
}

/* ---------- 4. 落地解析 ---------- */
ok('sstp:// 解析', parseProxyAddress('sstp://1.2.3.4:443')?.type === 'sstp');
ok('sstp:// 带认证', parseProxyAddress('sstp://u:p@h:443')?.username === 'u');
ok('proxyip IP:port', parseProxyAddress('1.2.3.4:8443')?.port === 8443);
ok('proxyip 纯域名默认 443', parseProxyAddress('a.b.c')?.port === 443);
ok('ipv6 括号形式', parseProxyAddress('[2001:db8::1]:443')?.host === '2001:db8::1');
ok('其它协议一律不支持', parseProxyAddress('socks5://1.2.3.4:1080') === null && parseProxyAddress('http://h:80') === null);

/* ---------- 5. path 落地解析 ---------- */
const urlOf = p => new URL('https://x.invalid' + p);
ok('/fdip=<落地>?ed=2560', parsePathProxy(urlOf('/fdip=sstp://1.2.3.4:443?ed=2560')) === 'sstp://1.2.3.4:443');
ok('键名任意', parsePathProxy(urlOf('/proxy=1.2.3.4:443')) === '1.2.3.4:443');
ok('URL 编码后仍可解析', parsePathProxy(urlOf('/fdip%3Dsstp%3A%2F%2Fvpn.example%3A443%3Fed%3D2560')) === 'sstp://vpn.example:443');
ok('无 = 返回 null', parsePathProxy(urlOf('/sub')) === null);
/* ---------- 5b. race 开关 ---------- */
{
  const req1 = new Request('https://x.invalid/x?race=1');
  const req2 = new Request('https://x.invalid/x');
  ok('race 开关', parseFlag(urlOf('/x?race=1'), req1, 'race') === true && parseFlag(urlOf('/x'), req2, 'race') === false);
  ok('race 也认 X-Race 头', parseFlag(urlOf('/x'), new Request('https://x.invalid/x', { headers: { 'X-Race': '1' } }), 'race') === true);
}

/* ---------- 5c. 竞速拨号 ---------- */
{
  const conn = () => { const o = { closed: 0, close() { o.closed += 1; } }; return o; };
  const a = conn(), b = conn(), c = conn();
  const slow = (value, ms) => () => new Promise(r => setTimeout(() => r(value), ms));
  const fail = () => Promise.resolve(null);

  const winner = await raceDial([slow(a, 60), slow(b, 5), slow(c, 100)]);
  ok('竞速：最快就绪的胜出', winner === b);
  await new Promise(r => setTimeout(r, 200));
  ok('竞速：输家被关闭', a.closed === 1 && c.closed === 1);

  ok('竞速：全部失败 → null', (await raceDial([fail, fail])) === null);
  const only = conn();
  ok('竞速：单候选直接返回', (await raceDial([() => Promise.resolve(only)])) === only);
  ok('竞速：空候选 → null', (await raceDial([])) === null);
  const d = conn();
  ok('竞速：部分失败取成功者', (await raceDial([fail, () => Promise.resolve(d), fail])) === d);
}

/* ---------- 6. VLESS 头解析 ---------- */
{
  const uuid = CONFIG.uuid;
  const uuidBytes = utils.getUuidBytes(uuid);
  const host = 'example.com';
  const hostBytes = new TextEncoder().encode(host);
  // ver(1) + uuid(16) + addonLen(1) + cmd(1) + port(2) + addrType(1) + addrLen(1) + addr + payload
  const head = new Uint8Array(24 + hostBytes.length + 2);
  head[0] = 0;
  head.set(uuidBytes, 1);
  head[17] = 0;                 // addon len
  head[18] = 1;                 // cmd = tcp
  head[19] = 443 >> 8; head[20] = 443 & 255;
  head[21] = 2;                 // addr type = domain
  head[22] = hostBytes.length;
  head.set(hostBytes, 23);
  head[23 + hostBytes.length] = 0; head[24 + hostBytes.length] = 80;

  const session = parseVlessHeader(head, uuidBytes);
  ok('VLESS 头解析出 host/port', session?.host === host && session?.port === 443);
  ok('detectInbound：完整头 → 1', detectInbound(head, uuidBytes) === 1);
  ok('detectInbound：截断 → 0（继续等）', detectInbound(head.subarray(0, 10), uuidBytes) === 0);
  ok('detectInbound：prefixChecked 后跳过比对', detectInbound(head.subarray(0, 10), uuidBytes, true) === 0);
  const bad = new Uint8Array(head); bad[5] ^= 0xff;
  ok('detectInbound：UUID 不符 → 3', detectInbound(bad, uuidBytes) === 3);
}

/* ---------- 7. /sub 访问控制 ---------- */
{
  const req = p => new Request('https://x.invalid' + p);
  ok('subAuth=uuid：无 UUID → 404', handleShareRequest(req('/sub'), {}, urlOf('/sub')).status === 404);
  const r2 = handleShareRequest(req(`/${CONFIG.uuid}/sub`), {}, urlOf(`/${CONFIG.uuid}/sub`));
  ok('subAuth=uuid：路径带正确 UUID → 200', r2.status === 200 && (await r2.text()).includes('vless://'));
  ok(
    'subAuth=uuid：query 带正确 UUID → 200',
    handleShareRequest(req('/sub?uuid=' + CONFIG.uuid), {}, urlOf('/sub?uuid=' + CONFIG.uuid)).status === 200,
  );
  ok('subAuth=uuid：错误 UUID → 404', handleShareRequest(req('/sub?uuid=wrong'), {}, urlOf('/sub?uuid=wrong')).status === 404);
  CONFIG.subAuth = 'off';
  ok('subAuth=off：一律 404', handleShareRequest(req('/sub'), {}, urlOf('/sub')).status === 404);
  CONFIG.subAuth = 'none';
  ok('subAuth=none：免校验 200', handleShareRequest(req('/sub'), {}, urlOf('/sub')).status === 200);
  CONFIG.subAuth = 'uuid';
}

console.log(`\n通过 ${pass} 项，失败 ${fail} 项`);
process.exit(fail ? 1 : 0);
