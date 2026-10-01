/**
 * 端到端测试：SSTP 隧道「出口 IP 一致性」。
 *
 * 要回答的问题：流量是不是真的从 SSTP 节点出去了，而不是被 Worker 回落成了直连？
 *
 * 断言链（除对照组外，全部在 SSTP 隧道内完成）：
 *   ① 期望的节点 IP（expectedIp）取自 **vpngate.csv 的 `IP` 列**，不依赖 DNS
 *   ② 隧道内 DNS 解析 API 主机名（默认 api.ip.sb）                                → apiIp
 *   ③ 隧道内 HTTPS（VLESS TCP → apiIp:443 + TLS，SNI=API 主机名）访问 /ip        → exitIp
 *   ④ 断言 exitIp !== 本机直连 IP（**唯一硬性判据**：流量确实换了出口）
 *
 * 与 CSV 里节点 IP 的关系**只作参考、不判失败**：VPN Gate 节点的接入地址 ≠ 出网地址
 * （节点做 NAT，实测 219.100.37.17 → 出口 219.100.37.234），且 opengw.net 的域名解析
 * 可能随时间变更、导致某个节点失效。拿 IP 相等当判据会误报，所以只打印关系供人参考。
 * 关系判定见 scripts/vpngate-csv.mjs 的 relationToNode()。
 *
 * CSV 的作用：给 `--node` 传域名时提供该节点的已知 IP 作参考；CSV 缺失不影响测试结论。
 * `--check-dns` 可额外做一次隧道内解析做交叉比对，不一致只告警、不判失败。
 *
 * 为什么必须 `global=1`：不带它时 Worker 会在落地失败/超时后**回落直连**，
 * 于是"测试通过"可能只是直连的结果，毫无意义。`global=1` 关掉回落与拨号超时。
 *
 * 用法：
 *   npm run test:exit-ip
 *   node scripts/exit-ip.mjs --node 219.100.37.17:443
 *   node scripts/exit-ip.mjs --node public-vpn-68.opengw.net:443
 *   node scripts/exit-ip.mjs --csv ../vpngate/vpngate.csv --check-dns
 *   node scripts/exit-ip.mjs --url wss://your-worker.workers.dev    # 打线上 Worker
 *
 * 注意（本地跑不通通常是网络，不是代码）：本机若在受限网络里（SSTP 节点要经 TUN 或
 * `127.0.0.1:1080` 代理才可达），Node 走系统路由会经过 TUN 所以能连，而 `wrangler dev` 里
 * workerd 的 `connect()` 不走 TUN，本地必然连不上节点。此时本地失败**不能**判定线上失败：
 * 请用 `--url` 打线上 Worker，或改用 `node scripts/sstp-probe.mjs <node> --exit-ip`
 * （走 Node 原生 socket，能过 TUN，同样按 CSV 的 IP 做对比）。
 */
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import { defaultCsvPath, loadVpngateCsv, lookupNode, relationToNode } from './vpngate-csv.mjs';

/* ---------------- 参数 ---------------- */

const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  if (i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--')) return argv[i + 1];
  const eq = argv.find(a => a.startsWith(`--${name}=`));
  return eq ? eq.slice(name.length + 3) : fallback;
};

if (argv.includes('-h') || argv.includes('--help')) {
  console.log(`用法：node scripts/exit-ip.mjs [选项]

  --url <ws://|wss://|http://|https://>  Worker 地址（默认 ${process.env.WS_URL || 'ws://127.0.0.1:8787'}）
  --node <host:port>                     SSTP 落地节点（默认 ${process.env.SSTP_NODE || '219.100.37.17:443'}）
  --api <host>                           查询出口 IP 的站点（默认 ${process.env.API_HOST || 'api.ip.sb'}）
  --dns <host:port>                      隧道内使用的 DNS（默认 ${process.env.DNS_SERVER || '1.1.1.1:53'}）
  --uuid <uuid>                          VLESS UUID（默认 ${process.env.UUID || '495c7195-85b8-498a-bf20-2ea9ce9175b5'}）
  --timeout <ms>                         总超时（默认 ${process.env.TIMEOUT || 90000}）
  --csv <path>                           vpngate.csv 路径（默认自动探测，见 scripts/vpngate-csv.mjs）
  --check-dns                            额外做一次隧道内解析节点域名，与 CSV 的 IP 交叉比对
  --no-global                            不加 global=1（允许回落直连，仅用于排查）

环境变量同名亦可（WS_URL / SSTP_NODE / API_HOST / DNS_SERVER / UUID / TIMEOUT / GLOBAL / VPNGATE_CSV）。
`);
  process.exit(0);
}

const RAW_URL = arg('url', process.env.WS_URL || 'ws://127.0.0.1:8787');
const NODE = arg('node', process.env.SSTP_NODE || '219.100.37.17:443');
const DNS_SERVER = arg('dns', process.env.DNS_SERVER || '1.1.1.1:53');
const API_HOST = arg('api', process.env.API_HOST || 'api.ip.sb');
const UUID = arg('uuid', process.env.UUID || '495c7195-85b8-498a-bf20-2ea9ce9175b5');
const TIMEOUT = Number(arg('timeout', process.env.TIMEOUT || 90000));
/** 强制走落地（global=1）；关掉回落直连，否则测试没有意义 */
const FORCE_TUNNEL = argv.includes('--no-global') ? false : process.env.GLOBAL !== '0';
/** 期望的节点 IP 来源：vpngate.csv */
const CSV_PATH = arg('csv', process.env.VPNGATE_CSV || '');
/** 额外做一次隧道内 DNS 解析节点域名，与 CSV 交叉比对（不一致只告警） */
const CHECK_DNS = argv.includes('--check-dns') || process.env.CHECK_DNS === '1';

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/* ---------------- vpngate.csv ---------------- */

/** 惰性加载：CSV 只是期望值的来源，缺失时退回隧道内 DNS */
let csvMap = null;
let csvNote = '';
{
  const file = CSV_PATH || defaultCsvPath();
  if (!file) {
    csvNote = CSV_PATH ? `找不到 ${CSV_PATH}` : '未找到 vpngate.csv（自动探测失败）';
  } else {
    try {
      csvMap = loadVpngateCsv(file);
      csvNote = `${file}（${csvMap.size} 个节点）`;
    } catch (err) {
      csvNote = `${file} 解析失败：${err.message}`;
    }
  }
}
const PROXY = `sstp://vpn:vpn@${NODE}`;
const WS_BASE = RAW_URL.replace(/^http/, 'ws').replace(/\/+$/, '');
const WS_URL = `${WS_BASE}/fdip=${encodeURIComponent(PROXY)}${FORCE_TUNNEL ? '?global=1' : ''}`;

const t0 = Date.now();
const ms = () => `${Date.now() - t0} ms`;
const pad = (label, value) => console.log(`${label.padEnd(22)}${value}`);

/* ---------------- VLESS ---------------- */

const uuidBytes = (() => {
  const hex = UUID.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
})();

/** VLESS 请求头：version + uuid + addonLen + cmd + port + addrType + addr（IPv4 直填 4 字节，否则按域名） */
function vlessHeader(host, port, cmd = 1) {
  const isV4 = IPV4_RE.test(host);
  const addr = isV4 ? Uint8Array.from(host.split('.').map(Number)) : new TextEncoder().encode(host);
  const buf = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + (isV4 ? 0 : 1) + addr.length);
  let o = 0;
  buf[o++] = 0;
  buf.set(uuidBytes, o); o += 16;
  buf[o++] = 0;
  buf[o++] = cmd;
  buf[o++] = (port >> 8) & 0xff;
  buf[o++] = port & 0xff;
  buf[o++] = isV4 ? 1 : 2;
  if (!isV4) buf[o++] = addr.length;
  buf.set(addr, o);
  return buf;
}

/* ---------------- 隧道 ---------------- */

/**
 * 开一条 VLESS 隧道（一个 WebSocket = 一条目标 TCP 流）。
 * 返回 { duplex, close }：duplex 已剥掉 VLESS 响应头的 2 字节，是干净的字节流。
 */
function openTunnel(targetHost, targetPort, cmd = 1) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WS_URL);
    ws.binaryType = 'arraybuffer';

    let prefixDone = false;
    let settled = false;
    const fail = err => { if (!settled) { settled = true; reject(err); } };

    const duplex = new Duplex({
      read() {},
      write(chunk, _enc, cb) {
        try { ws.send(chunk); cb(); } catch (err) { cb(err); }
      },
      final(cb) { try { ws.close(); } catch { /* ignore */ } cb(); },
      destroy(err, cb) { try { ws.close(); } catch { /* ignore */ } cb(err); },
    });

    ws.onopen = () => {
      ws.send(vlessHeader(targetHost, targetPort, cmd));
      if (!settled) {
        settled = true;
        resolve({ duplex, ws, close: () => { try { ws.close(); } catch { /* ignore */ } } });
      }
    };
    ws.onmessage = ev => {
      let data = Buffer.from(ev.data);
      // Worker 在转发隧道数据前会先发 2 字节 VLESS 响应头（version + addonLen），要剥掉
      if (!prefixDone) { prefixDone = true; data = data.subarray(2); }
      if (data.length) duplex.push(data);
    };
    ws.onerror = e => fail(new Error(`WebSocket 错误：${e?.message || e?.type || 'unknown'}`));
    ws.onclose = ev => {
      duplex.push(null);
      fail(new Error(`WebSocket 被关闭 code=${ev.code} reason=${ev.reason || ''}（Worker 建链失败？）`));
    };
  });
}

/** 顺序读取：从 duplex 里精确取 n 字节 */
function makeReader(duplex) {
  let buf = Buffer.alloc(0);
  let wake = null;
  let ended = false;
  let error = null;
  const notify = () => { const w = wake; wake = null; w?.(); };

  duplex.on('data', d => { buf = Buffer.concat([buf, d]); notify(); });
  duplex.on('end', () => { ended = true; notify(); });
  duplex.on('error', e => { error = e; notify(); });

  return async n => {
    while (buf.length < n) {
      if (error) throw error;
      if (ended) throw new Error(`流提前结束（需要 ${n} 字节，只剩 ${buf.length}）`);
      await new Promise(r => { wake = r; });
    }
    const out = buf.subarray(0, n);
    buf = buf.subarray(n);
    return out;
  };
}

/* ---------------- DNS ---------------- */

const DNS_TYPE = { A: 1, AAAA: 28, TXT: 16 };

function dnsQueryPacket(name, type) {
  const parts = [
    Buffer.from([0x12, 0x34]),                          // transaction id
    Buffer.from([0x01, 0x00]),                          // flags: RD
    Buffer.from([0x00, 0x01]),                          // qdcount
    Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  // an/ns/ar
  ];
  for (const label of name.split('.').filter(Boolean)) {
    parts.push(Buffer.from([label.length]), Buffer.from(label, 'latin1'));
  }
  parts.push(Buffer.from([0x00]));                            // root
  parts.push(Buffer.from([(type >> 8) & 0xff, type & 0xff])); // qtype
  parts.push(Buffer.from([0x00, 0x01]));                      // qclass IN
  return Buffer.concat(parts);
}

function parseDnsAnswers(msg) {
  if (msg.length < 12) return [];
  const qd = msg.readUInt16BE(4);
  const an = msg.readUInt16BE(6);
  let off = 12;

  const skipName = () => {
    while (off < msg.length) {
      const len = msg[off];
      if (len === 0) { off += 1; return; }
      if ((len & 0xc0) === 0xc0) { off += 2; return; }   // 压缩指针
      off += len + 1;
    }
  };

  for (let i = 0; i < qd && off < msg.length; i++) { skipName(); off += 4; }

  const out = [];
  for (let i = 0; i < an && off + 10 <= msg.length; i++) {
    skipName();
    if (off + 10 > msg.length) break;
    const type = msg.readUInt16BE(off); off += 2;
    off += 2;                                   // class
    off += 4;                                   // ttl
    const rdlen = msg.readUInt16BE(off); off += 2;
    const rd = msg.subarray(off, off + rdlen);
    off += rdlen;
    if (type === 1 && rdlen === 4) out.push({ type: 'A', data: `${rd[0]}.${rd[1]}.${rd[2]}.${rd[3]}` });
    else if (type === 28 && rdlen === 16) out.push({ type: 'AAAA', data: '::' });
    else out.push({ type: String(type), data: rd.toString('latin1') });
  }
  return out;
}

/** 隧道内 DNS：VLESS TCP → dnsServer:53，走 DNS-over-TCP（2 字节长度前缀） */
async function resolveViaTunnel(name, type = 'A') {
  if (type === 'A' && IPV4_RE.test(name)) return [{ type: 'A', data: name }];

  const [dnsHost, dnsPortRaw] = DNS_SERVER.split(':');
  const dnsPort = Number(dnsPortRaw || 53);
  const { duplex, close } = await openTunnel(dnsHost, dnsPort, 1);
  try {
    const need = makeReader(duplex);
    const query = dnsQueryPacket(name, DNS_TYPE[type] || 1);
    duplex.write(Buffer.concat([Buffer.from([query.length >> 8, query.length & 0xff]), query]));

    const head = await need(2);
    const body = await need(head.readUInt16BE(0));
    return parseDnsAnswers(body);
  } finally {
    close();
  }
}

/* ---------------- HTTPS over 隧道 ---------------- */

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

function splitHttp(raw) {
  const sep = raw.indexOf('\r\n\r\n');
  if (sep < 0) return { head: raw.toString('latin1'), body: Buffer.alloc(0), status: 0 };
  const head = raw.subarray(0, sep).toString('latin1');
  let body = raw.subarray(sep + 4);
  const status = Number((head.match(/^HTTP\/1\.[01] (\d{3})/) || [])[1] || 0);
  if (/transfer-encoding:\s*chunked/i.test(head)) body = dechunk(body);
  return { head, body, status };
}

/** 隧道内 HTTPS：连 ip:443 后在此之上跑 TLS（SNI=sni） */
async function httpsViaTunnel(ip, sni, reqPath) {
  const { duplex, close } = await openTunnel(ip, 443, 1);
  try {
    const sock = tls.connect({ socket: duplex, servername: sni });
    await new Promise((resolve, reject) => {
      sock.once('secureConnect', resolve);
      sock.once('error', reject);
    });

    sock.write(
      `GET ${reqPath} HTTP/1.1\r\nHost: ${sni}\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
    );
    const raw = await new Promise((resolve, reject) => {
      const chunks = [];
      sock.on('data', c => chunks.push(c));
      sock.once('end', () => resolve(Buffer.concat(chunks)));
      sock.once('error', reject);
    });
    return splitHttp(raw);
  } finally {
    close();
  }
}

/** 对照组：本机直连拿出口 IP（不经过隧道） */
async function directIp() {
  try {
    const res = await fetch(`https://${API_HOST}/ip`, { signal: AbortSignal.timeout(10000) });
    return (await res.text()).trim();
  } catch (err) {
    return `<失败: ${err?.name || err?.message}>`;
  }
}

/* ---------------- 主流程 ---------------- */

const watchdog = setTimeout(() => {
  console.error(`\n❌ 失败  总超时 ${TIMEOUT}ms`);
  process.exit(1);
}, TIMEOUT);

const finish = (ok, msg) => {
  clearTimeout(watchdog);
  console.log(`\n${ok ? '✅ 通过' : '❌ 失败'}  ${msg}  (${ms()})`);
  process.exit(ok ? 0 : 1);
};

(async () => {
  const [nodeHost, nodePortRaw] = NODE.split(':');
  const nodePort = Number(nodePortRaw || 443);
  const nodeIsIp = IPV4_RE.test(nodeHost);

  console.log('=== SSTP 出口 IP 一致性测试 ===\n');
  pad('Worker', WS_URL);
  pad('落地', PROXY);
  pad('强制走落地', FORCE_TUNNEL ? '是（global=1，禁用直连回落）' : '否（允许回落，结果仅供参考）');
  pad('隧道内 DNS', DNS_SERVER);
  pad('API', `https://${API_HOST}/ip`);
  console.log();

  /* ① 期望的节点 IP：优先取 vpngate.csv 的 `IP` 列 */
  console.log(`① 期望的节点 IP（来源：vpngate.csv）`);
  pad('  CSV', csvNote);
  const csvHit = lookupNode(csvMap, nodeHost);
  let expectedIp = null;
  let expectedFrom = '';

  if (nodeIsIp) {
    expectedIp = nodeHost;
    expectedFrom = '--node 本身就是 IP';
  } else if (csvHit) {
    expectedIp = csvHit.ip;
    expectedFrom = `vpngate.csv（${csvHit.country || '?'} ${csvHit.speed || '?'} Mbps）`;
  }

  if (expectedIp) {
    console.log(`  → ${nodeHost} = ${expectedIp}   [${expectedFrom}]  (${ms()})`);
  } else {
    console.log(`  CSV 未命中 ${nodeHost}，退回隧道内 DNS 解析`);
    const records = await resolveViaTunnel(nodeHost, 'A');
    expectedIp = records.find(r => r.type === 'A')?.data || null;
    if (!expectedIp) {
      console.log(`  应答: ${JSON.stringify(records)}`);
      return finish(false, `${nodeHost} 既不在 CSV 里，隧道内也解析不出 A 记录`);
    }
    expectedFrom = '隧道内 DNS（CSV 未命中）';
    console.log(`  → ${nodeHost} = ${expectedIp}   [${expectedFrom}]  (${ms()})`);
  }

  if (CHECK_DNS && !nodeIsIp) {
    try {
      const records = await resolveViaTunnel(nodeHost, 'A');
      const dnsIp = records.find(r => r.type === 'A')?.data;
      console.log(
        dnsIp === expectedIp
          ? `  ✔ 交叉比对：隧道内 DNS 也解析为 ${dnsIp}`
          : `  ⚠ 交叉比对：隧道内 DNS 解析为 ${dnsIp ?? '（无 A 记录）'}，与期望值 ${expectedIp} 不一致（以 CSV 为准）`,
      );
    } catch (err) {
      console.log(`  ⚠ 交叉比对：隧道内 DNS 解析失败（${err?.message || err}），以 CSV 为准`);
    }
  }
  console.log();

  /* ② 隧道内解析 API 主机名（这一步同时证明隧道内 DNS 可用） */
  console.log(`② 隧道内 DNS 解析 API 主机名 ${API_HOST}`);
  const apiRecords = await resolveViaTunnel(API_HOST, 'A');
  const apiIp = apiRecords.find(r => r.type === 'A')?.data;
  if (!apiIp) {
    console.log(`  应答: ${JSON.stringify(apiRecords)}`);
    return finish(false, `${API_HOST} 在隧道内解析不出 A 记录`);
  }
  console.log(`  → ${API_HOST} = ${apiIp}  (${ms()})\n`);

  /* ③ 隧道内 HTTPS 查询出口 IP（用隧道内解析出的 IP，避免再走边缘 DNS） */
  console.log(`③ 隧道内 HTTPS 访问 https://${API_HOST}/ip  （连 ${apiIp}:443）`);
  const res = await httpsViaTunnel(apiIp, API_HOST, '/ip');
  const exitIp = res.body.toString('utf8').trim();
  console.log(`  HTTP ${res.status}  出口 IP = ${exitIp}  (${ms()})\n`);
  if (res.status !== 200 || !IPV4_RE.test(exitIp)) {
    console.log(res.head.split('\r\n').slice(0, 8).join('\n'));
    return finish(false, `隧道内 HTTPS 未拿到合法 IP（status=${res.status} body=${JSON.stringify(exitIp)}）`);
  }

  /* 对照组 */
  const localIp = await directIp();
  console.log(`④ 对照：本机直连出口 IP = ${localIp}\n`);

  /* ⑤ 断言：硬性只有「没回落直连」，与 CSV 的 IP 关系仅作参考 */
  const relation = relationToNode(exitIp, expectedIp);
  console.log('⑤ 断言');
  pad('  隧道出口 IP', exitIp);
  pad('  本机直连 IP', localIp);
  pad('  参考 节点 IP（CSV）', `${expectedIp}   [${expectedFrom}]`);
  pad('  参考 出口 vs 节点', relation.label);
  console.log();

  if (localIp === exitIp) {
    return finish(false, `出口 IP 与本机直连 IP 相同（${exitIp}），疑似回落成了直连`);
  }
  return finish(
    true,
    `隧道出口 IP ${exitIp} ≠ 本机直连 IP ${localIp}，流量确实走了隧道` +
    `（参考：与 CSV 的 ${expectedIp} ${relation.label}）`,
  );
})().catch(err => finish(false, `${err?.message || err}`));
