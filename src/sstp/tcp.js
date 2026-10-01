/**
 * PPP 之上的最小 IPv4/TCP 栈（一条流 = 一个目标 TCP 连接）。
 *
 * 相比旧版的关键改进：
 *   - 状态机独立成模块，可被多条流共享同一条 SSTP 隧道（见 ./pool.js）；
 *   - 校验 seq 连续性：乱序 / 重复段不再被当成新数据写进上层（旧版会损坏数据）；
 *   - 窗口通告随接收缓冲变化，缓冲满时通告 0 窗口做背压（旧版固定 65535）；
 *   - 简化重传：未确认段超时重发，避免隧道内单次丢包就卡死；
 *   - 半关闭：收到 FIN 只关读方向并 ACK，写方向等上层 close() 再发 FIN。
 */

import { CONFIG } from '../config.js';
import { EMPTY, checksum, concat, randomU16, randomU32, seqLE, seqLT, setU16, setU32, toU8, u16, u32 } from '../utils.js';

const FLAG_FIN = 0x01;
const FLAG_SYN = 0x02;
const FLAG_RST = 0x04;
const FLAG_PSH = 0x08;
const FLAG_ACK = 0x10;

/** 解析 PPP 内的 IPv4 报文 → TCP 头字段与数据区间（payload 用 IP 总长度裁剪，去掉 padding） */
export function parseIpTcp(ip) {
  if (ip.length < 20 || ip[9] !== 6) return null;
  const ihl = (ip[0] & 0x0f) * 4;
  if (ip.length < ihl + 20) return null;
  const total = u16(ip, 2) || ip.length;
  const offset = ihl + ((ip[ihl + 12] >> 4) & 0x0f) * 4;
  const end = Math.min(ip.length, Math.max(offset, total));
  return {
    srcPort: u16(ip, ihl),
    dstPort: u16(ip, ihl + 2),
    seq: u32(ip, ihl + 4),
    ackNum: u32(ip, ihl + 8),
    flags: ip[ihl + 13],
    offset,
    end,
  };
}

/**
 * @param {object} tunnel 隧道句柄（见 ./pool.js）：提供 allocPort / write / sourceBytes / alive
 * @param {string} targetIp 目标 IPv4
 * @param {number} targetPort
 */
export function createTcpStream(tunnel, targetIp, targetPort) {
  const sourcePort = tunnel.allocPort();
  const sourceBytes = tunnel.sourceBytes;
  const targetBytes = new Uint8Array(targetIp.split('.').map(Number));

  let seq = randomU32();
  let ack = 0;
  let state = 'syn';                 // syn → established → closed
  let finSent = false;
  let finReceived = false;
  let destroyed = false;

  // --- 发送侧 ---
  const ipHeader = new Uint8Array(20);
  ipHeader.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); // v4/IHL5, DF, TTL64, TCP
  ipHeader.set(sourceBytes, 12);
  ipHeader.set(targetBytes, 16);

  // TCP 伪首部（12 + 报文长度，缓冲区 1432 ⇒ MSS 上限 1400）
  const pseudo = new Uint8Array(1432);
  pseudo.set(sourceBytes);
  pseudo.set(targetBytes, 4);
  pseudo[9] = 6;

  // --- 接收侧（背压缓冲） ---
  const chunks = [];
  let buffered = 0;
  let controller = null;
  let readableDone = false;
  let lastWindow = CONFIG.sstpWindowBytes;

  // --- 重传 ---
  let unacked = [];

  const windowSize = () => {
    const room = CONFIG.sstpBufferBytes - buffered;
    return room <= 0 ? 0 : Math.min(CONFIG.sstpWindowBytes, room);
  };

  /**
   * @param {number} flags
   * @param {Uint8Array} [data]
   * @param {number} [seqValue] 序号覆盖（重传时必须用该段的原始起始 seq）
   */
  const frame = (flags, data = EMPTY, seqValue = seq) => {
    const payloadLength = data.length;
    const tcpLength = 20 + payloadLength;
    const ipLength = 20 + tcpLength;
    const size = 8 + ipLength;
    const packet = new Uint8Array(size);

    // SSTP 头 + PPP(0x0021) + IPv4 头
    packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03, 0x00, 0x21]);
    packet.set(ipHeader, 8);
    setU16(packet, 10, ipLength);
    setU16(packet, 12, randomU16());               // identification
    setU16(packet, 18, checksum(packet, 8, 20));   // IPv4 校验和（字段初值为 0）

    // TCP 头
    setU16(packet, 28, sourcePort);
    setU16(packet, 30, targetPort);
    setU32(packet, 32, seqValue);
    setU32(packet, 36, ack);
    packet[40] = 0x50;                             // data offset = 5 * 4
    packet[41] = flags;
    setU16(packet, 42, windowSize());
    setU16(packet, 44, 0);
    if (payloadLength) packet.set(data, 48);

    pseudo[10] = tcpLength >> 8;
    pseudo[11] = tcpLength & 0xff;
    pseudo.set(packet.subarray(28, 28 + tcpLength), 12);
    setU16(packet, 44, checksum(pseudo, 0, 12 + tcpLength));
    return packet;
  };

  const sendAck = () => {
    if (destroyed || !tunnel.alive) return;
    lastWindow = windowSize();
    tunnel.write(frame(FLAG_ACK));
  };

  const sendFin = () => {
    if (finSent || destroyed) return;
    finSent = true;
    tunnel.write(frame(FLAG_FIN | FLAG_ACK));
    seq = (seq + 1) >>> 0;
  };

  const closeReadable = () => {
    if (readableDone) return;
    readableDone = true;
    try { controller?.close(); } catch {}
  };

  const drain = () => {
    if (!controller) return;
    while (chunks.length && !readableDone) {
      const chunk = chunks.shift();
      buffered -= chunk.byteLength;
      controller.enqueue(chunk);
    }
    // 之前通告过 0 窗口、现在有空间了 → 主动发窗口更新
    if (lastWindow === 0 && windowSize() > 0 && !destroyed && tunnel.alive) sendAck();
    if (finReceived && !chunks.length && !readableDone) closeReadable();
  };

  const push = data => {
    if (!data.byteLength) return;
    chunks.push(data);
    buffered += data.byteLength;
    drain();
  };

  /**
   * 记录一个未确认段。存「起始 seq + flags + 载荷」而不是整帧：
   * 重传时需要用**当前**的 ack 与窗口重新构造，重发旧帧会把过期的
   * window（可能是 0）再发一遍，导致双方互等死锁。
   */
  const recordUnacked = (startSeq, endSeq, flags, data) => {
    if (!CONFIG.sstpRetransmit) return;
    unacked.push({ start: startSeq, end: endSeq, flags, data, time: Date.now(), retries: 0 });
    if (unacked.length > 64) unacked.shift();
  };

  /**
   * 清掉已被确认的段。
   * 只在「确认号落在我们已发送范围内」时才生效：异常确认号（0、远超 snd_nxt 等）
   * 与序号回绕叠加时会把未确认段误判为已确认，导致丢包不重传。
   */
  const clearUnacked = ackNum => {
    if (!unacked.length) return;
    if (!seqLE(ackNum, seq)) return;
    unacked = unacked.filter(item => seqLT(ackNum, item.end));
  };

  /** 由隧道读循环 / 看门狗定期调用 */
  const checkRetransmit = () => {
    if (!CONFIG.sstpRetransmit || !unacked.length || destroyed || !tunnel.alive) return;
    const now = Date.now();
    for (const item of unacked) {
      if (now - item.time < CONFIG.sstpRtoMs) continue;
      if (item.retries >= CONFIG.sstpMaxRetries) { destroy(new Error('sstp: retransmit exceeded')); return; }
      item.retries += 1;
      item.time = now;
      tunnel.write(frame(item.flags, item.data, item.start));
    }
  };

  // --- 握手 ---
  let settle = null;
  const handshakePromise = new Promise((resolve, reject) => { settle = { resolve, reject }; });

  /** @param {number} [timeoutMs] 拨号方给的超时；0 表示用 CONFIG.sstpHandshakeMs */
  const handshake = async (timeoutMs = 0) => {
    const syn = frame(FLAG_SYN);
    recordUnacked(seq, (seq + 1) >>> 0, FLAG_SYN, EMPTY);
    await tunnel.write(syn);
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('sstp: tcp handshake timeout')), timeoutMs || CONFIG.sstpHandshakeMs);
    });
    try { return await Promise.race([handshakePromise, timeout]); }
    finally { clearTimeout(timer); }
  };

  // --- 收包 ---
  const deliver = (info, ip) => {
    if (destroyed) return;

    if (state === 'syn') {
      if (info.flags & FLAG_RST) { destroy(new Error('sstp: rst')); return; }
      if ((info.flags & (FLAG_SYN | FLAG_ACK)) !== (FLAG_SYN | FLAG_ACK)) return;
      ack = (info.seq + 1) >>> 0;
      seq = (seq + 1) >>> 0;               // SYN 消耗一个序号
      state = 'established';
      clearUnacked(info.ackNum);           // 用 SYN-ACK 的确认号清 unacked，不是用对端 seq
      sendAck();
      settle?.resolve(true);
      return;
    }
    if (state !== 'established') return;

    if (info.flags & FLAG_RST) { destroy(new Error('sstp: rst')); return; }
    if (info.flags & FLAG_ACK) clearUnacked(info.ackNum);

    let needAck = false;
    const length = info.end - info.offset;

    if (length > 0 && !finReceived) {
      if (info.seq === ack) {
        // 只有序号连续的段才交给上层；乱序 / 重传段一律丢弃（对端会重传）
        ack = (ack + length) >>> 0;
        push(ip.subarray(info.offset, info.end));
      }
      needAck = true;
    }
    if (info.flags & FLAG_FIN && !finReceived) {
      finReceived = true;
      ack = (ack + 1) >>> 0;               // FIN 也占一个序号
      needAck = true;
      closeReadable();
    }
    if (needAck) sendAck();
  };

  const destroy = err => {
    if (destroyed) return;
    destroyed = true;
    state = 'closed';
    chunks.length = 0;
    buffered = 0;
    unacked = [];
    closeReadable();
    try { settle?.reject(err || new Error('sstp: stream closed')); } catch {}
    tunnel.removeStream(sourcePort);
  };

  /** ReadableStream 的 queuing strategy：按字节计，配合窗口做背压 */
  const strategy = { highWaterMark: CONFIG.sstpBufferBytes, size: chunk => chunk.byteLength };

  const readable = new ReadableStream({
    start(stream) { controller = stream; },
    pull() { drain(); },
    cancel() { destroy(new Error('sstp: readable cancelled')); },
  }, strategy);

  const writable = new WritableStream({
    async write(chunk) {
      if (destroyed || !tunnel.alive) throw new Error('sstp: stream closed');
      const data = toU8(chunk);
      if (!data.byteLength) return;
      // 统一按 MSS 分片：每段单独记录 unacked（重传时才能只重发一段），
      // 但一次性 concat 写出，减少 write 次数
      const frames = [];
      for (let offset = 0; offset < data.length; offset += CONFIG.mss) {
        const segment = data.subarray(offset, Math.min(offset + CONFIG.mss, data.length));
        const start = seq;
        frames.push(frame(FLAG_PSH | FLAG_ACK, segment));
        seq = (seq + segment.length) >>> 0;
        recordUnacked(start, seq, FLAG_PSH | FLAG_ACK, segment);
      }
      await tunnel.write(frames.length === 1 ? frames[0] : concat(...frames));
      checkRetransmit();
    },
    close() { sendFin(); },
    abort() { destroy(new Error('sstp: writable aborted')); },
  });

  return {
    sourcePort,
    readable,
    writable,
    handshake,
    deliver,
    checkRetransmit,
    destroy,
    get state() { return state; },
  };
}
