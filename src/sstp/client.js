/**
 * SSTP 客户端：SSTP over TLS 建链 + PPP(LCP/PAP/IPCP) 协商 + SSTP 报文收发。
 * 只负责「隧道本身」，不关心隧道里跑什么（TCP 流由 ./tcp.js 处理）。
 */

import { connect } from 'cloudflare:sockets';

import { CONFIG, log } from '../config.js';
import { EMPTY, concat, decoder, encode, tryClose, u16 } from '../utils.js';

export const PPP_LCP = 0xc021;   // Link Control Protocol
export const PPP_PAP = 0xc023;   // Password Authentication Protocol
export const PPP_IPCP = 0x8021;  // IP Control Protocol
export const PPP_IPV4 = 0x0021;  // IPv4 数据报文

export function createSstpClient(username, password) {
  let socket = null;
  let reader = null;
  let writer = null;
  let host = '';
  let buffer = EMPTY;
  let pppId = 1;
  let readBuffer = new ArrayBuffer(16384);
  // 已被放弃（外部调用过 close）；connect 若在放弃后才完成，立刻关掉，避免 socket 泄漏
  let abandoned = false;

  const credit = password || CONFIG.sstpPass;
  const account = username || CONFIG.sstpUser;

  /** 精确读取 n 字节（带跨包拼接） */
  const readBytes = async n => {
    if (buffer.length >= n) {
      const out = buffer.subarray(0, n);
      buffer = buffer.subarray(n);
      return out;
    }
    const saved = buffer.length > 0 ? new Uint8Array(buffer) : null;
    const { value, done } = await reader.readAtLeast(n - buffer.length, new Uint8Array(readBuffer));
    if (done) throw new Error('sstp: eof');
    readBuffer = value.buffer;
    if (saved) {
      const merged = concat(saved, value);
      buffer = merged.subarray(n);
      return merged.subarray(0, n);
    }
    buffer = value.subarray(n);
    return value.subarray(0, n);
  };

  /** 读取一行 HTTP 头 */
  const readLine = async () => {
    for (;;) {
      const index = buffer.indexOf(10);
      if (index >= 0) {
        const line = decoder.decode(buffer.subarray(0, index));
        buffer = buffer.subarray(index + 1);
        return line.replace(/\r$/, '');
      }
      const saved = buffer.length > 0 ? new Uint8Array(buffer) : null;
      const { value, done } = await reader.readAtLeast(1, new Uint8Array(readBuffer));
      if (done) throw new Error('sstp: eof');
      readBuffer = value.buffer;
      buffer = saved ? concat(saved, value) : value;
    }
  };

  /**
   * 读取一个 SSTP 报文。
   * @param {number} ms 超时毫秒；**0 表示不超时**（隧道读循环用，避免超时后残留的
   *   pending read 破坏 buffer 连续性；隧道的空闲回收交给上层看门狗处理）
   */
  const readPacket = async (ms = 10000) => {
    if (ms <= 0) {
      const header = await readBytes(4);
      const length = u16(header, 2) & 0x0fff;
      return { ctrl: (header[1] & 1) === 1, body: length > 4 ? await readBytes(length - 4) : EMPTY };
    }
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('sstp: timeout')), ms); });
    try {
      const header = await Promise.race([readBytes(4), timeout]);
      clearTimeout(timer);
      const length = u16(header, 2) & 0x0fff;
      return { ctrl: (header[1] & 1) === 1, body: length > 4 ? await readBytes(length - 4) : EMPTY };
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  };

  /** SSTP 数据帧（承载 PPP） */
  const sstpData = frame => {
    const size = 6 + frame.length;
    const packet = new Uint8Array(size);
    packet.set([0x10, 0x00, ((size >> 8) & 0x0f) | 0x80, size & 0xff, 0xff, 0x03]);
    packet.set(frame, 6);
    return packet;
  };

  /** SSTP 控制帧 */
  const sstpControl = (messageType, attributes = []) => {
    const total = attributes.reduce((sum, attr) => sum + 4 + attr.data.length, 0);
    const packet = new Uint8Array(8 + total);
    const view = new DataView(packet.buffer);
    packet[0] = 0x10;
    packet[1] = 0x01;
    view.setUint16(2, (8 + total) | 0x8000);
    view.setUint16(4, messageType);
    view.setUint16(6, attributes.length);
    attributes.reduce((offset, attr) => {
      packet[offset + 1] = attr.id;
      view.setUint16(offset + 2, 4 + attr.data.length);
      packet.set(attr.data, offset + 4);
      return offset + 4 + attr.data.length;
    }, 8);
    return packet;
  };

  /** PPP 报文（协议 / code / id / 选项） */
  const pppFrame = (protocol, code, id, options = []) => {
    const total = options.reduce((sum, opt) => sum + 2 + opt.data.length, 0);
    const frame = new Uint8Array(6 + total);
    const view = new DataView(frame.buffer);
    view.setUint16(0, protocol);
    frame[2] = code;
    frame[3] = id;
    view.setUint16(4, 4 + total);
    options.reduce((offset, opt) => {
      frame[offset] = opt.type;
      frame[offset + 1] = 2 + opt.data.length;
      frame.set(opt.data, offset + 2);
      return offset + 2 + opt.data.length;
    }, 6);
    return frame;
  };

  /** PAP Authenticate-Request */
  const papFrame = id => {
    const user = encode(account);
    const pass = encode(credit);
    const tail = 6 + user.length + pass.length;
    const frame = new Uint8Array(2 + tail);
    const view = new DataView(frame.buffer);
    view.setUint16(0, PPP_PAP);
    frame[2] = 1;
    frame[3] = id;
    view.setUint16(4, tail);
    frame[6] = user.length;
    frame.set(user, 7);
    frame[7 + user.length] = pass.length;
    frame.set(pass, 8 + user.length);
    return frame;
  };

  const parsePPP = data => {
    const offset = data.length >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
    if (data.length - offset < 4) return null;
    const protocol = u16(data, offset);
    if (protocol === PPP_IPV4) return { protocol, ip: data.subarray(offset + 2) };
    return data.length - offset >= 6
      ? { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), raw: data.subarray(offset) }
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

  const connectSstp = async (hostname, port) => {
    socket = connect({ hostname, port }, { secureTransport: 'on' });
    await socket.opened;
    // 建链超时后 connect 仍可能姗姗来迟，此时必须自己关掉，否则 socket 泄漏
    if (abandoned) { tryClose(socket); throw new Error('sstp: abandoned'); }
    reader = socket.readable.getReader({ mode: 'byob' });
    writer = socket.writable.getWriter();
    host = hostname;
  };

  const establish = async () => {
    const request = encode(
      `SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `Content-Length: 18446744073709551615\r\n` +
      `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`,
    );
    const protocolId = new Uint8Array(2);
    new DataView(protocolId.buffer).setUint16(0, 1);
    const mru = new Uint8Array(2);
    new DataView(mru.buffer).setUint16(0, 1500);

    await writer.write(concat(
      request,
      sstpControl(0x0001, [{ id: 1, data: protocolId }]),
      sstpData(pppFrame(PPP_LCP, 1, pppId++, [{ type: 1, data: mru }])),
    ));

    const status = await readLine();
    while ((await readLine()) !== '');
    if (!status.includes('200')) throw new Error(`sstp: http ${status}`);

    let sstpAcked = false;
    let lcpOpened = false;
    let authenticated = false;
    let finished = false;
    let myIp = null;

    for (let round = 0; round < 25 && !finished; round++) {
      const packet = await readPacket();
      if (packet.ctrl) {
        if (!sstpAcked && packet.body.length >= 2 && u16(packet.body, 0) === 2) sstpAcked = true;
        continue;
      }
      const ppp = parsePPP(packet.body);
      if (!ppp) continue;

      if (ppp.protocol === PPP_LCP) {
        if (ppp.code === 1) {
          // Configure-Request → Configure-Ack（顺带在 LCP 打开后发 PAP）
          const ack = new Uint8Array(ppp.raw);
          ack[2] = 2;
          await writer.write(
            lcpOpened && !authenticated
              ? concat(sstpData(ack), sstpData(papFrame(pppId++)))
              : sstpData(ack),
          );
          if (lcpOpened) authenticated = true;
        } else if (ppp.code === 2) {
          lcpOpened = true;
          if (!authenticated) { await writer.write(sstpData(papFrame(pppId++))); authenticated = true; }
        }
      } else if (ppp.protocol === PPP_PAP && ppp.code === 2) {
        // PAP 认证成功 → 请求 IPCP 分配地址
        await writer.write(sstpData(pppFrame(PPP_IPCP, 1, pppId++, [{ type: 3, data: new Uint8Array(4) }])));
      } else if (ppp.protocol === PPP_IPCP) {
        if (ppp.code === 1) {
          const ack = new Uint8Array(ppp.raw);
          ack[2] = 2;
          await writer.write(sstpData(ack));
        } else if (ppp.code === 3) {
          const option = parseOptions(ppp.payload).find(opt => opt.type === 3);
          if (option) {
            myIp = [...option.data].join('.');
            await writer.write(sstpData(pppFrame(PPP_IPCP, 1, pppId++, [{ type: 3, data: option.data }])));
          }
        } else if (ppp.code === 2) {
          const option = parseOptions(ppp.payload).find(opt => opt.type === 3);
          if (option) { myIp = [...option.data].join('.'); finished = true; }
        }
      }
    }
    if (!myIp) throw new Error('sstp: no ip from ipcp');
    log('sstp established', host, 'ip=', myIp);
    return myIp;
  };

  return {
    connect: connectSstp,
    establish,
    readPacket,
    parsePPP,
    get buffer() { return buffer; },
    get writer() { return writer; },
    close: () => { abandoned = true; [reader, writer, socket].forEach(tryClose); },
  };
}
