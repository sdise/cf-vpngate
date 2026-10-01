/**
 * 入站：VLESS over WebSocket。
 *
 * 流程：Early Data / message 入队 → 攒齐 VLESS 头 → 建出站连接 → 双向转发；
 * UDP 只放行 53 端口（转 TCP DNS）。
 */

import { CONFIG, log } from './config.js';
import { concat, releaseLock, toU8, tryClose } from './utils.js';
import { dialOutbound } from './outbound.js';
import { detectInbound, extractEarlyData, parseVlessHeader } from './vless.js';
import { createQueue, pipeToWebSocket, sendDnsResponse } from './queue.js';

export async function handleWebSocket(request, uuidBytes, proxy, globalMode, options = {}) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.binaryType = 'arraybuffer';
  server.accept({ allowHalfOpen: true });

  const remote = { socket: null, writer: null };
  const queue = createQueue(CONFIG.upPack);

  let closed = false;
  let running = false;
  let handshakeDone = false;
  let prefixChecked = false;
  let dnsMode = false;
  let dnsTarget = null;
  let earlyBuffer = null;
  let timer = setTimeout(() => { if (!handshakeDone) close(1000); }, CONFIG.wsHandshakeTimeout);

  /** 数据入队（按 upPack 切片），队列满返回 0 */
  const feed = data => {
    if (!data?.byteLength) return 1;
    for (let offset = 0, total = data.byteLength; offset < total;) {
      const size = Math.min(CONFIG.upPack, total - offset);
      if (!queue.push(offset || size !== total ? data.subarray(offset, offset + size) : data)) return 0;
      offset += size;
    }
    return 1;
  };

  function close(code = 1000) {
    if (typeof code !== 'number') code = 1000;
    if (closed) return;
    closed = true;
    queue.clear();
    if (timer) { clearTimeout(timer); timer = 0; }
    try { remote.writer?.close(); } catch {}
    releaseLock(remote.writer);
    tryClose(remote.socket);
    try { server.close(code, ''); } catch {}
  }

  /** 消费队列：握手 → 建连 → 转发 */
  async function pump() {
    if (running || closed) return;
    running = true;
    try {
      while (!closed) {
        if (dnsMode) {
          // UDP(53)：后续每个包都是一次独立 DNS 查询
          const query = queue.pack();
          if (!query) break;
          await sendDnsResponse(query, server, dnsTarget.host, dnsTarget.port);
          queue.drain();
          continue;
        }
        if (!remote.socket) {
          const head = queue.pack();
          if (!head) break;
          const session = parseVlessHeader(head, uuidBytes);
          if (!session) throw new Error('bad vless header');

          if (session.responsePrefix.byteLength) server.send(session.responsePrefix);

          if (session.udp) {
            if (session.port !== 53) throw new Error('udp only for dns');
            dnsMode = true;
            dnsTarget = { host: session.host, port: session.port };
            await sendDnsResponse(session.payload, server, dnsTarget.host, dnsTarget.port);
            queue.drain();
            continue;
          }

          const socket = await dialOutbound(session.host, session.port, proxy, globalMode, options);
          if (!socket) throw new Error('dial failed');
          if (closed) { tryClose(socket); break; }

          remote.socket = socket;
          remote.writer = socket.writable.getWriter();
          pipeToWebSocket(socket.readable, server).catch(() => close(1011));

          const payload = queue.pack(session.payload);
          if (payload?.byteLength) await remote.writer.write(payload);
          queue.drain();
          continue;
        }

        const chunk = queue.pack();
        if (!chunk) break;
        await remote.writer.write(chunk);
        queue.drain();
      }
    } catch (err) {
      log('ws pump error', err?.message || err);
      close(1011);
    } finally {
      running = false;
      if (!queue.empty() && !closed) pump();
    }
  }

  const onData = data => {
    if (closed) return;
    let chunk = toU8(data);
    if (!chunk.byteLength) return;

    if (!handshakeDone) {
      earlyBuffer = earlyBuffer?.byteLength ? concat(earlyBuffer, chunk) : chunk;
      // prefixChecked：16 字节 UUID 已经比对通过后就不再重复比对（多帧 Early Data 时省 CPU）
      const state = detectInbound(earlyBuffer, uuidBytes, prefixChecked);
      if (!state) {
        if (earlyBuffer.byteLength >= 17) prefixChecked = true;
        return; // 头还没收全
      }
      if (state === 3) { close(1011); return; }
      chunk = earlyBuffer;
      earlyBuffer = null;
      handshakeDone = true;
      if (timer) { clearTimeout(timer); timer = 0; }
    }
    if (feed(chunk)) pump(); else close(1011);
  };

  const earlyData = extractEarlyData(request);
  if (earlyData) onData(earlyData);

  server.addEventListener('message', async event => {
    onData(event.data);
    const wait = queue.wait;
    if (wait) await wait; // 队列过大时让出，形成反压
  });
  server.addEventListener('close', close);
  server.addEventListener('error', close);

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { 'Sec-WebSocket-Extensions': '' },
  });
}
