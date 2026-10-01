/**
 * 数据队列与下行发送：上行分片入队 / 出队合并，下行攒包 + 背压感知。
 */

import { CONFIG } from './config.js';
import { EMPTY, releaseLock } from './utils.js';
import { dnsOverTcp } from './dns.js';

/**
 * isolate 级的上行队列总预算。
 * 旧版只有「单连接 8MB」上限，并发一多就会被多连接叠加吃光内存；
 * 这里再加一层全局预算，超了就拒收（上层随即冲刷或断流）。
 */
let TOTAL_BYTES = 0;

/** 上行队列：按 CONFIG.upPack 切片入队，出队时尽量合并成一个大包 */
export function createQueue(maxSize) {
  let items = [];
  let head = 0;
  let bytes = 0;
  let waiter = null;
  let wake = null;
  let scratch = null;

  const isEmpty = () => head >= items.length;
  const compact = () => { if (head > 32 && head * 2 >= items.length) { items = items.slice(head); head = 0; } };
  const take = () => {
    if (isEmpty()) return null;
    const item = items[head];
    items[head++] = undefined;
    bytes -= item.byteLength;
    TOTAL_BYTES -= item.byteLength;
    compact();
    return item;
  };

  return {
    empty: isEmpty,
    get size() { return bytes; },
    get wait() { return waiter; },
    clear() {
      items = []; head = 0;
      TOTAL_BYTES -= bytes;
      bytes = 0;
      wake?.(); wake = waiter = null;
    },
    push(chunk) {
      const length = chunk?.byteLength || 0;
      if (!length) return false;
      if (bytes + length > CONFIG.maxQueueBytes) return false;          // 单连接上限
      if (TOTAL_BYTES + length > CONFIG.maxQueueTotalBytes) return false; // 全局预算
      items.push(chunk);
      bytes += length;
      TOTAL_BYTES += length;
      if (bytes >= CONFIG.queueWakeBytes) waiter ||= new Promise(resolve => { wake = resolve; }); // 反压信号
      return true;
    },
    pack(first) {
      let item = first || take();
      if (!item || isEmpty()) return item || null;
      let total = item.byteLength;
      let index = head;
      while (index < items.length) {
        const next = items[index].byteLength;
        if (total + next > maxSize) break;
        total += next;
        index++;
      }
      if (index === head) return item;
      const out = (scratch ||= new Uint8Array(maxSize));
      out.set(item);
      let offset = item.byteLength;
      while (head < index) {
        const chunk = items[head];
        items[head++] = undefined;
        bytes -= chunk.byteLength;
        TOTAL_BYTES -= chunk.byteLength;
        out.set(chunk, offset);
        offset += chunk.byteLength;
      }
      compact();
      return out.slice(0, total);
    },
    drain() { if (bytes <= CONFIG.queueDrainBytes) { wake?.(); wake = waiter = null; } },
  };
}

/** 下行发送器：攒包 + 背压感知 + 自适应冲刷，减少 WebSocket 小包 */
export function createDownstreamSender(ws) {
  const maxPack = CONFIG.dnPack;
  const tail = CONFIG.dnTail;
  const queue = createQueue(maxPack);
  let timer = 0;
  // 吞吐估算：交互流量（低速率）立即冲刷，大流量才攒包等 dnMs
  let rate = 0;
  let lastFlushAt = Date.now();
  let bytesSinceFlush = 0;

  const emit = chunk => { if (ws.readyState === WebSocket.OPEN) ws.send(chunk); };
  const noteFlush = () => {
    const now = Date.now();
    const elapsed = Math.max(1, now - lastFlushAt);
    rate = rate ? rate * 0.7 + ((bytesSinceFlush * 1000) / elapsed) * 0.3 : (bytesSinceFlush * 1000) / elapsed;
    lastFlushAt = now;
    bytesSinceFlush = 0;
  };
  const flush = () => {
    if (timer) { clearTimeout(timer); timer = 0; }
    noteFlush();
    for (;;) {
      const chunk = queue.pack();
      if (!chunk) break;
      emit(chunk);
    }
  };

  return {
    send(data) {
      let offset = 0;
      const length = data?.byteLength || 0;
      if (!length) return;
      bytesSinceFlush += length;
      while (offset < length) {
        const room = maxPack - queue.size;
        const size = Math.min(room, length - offset);
        if (!size) { flush(); continue; }
        const slice = offset || size !== length ? data.subarray(offset, offset + size) : data;
        if (!queue.push(slice)) { flush(); if (!queue.push(slice)) break; }
        offset += size;
        if (queue.size >= maxPack || maxPack - queue.size < tail || !ws.bufferedAmount) flush();
        else {
          const delay = CONFIG.dnAdaptive && rate < CONFIG.dnAdaptiveBps ? 0 : CONFIG.dnMs;
          timer ||= setTimeout(flush, queue.size >= maxPack >> 1 ? delay : 0);
        }
      }
    },
    fastSend: emit,
    reap: flush,
  };
}

/** 落地 readable → WebSocket（byob 读 + 背压等待） */
export async function pipeToWebSocket(readable, ws) {
  let reader;
  let byob = false;
  try { reader = readable.getReader({ mode: 'byob' }); byob = true; } catch { reader = readable.getReader(); }

  const sender = createDownstreamSender(ws);
  const waitBackpressure = async () => {
    while (ws.readyState === WebSocket.OPEN && ws.bufferedAmount > CONFIG.wsBackpressureBytes) {
      const delay = ws.bufferedAmount > CONFIG.wsBackpressureBytes * 2 ? 8 : 2;
      await (globalThis.scheduler?.wait?.(delay) ?? new Promise(resolve => setTimeout(resolve, delay)));
      if (ws.bufferedAmount <= CONFIG.wsBackpressureReleaseBytes) break;
    }
  };
  const finish = () => {
    releaseLock(reader);
    try { ws.close(1000, ''); } catch {}
  };

  // BYOB 的 buffer 在 read 后会被转移/分离，只在 byob 分支需要重建；非 byob 分支用不到
  let buffer = byob ? new ArrayBuffer(CONFIG.chunk) : EMPTY.buffer;
  try {
    for (;;) {
      if (ws.readyState !== WebSocket.OPEN) break;
      await waitBackpressure();
      const { done, value } = byob ? await reader.read(new Uint8Array(buffer)) : await reader.read();
      if (done) break;
      if (value?.byteLength) {
        if (value.byteLength >= CONFIG.chunk >> 1) {
          sender.reap();          // 大块：先把攒着的发掉，再整块直发
          sender.fastSend(value);
        } else {
          sender.send(value);
        }
        if (byob) buffer = new ArrayBuffer(CONFIG.chunk);
      }
    }
    sender.reap();
  } catch {
    /* 连接已断开 */
  } finally {
    try { sender.reap(); } catch {}
    finish();
  }
}

export async function sendDnsResponse(query, ws, host, port) {
  try {
    const answer = await dnsOverTcp(query, host, port);
    if (answer?.byteLength && ws.readyState === WebSocket.OPEN) ws.send(answer);
  } catch { /* 忽略 */ }
}
