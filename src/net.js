/**
 * 最底层的 TCP 连接封装。
 * 半开直连（保留半关闭能力，便于落地侧 FIN 之后的残余数据回传）。
 */

import { connect } from 'cloudflare:sockets';

import { tryClose, withTimeout } from './utils.js';

/**
 * @param {string} host
 * @param {number} port
 * @param {number} [timeoutMs] 建连超时；超时会关闭 socket 并 reject
 */
export async function tcpConnect(host, port, timeoutMs = 0) {
  const hostname = String(host).replace(/^\[|\]$/g, '');
  const socket = connect({ hostname, port }, { allowHalfOpen: true });
  try {
    if (timeoutMs > 0) await withTimeout(socket.opened, timeoutMs, `connect timeout: ${hostname}:${port}`);
    else await socket.opened;
    return socket;
  } catch (err) {
    tryClose(socket);
    throw err;
  }
}
