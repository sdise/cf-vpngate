/**
 * Worker 入口：请求分流（WebSocket / XHTTP / 节点页 / 静默 204）。
 */

import { CONFIG, log } from './config.js';
import { getUuidBytes } from './utils.js';
import { parsePathProxy, parseFlag } from './vless.js';
import { handleWebSocket } from './ws.js';
import { handleXhttp } from './xhttp.js';
import { handleShareRequest } from './share.js';

/** 落地是否需要强制走（CONFIG.allowClientGlobal=false 时忽略请求方传入值） */
const resolveGlobalMode = (request, url) => {
  const fromClient = request.headers.get('global') || url.searchParams.get('global') || '';
  return CONFIG.allowClientGlobal ? fromClient : CONFIG.globalMode;
};



export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();

      const isWebSocket = upgrade === 'websocket';
      // XHTTP：与 edgetunnel 一致，POST 一律按 XHTTP 处理；
      // 若客户端发了 gRPC 帧（noGRPCHeader=false），首包解析会失败并返回 400
      const isXhttp = !isWebSocket && request.method === 'POST';

      if (!isWebSocket && !isXhttp) {
        // XHTTP 的 packet-up / stream-up 会把下行做成 GET（带 x_session / x_seq），
        // 本实现只支持 stream-one：这里明确回 400，别让客户端只看到静默 204 无从定位
        if (url.searchParams.has('x_session') || url.searchParams.has('x_seq')) {
          log('XHTTP 仅支持 mode=stream-one（packet-up/stream-up 需要跨请求会话表）', url.pathname);
          return new Response(
            'cf-vpngate: XHTTP only supports mode=stream-one；请把客户端 mode 设为 stream-one（packet-up/stream-up 不支持）',
            { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
          );
        }
        // 非代理流量：/sub、/uuid 返回节点信息（受 CONFIG.subAuth 控制），其余静默 204
        const share = handleShareRequest(request, env, url);
        if (share) return share;
        return new Response(null, { status: 204 });
      }

      const uuid = String(env?.UUID || globalThis.UUID || '').trim() || CONFIG.uuid;
      const uuidBytes = getUuidBytes(uuid);
      const globalMode = resolveGlobalMode(request, url);
      // 落地：path 里的优先，否则用 CONFIG.proxyip
      const proxy = parsePathProxy(url) || CONFIG.proxyip;

      // 竞速拨号：由 ?race=1 / X-Race: 1 直接控制，不写就是不竞速
      const options = { race: parseFlag(url, request, 'race') };

      return isWebSocket
        ? await handleWebSocket(request, uuidBytes, proxy, globalMode, options)
        : await handleXhttp(request, uuidBytes, uuid, proxy, globalMode, url, options);
    } catch (err) {
      log('fetch error', err?.message || err);
      return new Response(null, { status: 500 });
    }
  },
};
