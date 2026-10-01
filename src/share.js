/**
 * 节点信息页（GET /sub、/uuid）：输出 ws / xhttp 链接与推荐的 xhttp extra。
 * 带访问控制（CONFIG.subAuth），默认要求携带正确 UUID，避免 Worker 变开放代理。
 */

import { CONFIG, XHTTP_EXTRA } from './config.js';

/** 定长比较，避免通过响应时间侧信道逐字符猜 UUID */
const safeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

/**
 * UUID 可以从三处提供（任一命中即可）：
 *   ?uuid=<uuid>        → https://host/sub?uuid=xxx
 *   /<uuid>/sub         → https://host/<uuid>/sub
 *   X-Uuid: <uuid>      → 请求头
 */
const uuidAuthorized = (request, url, expected) => {
  const segments = url.pathname.split('/').filter(Boolean);
  const candidates = [
    url.searchParams.get('uuid'),
    request.headers.get('x-uuid'),
    segments.length >= 2 ? segments[0] : '',
  ];
  for (const candidate of candidates) {
    if (candidate && safeEqual(candidate.trim(), expected)) return true;
  }
  return false;
};

/**
 * 处理 /sub、/uuid；不是这两个路径则返回 null（交给入口继续分流）。
 */
export function handleShareRequest(request, env, url) {
  // 接受两种形态：/sub、/uuid，以及带 UUID 前缀的 /<uuid>/sub、/<uuid>/uuid
  const segments = url.pathname.split('/').filter(Boolean);
  const last = segments[segments.length - 1];
  if (segments.length > 2 || (last !== 'sub' && last !== 'uuid')) return null;

  const text = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (CONFIG.subAuth === 'off') return new Response('cf-vpngate: not found', { status: 404, headers: text });

  const uuid = String(env?.UUID || globalThis.UUID || '').trim() || CONFIG.uuid;
  if (CONFIG.subAuth === 'uuid' && !uuidAuthorized(request, url, uuid)) {
    return new Response('cf-vpngate: not found', { status: 404, headers: text });
  }
  return new Response(buildShareText(request, env, url, uuid), { headers: text });
}

export function buildShareText(request, env, url, uuid) {
  const host = request.headers.get('Host') || url.host;
  const backend = (url.searchParams.get('sstp') || url.searchParams.get('proxy') || '').trim() || CONFIG.proxyip;
  const path = encodeURIComponent(`/fdip=${backend}?ed=2560`);
  const common = `encryption=none&security=tls&host=${host}&sni=${host}&fp=chrome&allowInsecure=0`;

  const ws = `vless://${uuid}@${host}:443?path=${path}&${common}&type=ws#cf-vpngate-ws`;
  const xhttp = `vless://${uuid}@${host}:443?mode=stream-one&path=${path}&${common}&alpn=h2&type=xhttp#cf-vpngate-xhttp`;

  // uuid 只回显一次（用于 ?uuid= 的便捷复制），不再额外明文提示
  const hint = CONFIG.subAuth === 'uuid'
    ? `# 本页需携带 UUID 访问：${url.origin}/${uuid}/sub`
    : '# 提示：建议把 CONFIG.subAuth 设为 uuid，避免节点页被公开扫描';

  return [
    '# cf-vpngate',
    '',
    `# 当前落地：${backend}`,
    `# 修改落地：${url.origin}/sub?sstp=sstp://host:443&uuid=${uuid}  或  ${url.origin}/sub?proxy=1.2.3.4:443&uuid=${uuid}`,
    hint,
    '',
    '## vless-ws',
    ws,
    '',
    '## vless-xhttp（mode 固定 stream-one；extra 必须开启 noGRPCHeader）',
    xhttp,
    '',
    `## xhttp extra（xPaddingHeader / xPaddingKey 与 Worker 端 CONFIG 一致：${CONFIG.xhttpPaddingHeader} / ${CONFIG.xhttpPaddingKey}）`,
    XHTTP_EXTRA,
  ].join('\n');
}
