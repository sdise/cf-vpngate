/**
 * 入站：VLESS over XHTTP（只支持 mode=stream-one）。
 *
 * 一次 POST 承载一个完整会话：首包必须自带 VLESS 头（客户端需开 noGRPCHeader）。
 * 先建连再返回响应，失败时给干净的 400 / 502，而不是一条被中断的流。
 */

import { CONFIG, XHTTP_HEADERS, log } from './config.js';
import { EMPTY, concat, releaseLock, toU8, tryClose } from './utils.js';
import { applyPaddingHeader, extractXhttpPadding, paddingAcceptable } from './padding.js';
import { dnsOverTcp } from './dns.js';
import { dialOutbound } from './outbound.js';
import { matchUuid, parseVlessHeader } from './vless.js';

const byobReader = stream => {
  try { return { reader: stream.getReader({ mode: 'byob' }), byob: true }; }
  catch { return { reader: stream.getReader(), byob: false }; }
};

async function readSome(source, size) {
  if (source.byob) {
    const buffer = new ArrayBuffer(size);
    const { done, value } = await source.reader.read(new Uint8Array(buffer));
    return { done, value: value ? toU8(value) : EMPTY };
  }
  const { done, value } = await source.reader.read();
  return { done, value: value ? toU8(value) : EMPTY };
}

const xhttpError = (status, message) =>
  new Response(`cf-vpngate: ${message}`, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

/**
 * 攒齐 VLESS 首包。
 * XHTTP 只实现 stream-one：一次 POST 承载一个完整会话，首包必须自带 VLESS 头，
 * 即客户端需要开启 noGRPCHeader（这也是首包解析失败时最常见的原因）。
 *
 * 用一块预分配的 hsMax 缓冲累积（旧版每片 concat 一次，多片时是 O(n²) 拷贝）；
 * 命中后把 payload 拷出来，因为缓冲会被后续读取复用。
 */
async function readVlessHeader(source, uuidBytes) {
  const buf = new Uint8Array(CONFIG.hsMax);
  let filled = 0;
  let prefixChecked = false;

  for (;;) {
    if (!prefixChecked && filled >= 17) {
      if (!matchUuid(buf, uuidBytes)) {
        throw new Error('bad vless header；XHTTP 请设置 noGRPCHeader=true（或 Content-Type: application/octet-stream）');
      }
      prefixChecked = true;
    }
    if (filled >= 24) {
      const session = parseVlessHeader(buf.subarray(0, filled), uuidBytes);
      if (session) return { ...session, payload: new Uint8Array(session.payload) };
    }
    if (filled >= CONFIG.hsMax) throw new Error('header too large');
    const size = Math.min(filled === 0 ? CONFIG.xhInit : CONFIG.xhNext, CONFIG.hsMax - filled);
    if (size <= 0) throw new Error('bad header');
    const { done, value } = await readSome(source, size);
    if (done) throw new Error('eof before vless header');
    if (value.byteLength) {
      const take = value.subarray(0, Math.min(value.byteLength, CONFIG.hsMax - filled));
      buf.set(take, filled);
      filled += take.byteLength;
    }
  }
}

/** XHTTP 的 UDP(53)：按 2 字节长度前缀分包，逐批走 TCP DNS 后写进响应流 */
function createDnsResponder(emit, dnsHost, dnsPort) {
  let buffered = EMPTY;
  let chain = Promise.resolve();
  let stopped = false;

  const handle = async data => {
    if (stopped || !data?.byteLength) return;
    const chunk = toU8(data);
    buffered = buffered.byteLength ? concat(buffered, chunk) : chunk;

    const queries = [];
    let offset = 0;
    while (buffered.byteLength - offset >= 2) {
      const end = offset + 2 + ((buffered[offset] << 8) | buffered[offset + 1]);
      if (buffered.byteLength < end) break;
      queries.push(buffered.slice(offset, end));
      offset = end;
    }
    buffered = offset < buffered.byteLength ? buffered.slice(offset) : EMPTY;
    if (!queries.length) return;

    // 同一批并发查询（旧版逐条 await，延迟会叠加），再按原顺序回写
    const answers = await Promise.all(queries.map(query => dnsOverTcp(query, dnsHost, dnsPort)));
    for (let i = 0; i < answers.length; i++) {
      if (!answers[i]) throw new Error('dns query failed');
      emit(answers[i]);
    }
  };

  return {
    write(data) {
      chain = chain.then(() => handle(data)).catch(err => { stopped = true; throw err; });
      return chain;
    },
    async finish() {
      await chain;
      stopped = true;
      if (buffered.byteLength) throw new Error('dns: incomplete packet');
    },
  };
}

/** UDP(53) 的响应：把 DNS 应答直接写进响应体 */
function xhttpUdpResponse(session, source, headers) {
  const stream = new ReadableStream({
    async start(controller) {
      const responder = createDnsResponder(byte => controller.enqueue(byte), session.host, session.port);
      try {
        if (session.payload.byteLength) await responder.write(session.payload);
        for (;;) {
          const { done, value } = await readSome(source, CONFIG.chunk);
          if (done) break;
          if (value.byteLength) await responder.write(value);
        }
        await responder.finish();
      } catch (err) {
        log('xhttp udp error', err?.message || err);
      } finally {
        releaseLock(source.reader);
        try { controller.close(); } catch {}
      }
    },
    cancel() {
      try { source.reader.cancel(); } catch {}
      releaseLock(source.reader);
    },
  });
  return new Response(stream, { status: 200, headers });
}

/** 响应已返回后开始搬运：VLESS 响应头 → 上行 / 下行双向 pipe */
async function bridgeXhttp(session, source, request, remote, transform, output) {
  const upstreamAbort = new AbortController();
  const downstreamAbort = new AbortController();
  let outputReleased = false;
  let finished = false;
  let sides = 2;

  const cleanup = reason => {
    if (finished) return;
    finished = true;
    try { upstreamAbort.abort(reason); } catch {}
    try { downstreamAbort.abort(reason); } catch {}
    releaseLock(source.reader);
    tryClose(remote);
    if (!outputReleased) {
      outputReleased = true;
      try { output.abort(reason).catch(() => {}); } catch {}
      releaseLock(output);
    }
  };

  // 两个方向都结束才收摊（旧版下行一结束就 cleanup，会提前切断上行半关闭方向）
  const sideDone = () => { if (--sides <= 0) cleanup(); };

  try {
    if (session.responsePrefix.byteLength) await output.write(session.responsePrefix);
    outputReleased = true;
    releaseLock(output);

    const downstream = remote.readable
      .pipeTo(transform.writable, { signal: downstreamAbort.signal })
      .then(() => { try { upstreamAbort.abort(); } catch {} sideDone(); }, sideDone);

    if (session.payload.byteLength) {
      const writer = remote.writable.getWriter();
      try { await writer.write(session.payload); } finally { writer.releaseLock(); }
    }

    releaseLock(source.reader);
    request.body
      .pipeTo(remote.writable, { signal: upstreamAbort.signal })
      .then(sideDone, sideDone);
    downstream.catch(() => {});
  } catch (err) {
    cleanup(err);
  }
}

export async function handleXhttp(request, uuidBytes, uuid, proxy, globalMode, url, options = {}) {
  if (!request.body) return xhttpError(400, 'empty body');
  if (!paddingAcceptable(extractXhttpPadding(request, uuid, url))) return xhttpError(400, 'bad padding');

  const source = byobReader(request.body);
  const timer = setTimeout(() => { try { source.reader.cancel(); } catch {} }, CONFIG.xhttpHeaderTimeout);

  let session;
  try {
    session = await readVlessHeader(source, uuidBytes);
  } catch (err) {
    clearTimeout(timer);
    releaseLock(source.reader);
    log('xhttp header error', err?.message || err);
    return xhttpError(400, err?.message || 'bad request');
  }
  clearTimeout(timer);

  if (session.udp && session.port !== 53) {
    releaseLock(source.reader);
    return xhttpError(400, 'udp only supports port 53');
  }

  const headers = new Headers(XHTTP_HEADERS);
  applyPaddingHeader(headers);

  if (session.udp) return xhttpUdpResponse(session, source, headers);

  // 先建连再返回响应：失败时给出干净的 502，而不是一条被中断的流
  const remote = await dialOutbound(session.host, session.port, proxy, globalMode, options);
  if (!remote) {
    releaseLock(source.reader);
    log('xhttp dial failed', session.host, session.port);
    return xhttpError(502, `dial failed (${session.host}:${session.port})`);
  }

  const highWaterMark = { highWaterMark: CONFIG.wsBackpressureBytes };
  const transform =
    typeof IdentityTransformStream === 'function'
      ? new IdentityTransformStream(highWaterMark, highWaterMark)
      : new TransformStream({}, highWaterMark, highWaterMark);
  const output = transform.writable.getWriter();

  const response = new Response(transform.readable, { status: 200, headers });
  void bridgeXhttp(session, source, request, remote, transform, output);
  return response;
}
