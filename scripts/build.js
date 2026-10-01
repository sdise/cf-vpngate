/**
 * 把 src/ 下的模块按依赖顺序合并成单文件 worker.js（零依赖，不需要 esbuild）。
 *
 *   node scripts/build.js            # 生成 worker.js
 *   node scripts/build.js --check    # 只比对，不写文件（CI / 人工核对用）
 *
 * 说明：
 *   - 相对路径 import 会被去掉（所有模块最终在同一个作用域里，因此模块间不能重名）；
 *   - 外部 import（如 cloudflare:sockets）会被去重后提升到文件顶部；
 *   - `export const/let/function/class/async` 去掉 export 前缀，`export default` 保留。
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');
const OUT = join(ROOT, 'worker.js');
/** Snippets 专用压缩产物（32KB 上限） */
const SNIPPET = join(ROOT, 'snippet.js');

/** 缓存目录（中间产物）：可用环境变量 CACHE_DIR 覆盖 */
const CACHE_DIR = process.env.CACHE_DIR || 'Z:\\Temp';

/** 合并顺序 = 依赖顺序（被依赖的在前） */
const ORDER = [
  'config.js',
  'utils.js',
  'padding.js',
  'net.js',
  'dns.js',
  'sstp/client.js',
  'sstp/tcp.js',
  'sstp/pool.js',
  'outbound.js',
  'vless.js',
  'queue.js',
  'ws.js',
  'xhttp.js',
  'share.js',
  'index.js',
];

const BANNER = `/**
 * cf-vpngate
 * -----------------------------------------------------------------------------
 * 入站（前端）：VLESS over WebSocket / VLESS over XHTTP（只支持 mode=stream-one）
 * 出站（后端）：SSTP（VPN Gate 公共节点） / ProxyIP（含 \`域名!txt\` 列表）
 *
 * 可直接作为 Cloudflare Worker 部署（需 \`wrangler.toml\`），
 * 也可整段粘贴到 Cloudflare Snippets / Dashboard 快速编辑器中使用。
 *
 * ⚠️ 本文件由 src/ 自动生成（node scripts/build.js），请勿直接编辑；
 *    修改请改 src/ 下对应模块后重新执行 \`npm run build\`。
 *
 * 设计要点：
 *   - 有冲突的实现细节以 jacobax/snippets 的 snippet.js 为准；
 *   - 入站只保留 VLESS（ws + xhttp），去掉 trojan / ss 入站与 ss2022 加解密；
 *   - 出站只保留 SSTP 与 ProxyIP 两种，去掉 socks5 / http(s) / turn(s) 等落地；
 *   - UDP 仅支持 53 端口（DNS），由 Worker 转成 TCP 上的 DNS 查询再回写。
 */
`;

/** import 语句（支持跨行写法） */
const IMPORT_RE = /(?:^|\n)[ \t]*import\s(?:[\s\S]*?from\s*)?['"]([^'"]+)['"];?[ \t]*(?=\n|$)/g;

/** 去掉相对导入，收集外部导入，去掉 export 前缀 */
function transform(name, source) {
  const external = [];
  const stripped = source.replace(IMPORT_RE, match => {
    const specifier = match.match(/['"]([^'"]+)['"]/)[1];
    if (!specifier.startsWith('.')) external.push(match.trim());
    return '\n';
  });
  const body = stripped
    .split('\n')
    .map(line => line.replace(/^export\s+(?=(?:const|let|var|function|class|async)\b)/, ''))
    .join('\n');

  return { external, body: `/* ------------------------------- src/${name} ------------------------------- */\n${body.trim()}\n` };
}

function build() {
  const external = [];
  const chunks = [];

  for (const name of ORDER) {
    const file = join(SRC, name);
    if (!existsSync(file)) throw new Error(`缺少模块：src/${name}`);
    const result = transform(name, readFileSync(file, 'utf8'));
    external.push(...result.external);
    chunks.push(result.body);
  }

  const imports = [...new Set(external)];
  return `${BANNER}\n${imports.join('\n')}\n\n${chunks.join('\n')}`;
}

const output = build();

/**
 * 剔除独立的 `log(...)` 语句（Snippets 没有 `wrangler tail`，这些调试日志纯属体积负担）。
 * 只删「整行且括号配平」的调用，避免误伤跨行调用。
 */
function stripLogs(source) {
  return source
    .split('\n')
    .map(line => {
      const match = line.match(/^([ \t]*)log\(.*\);[ \t]*$/);
      if (!match) return line;
      const body = line.trim();
      let depth = 0;
      for (const ch of body) {
        if (ch === '(') depth += 1;
        else if (ch === ')') depth -= 1;
      }
      return depth === 0 ? '' : line;
    })
    .join('\n');
}

/**
 * Snippets 有 32KB 体积上限，可读版（88KB）塞不进去。
 * 用 esbuild 压一份 snippet.js：去注释 + 压缩标识符 + 合并行。
 * cloudflare:sockets 是运行时内置模块，必须保留为外部 import。
 */
async function minify() {
  const slim = process.env.SNIPPET_SLIM !== '0';
  const esbuild = await import('esbuild');
  const result = await esbuild.transform(slim ? stripLogs(output) : output, {
    loader: 'js',
    format: 'esm',
    target: 'es2022',
    minify: true,
    legalComments: 'none',
    // 默认 charset=ascii 会把中文转成 \uXXXX（每字 6 字节）；Snippets 源码本就是 UTF-8，
    // 保留原字符只占 3 字节，中文文案越多省得越多。
    charset: 'utf8',
    // transform 不解析模块，`import ... from 'cloudflare:sockets'` 会原样保留
  });
  let code = result.code.trim();
  if (!code.startsWith('import')) {
    // transform 可能把 import 挪到末尾，兜底：确保外部 import 在最前
    const imports = code.match(/^import[^;]+;$/gm) || [];
    if (imports.length) {
      code = `${imports.join('\n')}\n${code.replace(/^import[^;]+;$/gm, '').trim()}`;
    }
  }
  const banner =
    '/* cf-vpngate — Cloudflare Snippets 版（由 src/ 自动生成，勿手改；可读版见 worker.js） */\n';
  return banner + code + '\n';
}

const limit = Number(process.env.SNIPPET_LIMIT || 32768);

/** 只比对不写文件：worker.js 与 snippet.js 都要与 src/ 一致才算通过 */
if (process.argv.includes('--check')) {
  const stale = [];
  const workerCurrent = existsSync(OUT) ? readFileSync(OUT, 'utf8') : '';
  if (workerCurrent !== output) stale.push('worker.js');

  let snippet;
  try {
    snippet = await minify();
  } catch {
    console.error('⚠ 未安装 esbuild，跳过 snippet.js 校验');
  }
  if (snippet !== undefined) {
    const snippetCurrent = existsSync(SNIPPET) ? readFileSync(SNIPPET, 'utf8') : '';
    if (snippetCurrent !== snippet) stale.push('snippet.js');
  }

  if (stale.length) {
    console.error(`${stale.join(' / ')} 与 src/ 不一致，请执行 npm run build`);
    process.exit(1);
  }
  console.log('worker.js / snippet.js 均已是最新');
  process.exit(0);
}

try {
  const minified = await minify();
  const bytes = Buffer.byteLength(minified);
  writeFileSync(SNIPPET, minified);
  const pct = ((bytes / limit) * 100).toFixed(1);
  console.log(`已生成 ${SNIPPET}（${bytes} 字节 / ${limit} 上限 = ${pct}%）`);
  if (bytes > limit) {
    console.error(`⚠ 超出 Snippets ${limit} 字节上限 ${bytes - limit} 字节，需继续精简`);
    process.exitCode = 1;
  }
  // 压缩产物连语法都不合法的话，粘到 Snippets 也是白搭，构建时直接拦下
  try {
    execFileSync(process.execPath, ['--check', SNIPPET], { stdio: 'pipe' });
  } catch (err) {
    console.error('⚠ snippet.js 语法校验未通过：', String(err.stderr || err.message).trim());
    process.exitCode = 1;
  }
} catch (err) {
  console.error('压缩失败（未安装 esbuild？）：', err.message);
  console.error('可执行 npm i 后重试；worker.js 已正常生成。');
}

// 中间产物先落到缓存目录，便于出问题时回看
try {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR, { recursive: true });
  writeFileSync(join(CACHE_DIR, 'cf-vpngate.worker.bundle.js'), output);
} catch { /* 缓存目录不可写时忽略，不影响构建 */ }

writeFileSync(OUT, output);
console.log(`已生成 ${OUT}（${output.split('\n').length} 行，来自 src/ 共 ${ORDER.length} 个模块）`);
