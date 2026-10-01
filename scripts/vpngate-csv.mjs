/**
 * vpngate.csv 读取：`Hostname` → 节点信息。
 *
 * 为什么要读 CSV 而不是查 DNS：
 *   - VPN Gate 的 **API**（`api/iphone/`）里 `HostName` 只有短名（`public-vpn-68`），不带域名，无法解析；
 *   - **CSV** 里 `Hostname` 是完整域名（`public-vpn-68.opengw.net`），且**同一行就带着 IP**。
 * 所以「这个节点应该是哪个 IP」这个问题，CSV 是权威答案，不需要 DNS。
 *
 * CSV 列（表头固定，值内不含引号/逗号）：
 *   Country,Hostname,IP,Speed_Mbps,TCP_Port
 *   Japan,public-vpn-68.opengw.net,219.100.37.17,459.85,443
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** 按优先级探测 vpngate.csv：本仓库内 → 同级 vpngate 仓库（本项目常见布局） */
export const CSV_CANDIDATES = [
  join(ROOT, 'vpngate.csv'),
  join(ROOT, 'data', 'vpngate.csv'),
  join(ROOT, '..', 'vpngate', 'vpngate.csv'),
];

/** 找到第一个存在的 CSV 路径，找不到返回 null */
export function defaultCsvPath() {
  return CSV_CANDIDATES.find(p => existsSync(p)) || null;
}

/**
 * 解析 CSV → Map<hostname, { country, ip, port, speed }>。
 * 找不到文件 / 表头不对时抛错（调用方决定是否降级）。
 */
export function loadVpngateCsv(file) {
  const text = readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
  const lines = text.split(/\r?\n/).filter(line => line.trim());
  if (!lines.length) throw new Error(`${file} 是空文件`);

  const header = lines[0].split(',').map(s => s.trim().toLowerCase());
  const col = name => header.indexOf(name);
  const cHost = col('hostname');
  const cIp = col('ip');
  if (cHost < 0 || cIp < 0) {
    throw new Error(`${file} 表头不符合预期（需要 Hostname / IP 两列）：${lines[0]}`);
  }
  const cCountry = col('country');
  const cPort = col('tcp_port');
  const cSpeed = col('speed_mbps');

  const map = new Map();
  for (const line of lines.slice(1)) {
    const cells = line.split(',');
    const hostname = cells[cHost]?.trim();
    const ip = cells[cIp]?.trim();
    if (!hostname || !ip) continue;
    map.set(hostname.toLowerCase(), {
      hostname,
      ip,
      port: Number(cells[cPort] || 443) || 443,
      country: cCountry >= 0 ? cells[cCountry]?.trim() : '',
      speed: cSpeed >= 0 ? Number(cells[cSpeed]) : 0,
    });
  }
  return map;
}

/** 查一个主机名（大小写不敏感）。未命中返回 null。 */
export function lookupNode(map, hostname) {
  if (!map || !hostname) return null;
  return map.get(String(hostname).trim().toLowerCase()) || null;
}

/**
 * 隧道出口 IP 与「CSV 里该节点的 IP」的关系。
 *
 * 为什么不能直接断言两者相等：**VPN Gate 节点的接入地址 ≠ 出网地址**。实测（2026-10）：
 *   public-vpn-68.opengw.net  接入 219.100.37.17  → 出口 219.100.37.234
 *   public-vpn-100.opengw.net 接入 219.100.37.57  → 出口 219.100.37.236
 * 两者同属 ASN 36599（SoftEther Telecommunication Research Institute），即确实是同一个
 * VPN Gate 出口池，只是节点做了 NAT。所以「同网段」才是可断言的，相等只是更强的巧合。
 *
 * @returns {{level:'exact'|'subnet24'|'subnet16'|'foreign'|'unknown', label:string}}
 */
export function relationToNode(exitIp, nodeIp) {
  if (!exitIp || !nodeIp) return { level: 'unknown', label: '无法比对' };
  if (exitIp === nodeIp) return { level: 'exact', label: '完全一致' };

  const a = exitIp.split('.').map(Number);
  const b = nodeIp.split('.').map(Number);
  if (a.length === 4 && b.length === 4 && a.every(Number.isInteger) && b.every(Number.isInteger)) {
    if (a[0] === b[0] && a[1] === b[1] && a[2] === b[2]) {
      return { level: 'subnet24', label: `同 /24（${a[0]}.${a[1]}.${a[2]}.0/24，节点 NAT 出口）` };
    }
    if (a[0] === b[0] && a[1] === b[1]) {
      return { level: 'subnet16', label: `同 /16（${a[0]}.${a[1]}.0.0/16，节点 NAT 出口）` };
    }
  }
  return { level: 'foreign', label: '不在节点所在网段' };
}
