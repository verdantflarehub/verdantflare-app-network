export type Observation = {
 source: string; url: string; at: string; status: string; ip: string;
 country?: string; country_code?: string; region?: string; city?: string; asn?: string; isp?: string; organization?: string;
 asn_type?: string; company?: string; company_type?: string;
 datacenter: boolean | null; proxy: boolean | null; vpn: boolean | null; tor: boolean | null; mobile: boolean | null;
 risk_score: number | null; error?: string;
};
export type Probe = {
 status: string; target: string; started_at: string; finished_at: string;
 attempts: number; successes: number; success_rate: number; mean_latency_ms: number; jitter_ms: number;
 exit_ip: string; exit_changed: boolean; location_conflict: boolean; blacklist_status: string;
 samples: { at: string; latency_ms: number; ip?: string; error?: string }[]; observations: Observation[];
};
export type ProxyItem = {
 proxy_id: string; name: string; protocol: string; host: string; port: number; status: 'active' | 'pending' | 'off';
 tag: string; note: string; expires_at: string | null; auth_configured: boolean; assigned_apps: string[];
 revision: number; probe: Probe | null; testing: boolean; updated_at: string;
};
export type ProxyInput = {
 name: string; protocol: string; host: string; port: number; tag: string; note: string; expires_at: string;
 username?: string; password?: string; clear_auth?: boolean; status?: string; revision?: number;
};
const geoSources = ['IPinfo', 'ipapi.is (anonymous)', 'IPQuery'];
const countryNames = new Intl.DisplayNames(['en'], { type: 'region' });
const countryCodes = new Map<string, string>();
for (const locale of ['en', 'zh-CN']) {
 const names = new Intl.DisplayNames([locale], { type: 'region' });
 for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
  const code = String.fromCharCode(a, b), name = names.of(code);
  if (name && name !== code) countryCodes.set(name.toLowerCase(), code);
 }
}
export function countryCode(o?: Observation): string {
 const value = (o?.country_code || o?.country || '').trim();
 const code = /^[a-z]{2}$/i.test(value) ? value.toUpperCase() : countryCodes.get(value.toLowerCase()) || '';
 return code && countryNames.of(code) !== code ? code : '';
}
export function locationText(o?: Observation): string {
 if (!o) return '位置未获取';
 return [o.country || o.country_code || '国家未获取', o.region || '州／省未获取', o.city || '城市未获取'].join(' / ');
}
export function exitProfile(probe?: Probe | null) {
 const observations = (probe?.observations || []).filter(o => !!probe?.exit_ip && o.status === 'available' && o.ip === probe.exit_ip);
 const geo = geoSources.map(source => observations.find(o => o.source === source && (o.country_code || o.country || o.region || o.city))).find(Boolean);
 const typed = observations.filter(o => o.datacenter === true || o.mobile === true);
 const datacenter = typed.some(o => o.datacenter === true), mobile = typed.some(o => o.mobile === true);
 // A negative hosting flag, low risk or ISP name does not establish residential service.
 const conflict = (datacenter && observations.some(o => o.datacenter === false)) || (mobile && observations.some(o => o.mobile === false)) || (datacenter && mobile);
 let type = conflict ? '类型未判定' : datacenter ? '机房IP' : '类型未判定';
 let typeEvidence = typed.map(o => `${o.source}: ${[o.datacenter === true ? 'datacenter=true' : '', o.mobile === true ? 'mobile=true' : ''].filter(Boolean).join(', ')}`).join('；');
 typeEvidence = conflict ? `类型标记冲突；${typeEvidence}` : typeEvidence || '当前来源没有明确的 IP 类型证据';
 const primary = observations.find(o => o.source === 'IPinfo (type)');
 if (primary) {
  const a = (primary.asn_type || '').trim().toLowerCase(), c = (primary.company_type || '').trim().toLowerCase();
  const hosting = primary.datacenter === true || a === 'hosting' || c === 'hosting';
  const count = Number(a === 'isp') + Number(c === 'isp');
  type = '类型未判定';
  if (a && c && count) {
   if (!hosting && primary.mobile !== true) type = count === 2 ? '住宅IP' : '单ISP';
  } else if (hosting && primary.mobile !== true) type = '机房IP';

  typeEvidence = `IPinfo: ASN type=${a || '未知'}；Company type=${c || '未知'}；hosting=${primary.datacenter ?? '未知'}`;
  // Secondary negative flags never erase an explicit primary-source classification.
  if (observations.some(o => o !== primary && o.datacenter != null && primary.datacenter != null && o.datacenter !== primary.datacenter)) typeEvidence += '；其他来源的机房标记存在差异，见原始观测';
 }
 if (probe?.exit_changed) { type = '类型未判定'; typeEvidence = '采样期间出口发生变化，请重新检测'; }
 return { geo, countryCode: countryCode(geo), location: locationText(geo), type, typeEvidence, fallback: !!geo && geo.source !== geoSources[0] };
}
const errors: Record<string, string> = {
 UNAUTHENTICATED: '登录已失效，请重新登录', PERMISSION_DENIED: '当前账号没有代理管理权限',
 INVALID_ARGUMENT: '请检查名称、协议、主机、端口、有效期及认证字段',
 PROXY_CONFLICT: '记录已被修改、端点重复或仍有引用，请刷新后核对', PROBE_BUSY: '已有探测运行或达到并发上限，请稍后重试',
 PROXY_DISABLED_OR_EXPIRED: '代理已停用或过期，请先编辑并启用', EGRESS_NOT_CONFIGURED: '代理管理服务尚未配置',
 SERVICE_UNAVAILABLE: '代理管理服务暂不可用，请重试', NOT_FOUND: '代理不存在或接口尚未就绪',
 endpoint_not_allowed: '此端点不在允许的代理范围内', connection_failed: '代理连接失败', proxy_auth_failed: '代理认证失败',
 timeout: '连接超时', tls_verification_failed: 'TLS 证书验证失败', invalid_exit_ip: '探测目标未返回有效公网 IP',
 ip_mismatch: '信息源返回的 IP 与出口不一致', invalid_response: '信息源返回格式异常', http_status_429: '信息源查询额度或频率受限',
 exit_changed: '查询期间出口发生变化，请重新检测',
};
export function message(code: string) { return errors[code] || (code.startsWith('http_status_') ? `目标返回 HTTP ${code.slice(12)}` : '请求失败，请稍后重试'); }
export async function api<T>(path = '', method = 'GET', body?: unknown): Promise<T> {
 const { requestApp } = await import('./host');
 const response = await requestApp({ path: `/proxies${path}`, method, body });
 if (response.status === 204) return undefined as T;
 const data = response.data as { code?: string };
 if (response.status < 200 || response.status >= 300) throw new Error(message(data?.code || 'SERVICE_UNAVAILABLE'));
 return data as T;
}
export function payload(r: ProxyItem): ProxyInput { return { name: r.name, protocol: r.protocol, host: r.host, port: r.port, tag: r.tag, note: r.note, expires_at: r.expires_at || '', revision: r.revision }; }
export function exportData(rows: ProxyItem[]) {
 return { format: 'verdantflare-proxies-v1', exported_at: new Date().toISOString(), credentials_included: false,
 items: rows.map(r => { const { revision: _revision, ...data } = payload(r); return { ...data, status: r.status === 'off' ? 'off' : 'pending', authentication_required: r.auth_configured }; }) };
}
export type ImportRow = { line: number; input?: ProxyInput; state: 'valid' | 'duplicate' | 'invalid' | 'imported' | 'failed'; detail: string };
export function parseImport(text: string, existing: ProxyItem[]): ImportRow[] {
 let values: unknown[]; const trimmed = text.trim(); if (!trimmed) return [];
 if (trimmed.startsWith('{')) { const data = JSON.parse(trimmed); if (data.format !== 'verdantflare-proxies-v1' || !Array.isArray(data.items)) throw new Error('不支持的 JSON 文件格式'); values = data.items; }
 else values = trimmed.split(/\r?\n/).filter(Boolean);
 if (values.length > 50) throw new Error('每次最多导入 50 条代理'); const seen = new Set<string>();
 return values.map((value, index) => {
  try {
   let input: ProxyInput; let missingAuth = false;
   if (typeof value === 'string') { const u = new URL(value.trim()); if (u.search || u.hash || (u.pathname && u.pathname !== '/')) throw Error(); const port = Number(u.port || (u.protocol === 'http:' ? 80 : u.protocol === 'https:' ? 443 : 0)); input = { name: `导入-${u.hostname}:${port}`, protocol: u.protocol.slice(0, -1), host: u.hostname.replace(/^\[|\]$/g, ''), port, username: decodeURIComponent(u.username), password: decodeURIComponent(u.password), tag: 'imported', note: '', expires_at: '' }; }
   else { if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error(); const v = value as Record<string, unknown>; if (['name', 'protocol', 'host'].some(k => typeof v[k] !== 'string') || typeof v.port !== 'number' || ['tag', 'note', 'expires_at'].some(k => v[k] !== undefined && typeof v[k] !== 'string') || (v.status !== undefined && !['off', 'pending'].includes(v.status as string))) throw Error(); input = { name: v.name as string, protocol: v.protocol as string, host: v.host as string, port: v.port, tag: (v.tag as string) || '', note: (v.note as string) || '', expires_at: (v.expires_at as string) || '', status: v.status === 'off' ? 'off' : 'pending' }; missingAuth = v.authentication_required === true; }
   input.host = input.host.trim().toLowerCase().replace(/\.$/, ''); input.protocol = input.protocol.toLowerCase();
   if (!['http', 'https', 'socks5', 'socks5h'].includes(input.protocol) || !Number.isInteger(input.port) || input.port < 1 || input.port > 65535 || !input.name || input.name.length > 120 || !input.host || /[\s/@?#]/.test(input.host)) throw Error();
   const key = `${input.protocol}|${input.host}|${input.port}|${input.username || ''}`;
   const duplicate = seen.has(key) || existing.some(r => r.protocol === input.protocol && r.host === input.host && r.port === input.port && !r.auth_configured && !input.username); seen.add(key);
   return { line: index + 1, input, state: duplicate ? 'duplicate' : 'valid', detail: duplicate ? '重复，跳过' : missingAuth ? '可导入；原认证未导出，导入后需重新填写' : '可导入' };
  } catch { return { line: index + 1, state: 'invalid', detail: '格式或字段无效；不会写入' }; }
 });
}
