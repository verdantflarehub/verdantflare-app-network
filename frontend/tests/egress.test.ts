import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseImport, exportData, exitProfile, countryCode, type ProxyItem, type Observation, type Probe } from '../src/egress.ts';

test('URL preview distinguishes valid, duplicate and invalid input without echoing secrets', () => {
 const rows = parseImport('socks5://alice:p%40ss@proxy.example:1080\nsocks5://alice:p%40ss@proxy.example:1080\nftp://proxy.example:1080\nsocks5://proxy.example:65536\nsocks5://proxy.example:1080/path', []);
 assert.deepEqual(rows.map(r => r.state), ['valid', 'duplicate', 'invalid', 'invalid', 'invalid']);
 assert.equal(rows[0].input?.password, 'p@ss');
 assert.ok(!rows[0].input?.name.includes('alice')); assert.ok(!rows[0].detail.includes('p@ss'));
});
test('export is explicit field allowlist and round trips metadata without credentials', () => {
 const row = { proxy_id: 'test', name: 'kept', protocol: 'socks5', host: 'proxy.example', port: 7891, status: 'active', tag: 'qa', note: 'note', expires_at: null, auth_configured: true, assigned_apps: [], revision: 3, probe: null, testing: false, updated_at: '', username: 'secret-user', password: 'secret-password' } as ProxyItem;
 const exported = exportData([row]); const text = JSON.stringify(exported);
 assert.ok(!text.includes('secret-user')); assert.ok(!text.includes('secret-password')); assert.ok(!text.includes('revision'));
 const back = parseImport(text, []); assert.equal(back[0].state, 'valid'); assert.equal(back[0].input?.note, 'note'); assert.equal(back[0].input?.status, 'pending'); assert.match(back[0].detail, /需重新填写/);
});
test('imports are bounded and unknown formats rejected', () => {
 assert.throws(() => parseImport(Array(51).fill('socks5://proxy.example:1080').join('\n'), []), /50/);
 assert.throws(() => parseImport('{"items":[]}', [])); assert.deepEqual(parseImport('', []), []);
});

test('HTTP default ports survive URL normalization; SOCKS requires an explicit port', () => {
 const rows = parseImport('http://proxy.example:80\nhttps://proxy.example:443\nsocks5://proxy.example', []);
 assert.deepEqual(rows.map(r => r.state), ['valid', 'valid', 'invalid']);
 assert.equal(rows[0].input?.port, 80); assert.equal(rows[1].input?.port, 443);
});

test('JSON preview rejects coerced fields and invalid management states', () => {
 const base = { name: 'proxy', protocol: 'socks5', host: 'proxy.example', port: 1080 };
 const rows = parseImport(JSON.stringify({ format: 'verdantflare-proxies-v1', items: [base, {...base, name: {}}, {...base, port: '1080'}, {...base, status: 'active'}] }), []);
 assert.deepEqual(rows.map(r => r.state), ['valid', 'invalid', 'invalid', 'invalid']);
});

const observation = (source: string, fields: Partial<Observation> = {}): Observation => ({ source, url: '', at: '', status: 'available', ip: '8.8.8.8', datacenter: null, mobile: null, proxy: null, vpn: null, tor: null, risk_score: null, ...fields });
const probe = (observations: Observation[]) => ({ exit_ip: '8.8.8.8', observations }) as Probe;
test('IPinfo two-field classification distinguishes single, dual, hosting and incomplete evidence', () => {
 const classify = (fields: Partial<Observation>) => exitProfile(probe([observation('IPinfo (type)', fields)]));
 assert.equal(classify({asn_type:'isp', company_type:'business', datacenter:false}).type, '单ISP');
 assert.equal(classify({asn_type:'ISP', company_type:' isp '}).type, '住宅IP');
 assert.equal(classify({asn_type:'business', company_type:'isp'}).type, '单ISP');
 assert.equal(classify({asn_type:'hosting', company_type:'hosting', datacenter:true}).type, '机房IP');
 assert.equal(classify({asn_type:'isp'}).type, '类型未判定');
 assert.equal(classify({company_type:'isp', datacenter:false}).type, '类型未判定');
 assert.equal(classify({asn_type:'business', company_type:'business', datacenter:false}).type, '类型未判定');
 assert.equal(classify({asn_type:'isp', company_type:'hosting'}).type, '类型未判定');
 assert.equal(classify({asn_type:'isp', company_type:'isp', datacenter:true}).type, '类型未判定');
 assert.equal(classify({asn_type:'isp', company_type:'isp', mobile:true}).type, '类型未判定');
 for (const invalid of [{status:'unavailable'}, {ip:'1.1.1.1'}]) assert.equal(classify({asn_type:'isp',company_type:'isp',...invalid}).type,'类型未判定');
 const records = [observation('IPQuery',{datacenter:false}),observation('IPinfo (type)',{asn_type:'hosting',company_type:'hosting',datacenter:true})];
 assert.equal(exitProfile(probe(records)).type,'机房IP');
 assert.match(exitProfile(probe(records)).typeEvidence,/存在差异/);
 assert.equal(exitProfile({...probe(records),exit_changed:true}).type,'类型未判定');
});
test('geography uses fixed source priority, a matching exit IP and one complete source record', () => {
 const q = observation('IPQuery', { country: 'United States', region: 'Texas', city: 'Dallas' });
 const info = observation('IPinfo', { country_code: 'US', region: 'California', city: 'San Francisco' });
 const g = observation('ipapi.is (anonymous)', { country: 'United States', region: 'Washington', city: 'Seattle' });
 for (const list of [[q, info, g], [g, info, q]]) {
  const result = exitProfile(probe(list));
  assert.equal(result.location, 'US / California / San Francisco');
  assert.equal(result.countryCode, 'US');
  assert.equal(result.fallback, false);
 }
 const result = exitProfile(probe([q, {...info, status: 'unavailable', error: 'http_status_429'}, g]));
 assert.equal(result.geo?.source, g.source); assert.equal(result.fallback, true);
 assert.equal(exitProfile(probe([q, {...info, ip: '1.1.1.1'}])).geo?.source, q.source);
 assert.equal(exitProfile(probe([q, {...info, city: ''}])).location, 'US / California / 城市未获取');
 assert.equal(exitProfile(probe([q])).location, 'United States / Texas / Dallas');
});
test('negative data center flags, ISP ownership and zero risk never imply a residential IP', () => {
 const q = observation('IPQuery', { datacenter: false, risk_score: 0, organization: 'Residential ISP' });
 assert.equal(exitProfile(probe([q])).type, '类型未判定');
 assert.equal(exitProfile(probe([{...q, datacenter: true}])).type, '机房IP');
 assert.equal(exitProfile(probe([{...q, mobile: true}])).type, '类型未判定');
 assert.equal(exitProfile(probe([{...q, datacenter: true, mobile: true}])).type, '类型未判定');
 assert.equal(exitProfile(probe([q, observation('IPinfo', { datacenter: true })])).type, '类型未判定');
 assert.equal(exitProfile(probe([{...q, datacenter: true, status: 'unavailable'}])).type, '类型未判定');
 assert.equal(exitProfile(probe([{...q, datacenter: true, ip: '1.1.1.1'}])).type, '类型未判定');
});
test('old observations derive a country flag without inventing missing geography', () => {
 assert.equal(countryCode(observation('IPQuery', {country: 'United States'})), 'US');
 assert.equal(countryCode(observation('IPinfo', {country_code: '../../US'})), '');
 assert.equal(countryCode(observation('IPQuery', {country: 'Unknown'})), '');
 assert.equal(exitProfile(null).location, '位置未获取');
 assert.equal(exitProfile(null).type, '类型未判定');
});
