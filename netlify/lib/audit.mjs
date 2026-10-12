// Fusion Media website check: audit engine shared by /api/scan (public, plain English) and
// /api/report (password protected, full technical detail).
// Passive only: public DNS (DNS-over-HTTPS), the site's public pages and its TLS certificate.
// No dependencies; runs on Node 18+ (Netlify Functions).
import tls from 'node:tls';

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36';
const BOT_UA = {
  GPTBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot',
  'OAI-SearchBot': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot',
  ClaudeBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
  PerplexityBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)',
  Googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  Bingbot: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
};
// robots.txt tokens. search = fetches pages for AI/search answers; training = model training only
const ROBOT_TOKENS = {
  search: ['Googlebot', 'Bingbot', 'OAI-SearchBot', 'ChatGPT-User', 'Claude-SearchBot', 'Claude-User', 'PerplexityBot',
    'Perplexity-User', 'Applebot', 'DuckAssistBot'],
  training: ['GPTBot', 'ClaudeBot', 'Google-Extended', 'Applebot-Extended', 'CCBot', 'meta-externalagent', 'Amazonbot'],
};
const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'default', 'k1', 's1', 's2', 'dkim', 'mail', 'zoho', 'fm1',
  'sig1', 'protonmail', 'hs1', 'mandrill', 'resend', 'k2', 'mxvault', 'cm', 'smtp'];

// ----------------------------------------------------------------------------- input + SSRF guard
export function normaliseDomain(input) {
  let d = String(input || '').trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '').split(/[/?#]/)[0].split('@').pop().replace(/:\d+$/, '').replace(/\.$/, '');
  if (d.startsWith('www.')) d = d.slice(4);
  if (!/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(d)) return null;
  return d;
}

function ipPrivate(ip) {
  if (ip.includes(':')) {
    const x = ip.toLowerCase();
    if (x === '::' || x === '::1' || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('fe8') || x.startsWith('fe9') ||
        x.startsWith('fea') || x.startsWith('feb') || x.startsWith('ff')) return true;
    const m = x.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return m ? ipPrivate(m[1]) : false;
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !(n >= 0 && n <= 255))) return true;
  const [a, b] = p;
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && p[2] === 0) ||
    (a === 198 && (b === 18 || b === 19));
}

const hostOk = new Map();
async function assertPublicHost(host) {
  if (hostOk.has(host)) return hostOk.get(host);
  let ok = false;
  if (normaliseDomain(host) || /^www\./.test(host)) {
    const [a, aaaa] = await Promise.all([dns(host, 'A'), dns(host, 'AAAA')]);
    const ips = [...a, ...aaaa].filter(x => /^[\d.]+$|:/.test(x));
    ok = ips.length > 0 && !ips.some(ipPrivate);
  }
  hostOk.set(host, ok);
  return ok;
}

// ----------------------------------------------------------------------------- DNS over HTTPS
const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const dnsCache = new Map();
export async function dns(name, type, full = false) {
  const key = name.toLowerCase().replace(/\.$/, '') + '|' + type;
  if (!dnsCache.has(key)) dnsCache.set(key, (async () => {
    for (const base of ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve']) {
      try {
        const r = await fetch(`${base}?name=${encodeURIComponent(key.split('|')[0])}&type=${type}`,
          { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(3000) });
        const j = await r.json();
        return { ad: !!j.AD, answers: (j.Answer || []).filter(x => x.type === TYPES[type]).map(x => x.data) };
      } catch { /* try next resolver */ }
    }
    return { ad: false, answers: [], error: true };
  })());
  const res = await dnsCache.get(key);
  return full ? res : res.answers;
}
const unq = d => { const p = [...d.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1]); return p.length ? p.join('') : d; };
export const txt = async n => (await dns(n, 'TXT')).map(unq);

// ----------------------------------------------------------------------------- HTTP
async function readCapped(res, cap) {
  if (!res.body) return { text: '', bytes: 0, truncated: false };
  const reader = res.body.getReader(); const chunks = []; let bytes = 0, truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.length;
    if (bytes > cap) { truncated = true; chunks.push(value.slice(0, Math.max(0, value.length - (bytes - cap)))); try { await reader.cancel(); } catch {} break; }
    chunks.push(value);
  }
  const buf = Buffer.concat(chunks.map(c => Buffer.from(c)));
  return { text: buf.toString('utf8'), bytes: truncated ? Math.max(bytes, cap) : bytes, truncated };
}

let DEADLINE = Infinity; // whole-audit time budget (functions time out at 10s)
export async function get(url, { ua = UA, follow = true, cap = 2_000_000, timeout = 4500 } = {}) {
  const t0 = Date.now(); const chain = [];
  const left = DEADLINE - t0;
  if (left < 500) return { ok: false, error: 'time budget', url, status: null, headers: {}, text: '', bytes: 0, chain, ms: 0 };
  timeout = Math.min(timeout, left - 250);
  try {
    for (let hop = 0; hop < 6; hop++) {
      const u = new URL(url);
      if (!['http:', 'https:'].includes(u.protocol) || !(await assertPublicHost(u.hostname))) {
        return { ok: false, error: 'blocked or unresolvable host', url, status: null, headers: {}, text: '', bytes: 0, chain, ms: Date.now() - t0 };
      }
      const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(timeout),
        headers: { 'user-agent': ua, accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'accept-language': 'en' } });
      chain.push([res.status, url]);
      const headers = Object.fromEntries([...res.headers].map(([k, v]) => [k.toLowerCase(), v]));
      if (follow && [301, 302, 303, 307, 308].includes(res.status) && headers.location) {
        try { await res.body?.cancel(); } catch {}
        url = new URL(headers.location, url).href; continue;
      }
      const body = await readCapped(res, cap);
      return { ok: true, status: res.status, url, headers, ...body, chain, ms: Date.now() - t0 };
    }
    return { ok: false, error: 'too many redirects', url, status: null, headers: {}, text: '', bytes: 0, chain, ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, error: String(e?.cause?.code || e?.name || e?.message || e).slice(0, 120), url, status: null, headers: {}, text: '', bytes: 0, chain, ms: Date.now() - t0 };
  }
}

function certInfo(host) {
  return new Promise(resolve => {
    let done = false; const fin = v => { if (!done) { done = true; resolve(v); } };
    try {
      const s = tls.connect({ host, port: 443, servername: host, timeout: 4000 }, () => {
        const c = s.getPeerCertificate() || {};
        const issuer = [c.issuer?.O, c.issuer?.CN].filter(Boolean).join(' ');
        const out = { authorized: s.authorized, error: s.authorizationError ? String(s.authorizationError) : null, issuer,
          validTo: c.valid_to ? new Date(c.valid_to).toISOString() : null };
        if (/Anthropic|Egress Gateway/.test(issuer)) out.intercepted = true; // test sandbox only
        s.end(); fin(out);
      });
      s.on('error', e => fin({ authorized: false, error: e.code || e.message }));
      s.on('timeout', () => { s.destroy(); fin({ authorized: false, error: 'timeout' }); });
    } catch (e) { fin({ authorized: false, error: String(e.message) }); }
  });
}

// ----------------------------------------------------------------------------- robots.txt (Google rules)
function parseRobots(text) {
  const groups = []; let cur = null, lastUA = false;
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/#.*/, '').trim();
    const m = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/); if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === 'user-agent') { if (!cur || !lastUA) { cur = { agents: [], rules: [] }; groups.push(cur); } cur.agents.push(v.toLowerCase()); lastUA = true; }
    else if (k === 'allow' || k === 'disallow') { if (cur) cur.rules.push({ allow: k === 'allow', path: v }); lastUA = false; }
    else lastUA = false;
  }
  return groups;
}
function robotsAllows(groups, token, path = '/') {
  token = token.toLowerCase();
  let best = '', rules = [];
  for (const g of groups) for (const a of g.agents) if (a !== '*' && token.startsWith(a) && a.length >= best.length) {
    if (a.length > best.length) rules = []; best = a; rules.push(...g.rules);
  }
  if (!best) rules = groups.filter(g => g.agents.includes('*')).flatMap(g => g.rules);
  let win = null;
  for (const r of rules) {
    if (!r.path) continue;
    const re = new RegExp('^' + r.path.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\\\$$/, '$'));
    if (re.test(path) && (!win || r.path.length > win.path.length || (r.path.length === win.path.length && r.allow))) win = r;
  }
  return !win || win.allow;
}

// ----------------------------------------------------------------------------- HTML signals (regex, no DOM)
const attrs = tag => Object.fromEntries([...tag.matchAll(/([a-zA-Z:_-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g)]
  .map(m => [m[1].toLowerCase(), m[3] ?? m[4] ?? m[5] ?? '']));
function ldTypes(o, acc = new Set()) {
  if (Array.isArray(o)) o.forEach(x => ldTypes(x, acc));
  else if (o && typeof o === 'object') {
    const t = o['@type']; if (t) (Array.isArray(t) ? t : [t]).forEach(x => acc.add(String(x)));
    Object.values(o).forEach(v => ldTypes(v, acc));
  }
  return acc;
}
function ldSameAs(o, acc = []) {
  if (Array.isArray(o)) o.forEach(x => ldSameAs(x, acc));
  else if (o && typeof o === 'object') {
    if (o.sameAs) acc.push(...(Array.isArray(o.sameAs) ? o.sameAs : [o.sameAs]));
    Object.values(o).forEach(v => ldSameAs(v, acc));
  }
  return acc;
}
export function pageSignals(html, headers = {}) {
  const noSvg = html.replace(/<svg\b[\s\S]*?<\/svg>/gi, '');
  const meta = {};
  for (const m of noSvg.matchAll(/<meta\b[^>]*>/gi)) {
    const a = attrs(m[0]); const k = (a.name || a.property || '').toLowerCase();
    if (k && !(k in meta)) meta[k] = a.content || '';
  }
  const canon = [...noSvg.matchAll(/<link\b[^>]*>/gi)].map(m => attrs(m[0])).filter(a => /\bcanonical\b/i.test(a.rel || '')).map(a => a.href || '');
  const ld = [...html.matchAll(/<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  const types = new Set(); const sameAs = []; let ldErrors = 0;
  for (const b of ld) { try { const o = JSON.parse(b); ldTypes(o, types); ldSameAs(o, sameAs); } catch { ldErrors++; } }
  const text = noSvg.replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ');
  const imgs = [...noSvg.matchAll(/<img\b[^>]*>/gi)].map(m => attrs(m[0]));
  return {
    title: (noSvg.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '').replace(/\s+/g, ' ').trim(),
    desc: meta.description || '', meta, canonical: canon,
    robots: ((meta.robots || '') + ' ' + (headers['x-robots-tag'] || '')).toLowerCase(),
    lang: noSvg.match(/<html\b[^>]*\blang\s*=\s*["']?([^"'\s>]+)/i)?.[1] || '',
    h1: (noSvg.match(/<h1\b/gi) || []).length,
    words: (text.match(/[\p{L}\p{N}]{2,}/gu) || []).length,
    imgs: imgs.length, noAlt: imgs.filter(a => !('alt' in a)).length,
    types: [...types], sameAs: [...new Set(sameAs.map(String))], ldErrors,
    b64: [...html.matchAll(/data:[a-z]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]{200,}/gi)].reduce((n, m) => n + m[0].length, 0),
    insecure: [...new Set([...noSvg.matchAll(/<(?:img|script|iframe|source|video|audio|embed)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi)].map(m => m[1]))],
    links: [...new Set([...noSvg.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)/gi)].map(m => m[1]))],
    contact: /mailto:|tel:|[\w.+-]+@[\w-]+\.[\w.]+|\+?\d[\d ()-]{7,}\d/.test(html),
    jsShell: /<div\b[^>]*\bid\s*=\s*["'](?:root|app|__next|__nuxt|svelte)["'][^>]*>\s*<\/div>|ng-version=|data-reactroot|<noscript>[^<]*enable javascript/i.test(html),
  };
}

// ----------------------------------------------------------------------------- stack detection
const NS_MAP = [['crazydomains', 'Crazy Domains', 'crazydomains'], ['domaincontrol.com', 'GoDaddy', 'godaddy'], ['cloudflare.com', 'Cloudflare', 'cloudflare'],
  ['awsdns', 'AWS Route 53', 'generic'], ['nsone.net', 'Netlify DNS', 'netlifydns'], ['squarespacedns', 'Squarespace', 'squarespace'],
  ['googledomains.com', 'Squarespace (ex Google Domains)', 'squarespace'], ['registrar-servers.com', 'Namecheap', 'namecheap'],
  ['wixdns.net', 'Wix', 'generic'], ['vercel-dns.com', 'Vercel', 'generic'], ['nameserver.net.au', 'VentraIP', 'generic'],
  ['netregistry', 'Netregistry', 'generic'], ['hostinger', 'Hostinger', 'generic'], ['siteground', 'SiteGround', 'generic']];
const MX_MAP = [['google.com', 'Google Workspace', 'google'], ['googlemail.com', 'Google Workspace', 'google'], ['outlook.com', 'Microsoft 365', 'm365'],
  ['zoho', 'Zoho Mail', 'zoho'], ['messagingengine.com', 'Fastmail', 'fastmail'], ['secureserver.net', 'GoDaddy email', 'generic'],
  ['crazydomains', 'Crazy Domains email', 'generic'], ['protonmail', 'Proton Mail', 'generic'], ['mimecast', 'Mimecast', 'generic']];
function detectStack(ns, mx, home) {
  const h = home.headers || {}, body = (home.text || '').slice(0, 300000).toLowerCase(), server = (h.server || '').toLowerCase();
  const pick = (map, list, dflt) => { for (const [k, n, key] of map) if (list.some(x => x.toLowerCase().includes(k))) return [n, key]; return dflt; };
  const [dnsName, dnsKey] = pick(NS_MAP, ns, ['Unknown', 'generic']);
  const [email, emailKey] = mx.length ? pick(MX_MAP, mx, ['Other', 'generic']) : ['None (no MX records)', 'none'];
  const hosts = [['x-nf-request-id' in h || server.includes('netlify'), 'Netlify', 'netlify'], ['x-vercel-id' in h, 'Vercel', 'vercel'],
    [server.includes('squarespace'), 'Squarespace', 'squarespace'], ['x-wix-request-id' in h || server.includes('pepyaka'), 'Wix', 'wix'],
    ['x-shopid' in h || /shopify/.test(h['powered-by'] || ''), 'Shopify', 'shopify'], [body.includes('data-wf-site'), 'Webflow', 'webflow'],
    [server.includes('github.com'), 'GitHub Pages', 'generic'], ['cf-ray' in h, 'Cloudflare (proxied)', 'cloudflare']];
  const [host, hostKey] = (hosts.find(x => x[0]) || [0, 'Unknown', 'generic']).slice(1);
  const cms = /wp-content|wp-json/.test(body) ? 'WordPress' : /data-astro|astro-/.test(body) ? 'Astro' : /_next\/static/.test(body) ? 'Next.js' : '';
  return { dns: dnsName, dnsKey, email, emailKey, host, hostKey, cms, cdn: 'cf-ray' in h ? 'Cloudflare' : '' };
}

// ----------------------------------------------------------------------------- the audit
// area keys: safety, email, access, understood, readable
export async function runAudit(domain, { deep = false, budget = 8600 } = {}) {
  const t0 = Date.now(); let checks = [];
  DEADLINE = t0 + budget;
  const add = (area, key, status, weight, title, detail = '') => checks.push({ area, key, status, weight, title, detail });

  // stage 1: everything that only needs the domain
  const [homeA, ns, mxRaw, rootTxt, dmarcTxt, stsTxt, tlsrptTxt, caa, apexA, wwwA, wwwC, soa] = await Promise.all([
    get(`https://${domain}/`, { cap: 6_000_000 }), dns(domain, 'NS'), dns(domain, 'MX'), txt(domain), txt('_dmarc.' + domain),
    txt('_mta-sts.' + domain), txt('_smtp._tls.' + domain), dns(domain, 'CAA'), dns(domain, 'A'), dns('www.' + domain, 'A'),
    dns('www.' + domain, 'CNAME'), dns(domain, 'SOA', true)]);
  let home = homeA;
  if (!home.ok || home.status >= 400) {
    const w = await get(`https://www.${domain}/`, { cap: 6_000_000 });
    if (w.ok && w.status < 400) home = w;
  }
  const canon = (() => { try { return new URL(home.url).hostname; } catch { return domain; } })();
  const base = `https://${canon}`;
  const mx = mxRaw.map(x => x.split(/\s+/).pop().replace(/\.$/, '').toLowerCase()).filter(x => x && x !== '.' && x !== '').sort();
  const blocked = home.ok && [401, 403, 405, 406, 429, 503].includes(home.status)
    ? `HTTP ${home.status}${home.headers['x-datadome'] || /datadome/i.test(home.headers.server || '') ? ', DataDome' : 'cf-ray' in home.headers ? ', Cloudflare' : ''}` : '';
  const other = canon === domain ? 'www.' + domain : domain;
  const otherResolves = canon === domain ? (wwwA.length || wwwC.length) : apexA.length;

  // stage 2: dependent fetches, all in parallel
  const selectors = deep ? DKIM_SELECTORS : DKIM_SELECTORS.slice(0, 12);
  const uaTest = deep ? ['GPTBot', 'OAI-SearchBot', 'ClaudeBot', 'PerplexityBot', 'Googlebot', 'Bingbot'] : ['GPTBot', 'ClaudeBot', 'PerplexityBot'];
  const [httpApex, httpWww, otherHost, robots, llms, r404, mtaPolicy, cert, dkimFound, uaRes] = await Promise.all([
    apexA.length ? get(`http://${domain}/`, { follow: false, cap: 4000 }) : null,
    (wwwA.length || wwwC.length) ? get(`http://www.${domain}/`, { follow: false, cap: 4000 }) : null,
    otherResolves ? get(`https://${other}/`, { follow: false, cap: 4000 }) : null,
    get(base + '/robots.txt', { cap: 300000 }), get(base + '/llms.txt', { cap: 300000 }),
    get(base + '/this-page-should-not-exist-' + Date.now(), { cap: 20000 }),
    stsTxt.some(t => /^v=stsv1/i.test(t)) ? get(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { follow: false, cap: 20000 }) : null,
    certInfo(canon),
    mx.length ? Promise.all(selectors.map(async s => {
      const t = (await txt(`${s}._domainkey.${domain}`)).find(x => /p=/.test(x)); if (!t) return null;
      const key = (t.match(/p=([A-Za-z0-9+/=\s]*)/)?.[1] || '').replace(/\s/g, '');
      const n = key ? Buffer.from(key, 'base64').length : 0;
      return { s, bits: n > 520 ? 4096 : n >= 270 ? 2048 : n >= 140 ? 1024 : n ? 512 : 0 };
    })).then(r => r.filter(Boolean)) : [],
    home.status === 200 ? Promise.all(uaTest.map(b => get(base + '/', { ua: BOT_UA[b], cap: 200000 }).then(r => [b, r]))) : [],
  ]);

  // sitemap (needs robots)
  const rtxt = robots.ok && robots.status === 200 && !/^\s*</.test(robots.text) ? robots.text : '';
  const smCands = [...rtxt.matchAll(/^\s*sitemap:\s*(\S+)/gim)].map(m => m[1].replace(/^http:/, 'https:'));
  let smUrls = [], smSrc = '';
  for (const u of (smCands.length ? smCands : [base + '/sitemap.xml', base + '/sitemap_index.xml', base + '/wp-sitemap.xml']).slice(0, 3)) {
    const r = await get(u, { cap: 3_000_000, timeout: 3500 });
    if (r.ok && r.status === 200 && /<urlset|<sitemapindex/.test(r.text.slice(0, 3000))) {
      smSrc = u;
      const locs = [...r.text.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map(m => m[1].replace(/&amp;/g, '&'));
      if (/<sitemapindex/.test(r.text.slice(0, 3000))) {
        const kids = await Promise.all(locs.slice(0, 3).map(c => get(c.replace(/^http:/, 'https:'), { cap: 3_000_000, timeout: 3500 })));
        smUrls = kids.flatMap(k => [...(k.text || '').matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map(m => m[1].replace(/&amp;/g, '&')));
      } else smUrls = locs;
      break;
    }
  }

  // page sample
  const homeSig = home.ok && home.status === 200 ? pageSignals(home.text, home.headers) : null;
  let pool = smUrls.length ? smUrls : (homeSig?.links || []).map(h => { try { return new URL(h, home.url).href.split('#')[0]; } catch { return ''; } })
    .filter(u => { try { return new URL(u).hostname === canon && !/\.(pdf|jpe?g|png|zip|mp4|webp)$/i.test(u); } catch { return false; } });
  pool = [...new Set(pool)].filter(u => u.replace(/\/$/, '') !== home.url.replace(/\/$/, '')).sort((a, b) => a.split('/').length - b.split('/').length || a.length - b.length);
  const sample = pool.slice(0, deep ? 6 : 3);
  const fetched = await Promise.all(sample.map(u => get(u, { cap: 6_000_000, timeout: 4000 })));
  const pages = [];
  if (homeSig) pages.push({ url: home.url, status: home.status, bytes: home.bytes, ms: home.ms, redirected: false, ...homeSig });
  sample.forEach((u, i) => {
    const r = fetched[i];
    const row = { url: u, status: r.status, bytes: r.bytes, ms: r.ms, redirected: r.chain.length > 1, final: r.url, error: r.error };
    if (r.ok && r.status === 200 && /html/.test(r.headers['content-type'] || 'text/html')) Object.assign(row, pageSignals(r.text, r.headers));
    pages.push(row);
  });

  // ------------------------------------------------ checks: website safety
  if (blocked) add('safety', 'https_works', 'pass', 3, 'Site loads over HTTPS', `TLS OK; site answered ${blocked} to the check`);
  else if (!home.ok || home.status >= 500) add('safety', 'https_works', 'fail', 3, 'Site loads over HTTPS', `https://${domain}/ failed: ${home.error || home.status}`);
  else add('safety', 'https_works', 'pass', 3, 'Site loads over HTTPS', `${home.url} (${home.status})`);
  const badHttp = [httpApex, httpWww].filter(Boolean).filter(r => !([301, 308].includes(r.status) && /^https:/.test(r.headers.location || '')))
    .filter(r => !(blocked && [401, 403, 429].includes(r.status)));
  add('safety', 'https_redirect', badHttp.length ? 'fail' : 'pass', 3, 'HTTP redirects to HTTPS (301)',
    badHttp.length ? badHttp.map(r => `${r.url} -> ${r.status || r.error} ${r.headers.location || ''}`).join('; ') : 'http:// permanently redirects to https://');
  if (otherHost && blocked && [401, 403, 429].includes(otherHost.status)) {
    add('safety', 'host_redirect', 'info', 2, 'One primary host (www vs non-www)', `Could not test: ${other} refused the check`);
  } else if (otherHost) {
    let ok = false; try { ok = [301, 308].includes(otherHost.status) && new URL(otherHost.headers.location || '', otherHost.url).hostname === canon; } catch {}
    add('safety', 'host_redirect', ok ? 'pass' : 'warn', 2, 'One primary host (www vs non-www)', `https://${other}/ -> ${otherHost.status || otherHost.error} ${otherHost.headers.location || ''}; primary ${canon}`);
  } else add('safety', 'host_redirect', 'warn', 1, 'One primary host (www vs non-www)', `${other} does not resolve`);
  const certBad = !home.ok && /CERT|SSL|TLS|self.signed|expired/i.test(home.error || '');
  if (certBad || (cert.error && !cert.intercepted && !cert.authorized)) add('safety', 'cert_valid', 'fail', 3, 'Valid TLS certificate', home.error || cert.error);
  else {
    add('safety', 'cert_valid', 'pass', 3, 'Valid TLS certificate', cert.intercepted ? 'Verified over HTTPS' : `Issuer: ${cert.issuer || '?'}`);
    if (cert.validTo && !cert.intercepted) {
      const days = Math.floor((new Date(cert.validTo) - Date.now()) / 864e5);
      add('safety', 'cert_expiry', days < 7 ? 'fail' : days < 14 ? 'warn' : 'pass', 2, 'Certificate not close to expiry', `${days} days left (${cert.validTo.slice(0, 10)})`);
    }
  }
  const h = home.headers || {};
  const hsts = h['strict-transport-security'] || '', maxAge = +(hsts.match(/max-age=(\d+)/)?.[1] || 0);
  add('safety', 'hsts', hsts && maxAge >= 15552000 ? 'pass' : 'warn', 2, 'HSTS header', hsts || 'Strict-Transport-Security not sent');
  const csp = h['content-security-policy'] || h['content-security-policy-report-only'] || '';
  const missing = [!/nosniff/i.test(h['x-content-type-options'] || '') && 'X-Content-Type-Options',
    !h['x-frame-options'] && !/frame-ancestors/.test(csp) && 'X-Frame-Options', !h['referrer-policy'] && 'Referrer-Policy',
    !h['permissions-policy'] && 'Permissions-Policy'].filter(Boolean);
  if (!blocked) add('safety', 'sec_headers', missing.length ? 'warn' : 'pass', 2, 'Basic security headers', missing.length ? 'Missing: ' + missing.join(', ') : 'All present');
  add('safety', 'csp', csp ? 'pass' : 'info', 1, 'Content-Security-Policy', csp ? csp.slice(0, 140) : 'Not set (optional for brochure sites)');
  if (homeSig) add('safety', 'mixed', homeSig.insecure.length ? 'warn' : 'pass', 2, 'No insecure (http://) assets', homeSig.insecure.slice(0, 4).join(', ') || 'None found');
  add('safety', 'caa', caa.length ? 'pass' : 'info', 1, 'CAA record', caa.join('; ') || 'None (optional)');
  add('safety', 'dnssec', soa.ad ? 'pass' : 'info', 1, 'DNSSEC', soa.ad ? 'Signed' : 'Not enabled (optional)');

  // ------------------------------------------------ checks: email
  const spf = rootTxt.filter(t => /^v=spf1/i.test(t));
  if (!spf.length) add('email', 'spf', 'fail', 3, 'SPF record', 'No v=spf1 TXT record');
  else if (spf.length > 1) add('email', 'spf_multi', 'fail', 3, 'SPF record', `${spf.length} SPF records (must be one)`);
  else {
    const q = spf[0].match(/([~\-+?]?)all\b/);
    if (q && (q[1] === '+' || q[1] === '?' || q[1] === '')) add('email', 'spf_all', 'fail', 3, 'SPF record', `${spf[0]} (lets anyone send)`);
    else if (!q && !/redirect=/.test(spf[0])) add('email', 'spf_all', 'warn', 3, 'SPF record', `${spf[0]} (no ~all/-all)`);
    else add('email', 'spf', 'pass', 3, 'SPF record', spf[0]);
  }
  if (mx.length) {
    add('email', 'dkim', dkimFound.length ? 'pass' : 'warn', 3, 'DKIM signing key',
      dkimFound.length ? 'Found: ' + dkimFound.map(x => `${x.s}._domainkey${x.bits ? ` ~${x.bits}-bit` : ''}`).join(', ') : 'Not found at common selectors (may use a custom one)');
    const weak = dkimFound.filter(x => x.bits && x.bits < 2048);
    if (weak.length) add('email', 'dkim_weak', 'warn', 1, 'DKIM key strength', 'Weak: ' + weak.map(x => x.s).join(', '));
  } else add('email', 'mx', 'info', 1, 'Mail (MX) records', 'No MX records: domain does not receive email');
  const dm = dmarcTxt.filter(t => /^v=dmarc1/i.test(t));
  if (!dm.length) add('email', 'dmarc', 'fail', 3, 'DMARC policy', 'No TXT at _dmarc');
  else if (dm.length > 1) add('email', 'dmarc_multi', 'fail', 3, 'DMARC policy', `${dm.length} DMARC records`);
  else {
    const kv = Object.fromEntries(dm[0].split(';').map(x => x.split('=').map(y => y.trim().toLowerCase())).filter(x => x.length === 2));
    const enforced = ['quarantine', 'reject'].includes(kv.p);
    add('email', 'dmarc_policy', enforced && (kv.pct || '100') === '100' ? 'pass' : 'warn', 3, 'DMARC policy', dm[0] + (enforced ? '' : ' (p=none: monitoring only)'));
    if (!kv.rua) add('email', 'dmarc_rua', 'warn', 1, 'DMARC reports (rua)', 'No rua= reporting address');
  }
  if (mx.length) {
    const sts = stsTxt.filter(t => /^v=stsv1/i.test(t));
    if (!sts.length) add('email', 'mta_sts', 'warn', 2, 'MTA-STS', 'No _mta-sts TXT record');
    else if (!mtaPolicy?.ok || mtaPolicy.status !== 200 || !/stsv1/i.test(mtaPolicy.text)) add('email', 'mta_sts_fetch', 'fail', 2, 'MTA-STS policy reachable', `Policy fetch: ${mtaPolicy?.error || mtaPolicy?.status}`);
    else {
      const mode = mtaPolicy.text.match(/^\s*mode\s*:\s*(\w+)/im)?.[1] || '?';
      const pats = [...mtaPolicy.text.matchAll(/^\s*mx\s*:\s*(\S+)/gim)].map(m => m[1].toLowerCase());
      const match = (host, p) => p.startsWith('*.') ? host.endsWith(p.slice(1)) && host.split('.').length === p.split('.').length : host === p;
      add('email', 'mta_sts_mode', mode === 'enforce' ? 'pass' : 'warn', 2, 'MTA-STS policy', `${sts[0]}; mode: ${mode}`);
      const un = mx.filter(m => !pats.some(p => match(m, p)));
      if (un.length) add('email', 'mta_sts_mx', 'fail', 2, 'MTA-STS covers all MX hosts', 'Not covered: ' + un.join(', '));
    }
    add('email', 'tlsrpt', tlsrptTxt.some(t => /^v=tlsrptv1/i.test(t)) ? 'pass' : 'warn', 1, 'TLS-RPT', tlsrptTxt[0] || 'No TXT at _smtp._tls');
  }

  // ------------------------------------------------ checks: AI access
  if (robots.ok && robots.status === 200 && /^\s*</.test(robots.text)) add('access', 'robots_html', 'warn', 2, 'robots.txt', 'Returns an HTML page');
  else add('access', 'robots', rtxt ? 'pass' : 'warn', 2, 'robots.txt', rtxt ? 'Present' : `Not found (${robots.status || robots.error})`);
  const groups = parseRobots(rtxt);
  if (!robotsAllows(groups, 'somerandomcrawler')) add('access', 'robots_all', 'fail', 3, 'robots.txt allows crawling', 'User-agent: * disallowed from /');
  const bs = ROBOT_TOKENS.search.filter(t => !robotsAllows(groups, t)), bt = ROBOT_TOKENS.training.filter(t => !robotsAllows(groups, t));
  add('access', 'ai_search_block', bs.length ? 'fail' : 'pass', 3, 'AI search & answer bots allowed', bs.length ? 'Blocked in robots.txt: ' + bs.join(', ') : 'All allowed');
  add('access', 'ai_train_block', bt.length ? 'info' : 'pass', 1, 'AI training crawlers', bt.length ? 'Blocked: ' + bt.join(', ') : 'All allowed');
  if (blocked) add('access', 'waf', 'warn', 2, 'Bot protection lets crawlers in', `Site refused a normal request from a cloud network (${blocked})`);
  else if (uaRes.length) {
    const refused = uaRes.filter(([, r]) => r.status !== 200 || r.headers['cf-mitigated'] || /Just a moment\.\.\./.test(r.text.slice(0, 5000)))
      .map(([b, r]) => `${b} (${r.status || r.error})`);
    add('access', 'ua_block', refused.length ? 'warn' : 'pass', 3, 'Server lets AI bots in (live test)', refused.length ? 'Refused: ' + refused.join(', ') : 'Home page returned 200 to ' + uaRes.map(x => x[0]).join(', '));
  }
  const lt = llms.ok && llms.status === 200 && !/^\s*</.test(llms.text) && llms.text.trim().length > 50;
  add('access', 'llms', lt ? 'pass' : 'warn', 1, 'llms.txt', lt ? `Present (${llms.text.length} chars)` : 'Not found');

  // ------------------------------------------------ checks: understood + readable
  if (!smSrc) add('readable', 'sitemap', 'fail', 3, 'XML sitemap', 'No sitemap found');
  else {
    add('readable', 'sitemap', smCands.length ? 'pass' : 'warn', 3, 'XML sitemap', `${smSrc}: ${smUrls.length} URLs${smCands.length ? '' : '; not in robots.txt'}`);
    const wrong = smUrls.filter(u => { try { const x = new URL(u); return x.hostname !== canon || x.protocol !== 'https:'; } catch { return true; } });
    if (wrong.length) add('readable', 'sitemap_host', 'warn', 2, 'Sitemap uses the primary https host', `${wrong.length} URL(s) differ, e.g. ${wrong[0]}`);
  }
  add('readable', 'soft404', r404.status === 404 ? 'pass' : 'warn', 1, 'Missing pages return 404', `Random URL returned ${r404.status || r404.error}`);
  const ok = pages.filter(p => 'title' in p);
  const P = p => { try { return new URL(p.url).pathname; } catch { return p.url; } };
  if (!ok.length) {
    add('understood', 'pages', blocked ? 'info' : 'fail', 3, 'Pages could be read', blocked ? `Skipped: site refused the check (${blocked})` : 'No pages could be fetched');
  } else {
    const n = ok.length;
    const agg = (area, key, weight, title, bad, warnOnly, fmt = P) => {
      const b = ok.filter(bad);
      add(area, key, !b.length ? 'pass' : (warnOnly || b.length < n ? 'warn' : 'fail'), weight, title,
        `${n - b.length}/${n} pages OK` + (b.length ? '; issues: ' + b.slice(0, 6).map(fmt).join(', ') : ''));
    };
    const broken = pages.filter(p => p.status !== 200);
    if (broken.length) add('readable', 'sitemap_urls', 'warn', 2, 'Sampled pages return 200', broken.map(p => `${P(p)} -> ${p.status || p.error}`).join(', '));
    const smSet = new Set(smUrls.map(u => u.replace(/\/$/, '')));
    const clash = ok.filter(p => /noindex/.test(p.robots) && (smSet.has(p.url.replace(/\/$/, '')) || p === ok[0]));
    if (clash.length) add('understood', 'noindex', 'fail', 3, 'Pages are indexable', 'noindex on ' + clash.map(P).join(', ') + ' (listed in sitemap)');
    else agg('understood', 'noindex', 3, 'Pages are indexable', p => /noindex/.test(p.robots), true);
    agg('understood', 'title', 2, 'Title tags (15-70 chars)', p => p.title.length < 15 || p.title.length > 70, true, p => `${P(p)} (${p.title.length})`);
    agg('understood', 'desc', 2, 'Meta descriptions (50-160 chars)', p => p.desc.length < 50 || p.desc.length > 160, true, p => `${P(p)} (${p.desc.length})`);
    agg('understood', 'canonical', 2, 'Canonical tags', p => {
      if (p.canonical.length !== 1 || !/^https?:/.test(p.canonical[0])) return true;
      try { return new URL(p.canonical[0]).hostname !== canon; } catch { return true; }
    }, false, p => `${P(p)} (${p.canonical[0] || 'missing'})`);
    agg('understood', 'h1', 1, 'One H1 per page', p => p.h1 !== 1, true, p => `${P(p)} (${p.h1})`);
    agg('understood', 'lang', 1, 'Language declared', p => !p.lang, false);
    agg('understood', 'og', 1, 'Social sharing tags', p => !(p.meta['og:title'] && p.meta['og:description'] && p.meta['og:image']), true);
    agg('understood', 'jsonld', 3, 'Structured data (JSON-LD)', p => !p.types.length, false);
    const errs = ok.filter(p => p.ldErrors);
    if (errs.length) add('understood', 'jsonld_err', 'fail', 2, 'JSON-LD is valid', errs.map(P).join(', '));
    const ORG = ['Organization', 'LocalBusiness', 'ProfessionalService', 'Corporation', 'Store', 'Restaurant', 'MedicalBusiness', 'LegalService', 'OnlineStore', 'Person'];
    const types = [...new Set(ok.flatMap(p => p.types))];
    const ent = types.filter(t => ORG.includes(t) || t.endsWith('Business'));
    add('understood', 'entity', ent.length ? 'pass' : 'warn', 3, 'Business entity in structured data', ent.length ? 'Entity: ' + ent.join(', ') : 'No Organization / LocalBusiness markup');
    const same = [...new Set(ok.flatMap(p => p.sameAs))];
    add('understood', 'sameas', same.length ? 'pass' : 'warn', 2, 'Official profiles linked (sameAs)', same.slice(0, 5).join(', ') || 'None');
    add('understood', 'contact', ok.some(p => p.contact) ? 'pass' : 'warn', 1, 'Contact details in HTML', ok.some(p => p.contact) ? 'Found' : 'No email or phone found');
    agg('readable', 'thin', 3, 'Readable text without JavaScript', p => p.words < 150, false, p => `${P(p)} (${p.words} words)`);
    agg('readable', 'weight', 2, 'HTML size under 1 MB', p => p.bytes > 1_000_000, false, p => `${P(p)} (${(p.bytes / 1e6).toFixed(1)} MB)`);
    agg('readable', 'base64', 2, 'No heavy inline assets', p => p.b64 > 200_000, false, p => `${P(p)} (${(p.b64 / 1e6).toFixed(1)} MB)`);
    agg('readable', 'speed', 1, 'Server response time', p => p.ms > 4000, true, p => `${P(p)} (${(p.ms / 1000).toFixed(1)}s)`);
    if (ok.some(p => p.words < 150 && p.jsShell)) add('readable', 'js_shell', 'info', 1, 'Content rendered by JavaScript', ok.filter(p => p.jsShell).map(P).join(', '));
    const tot = ok.reduce((a, p) => a + p.imgs, 0), na = ok.reduce((a, p) => a + p.noAlt, 0);
    add('readable', 'alt', na ? 'warn' : 'pass', 1, 'Image alt text', `${tot - na}/${tot} images have alt text`);
  }

  // bot protection refused us: page-level results would be noise, keep what is still reliable
  if (blocked) checks = checks.filter(c => ['safety', 'email'].includes(c.area) || c.key === 'waf' ||
    (rtxt && ['robots_all', 'ai_search_block', 'ai_train_block'].includes(c.key)));
  const stack = detectStack(ns, mx, home);
  DEADLINE = Infinity;
  const reachable = home.ok || !!blocked;
  return { domain, canon, reachable, checkedAt: new Date().toISOString(), ms: Date.now() - t0, stack, mx, checks, blocked, pages: pages.length };
}

// ----------------------------------------------------------------------------- scoring
const VAL = { pass: 1, warn: 0.5, fail: 0 };
export function score(checks) {
  const c = checks.filter(x => x.status in VAL); const w = c.reduce((a, x) => a + x.weight, 0);
  const s = w ? Math.round(100 * c.reduce((a, x) => a + VAL[x.status] * x.weight, 0) / w) : 0;
  return { score: s, grade: s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F' };
}

// ----------------------------------------------------------------------------- plain-English summary (public)
// Deliberately non-technical: business impact only. No record names, no tools, no fixes.
const AREAS = [
  ['safety', 'Website safety'], ['email', 'Email protection'], ['access', 'Found by AI assistants'],
  ['understood', 'Understood by Google & AI'], ['readable', 'Easy for search engines to read'],
];
const bad = (checks, keys, statuses = ['fail']) => checks.some(c => keys.includes(c.key) && statuses.includes(c.status));
const GOOD = {
  safety: 'Your site is secure and set up the way browsers expect.',
  email: 'Your email is well protected against people pretending to be you.',
  access: 'AI assistants can reach and read your site.',
  understood: 'Search engines and AI can clearly tell who you are and what you do.',
  readable: 'Your site is easy for search engines to find and read.',
};
const UNKNOWN = 'Your site’s security stopped us reading your pages. If it stops us, it may be stopping search engines and AI tools too.';
const LINES = {
  safety: [
    [c => bad(c, ['https_works', 'cert_valid', 'cert_expiry']), 'Some visitors may get a security warning before your site even loads. Most people leave when that happens.'],
    [c => bad(c, ['https_redirect', 'mixed'], ['fail', 'warn']), 'Your site can still be opened in a way that isn’t fully secure, so some visitors may see a “not secure” warning.'],
    [c => bad(c, ['host_redirect'], ['warn']), 'Your site answers at more than one address, which can split your search ranking and confuse some visitors.'],
    [() => true, 'Your site is safe to visit, but it’s missing some of the standard protections browsers and security scanners look for.'],
  ],
  email: [
    [c => bad(c, ['spf', 'spf_multi', 'spf_all', 'dmarc', 'dmarc_multi']), 'Right now, someone could send emails that look like they come from your business, and your customers would have no easy way to tell.'],
    [c => c.some(x => x.key === 'mx'), 'This domain doesn’t receive email, but it isn’t fully locked down. Someone could still send email pretending to be you.'],
    [c => bad(c, ['dmarc_policy', 'dkim'], ['warn']), 'Your email is partly protected, but scammers could still send emails that look like yours, and some of your real emails may land in junk.'],
    [() => true, 'Your email is mostly protected. A few finishing touches would close the remaining gaps.'],
  ],
  access: [
    [c => bad(c, ['robots_all', 'ai_search_block']), 'Your site is turning away some AI assistants, so tools like ChatGPT and Perplexity can’t read it or recommend you.'],
    [c => bad(c, ['ua_block', 'waf'], ['warn', 'fail']), 'Your site’s security settings are blocking some AI assistants, so they may not be able to read your pages or recommend you.'],
    [c => bad(c, ['robots', 'robots_html'], ['warn']), 'AI assistants can reach your site, but there are no clear instructions telling them what they can read.'],
    [() => true, 'AI assistants can reach your site, but you’re missing an easy extra that helps them sum up your business accurately.'],
  ],
  understood: [
    [c => bad(c, ['noindex'], ['fail', 'warn']), 'Some of your pages are hidden from Google and AI search, so nobody can find them there.'],
    [c => bad(c, ['pages']), 'We couldn’t read your pages, and many search and AI tools probably can’t either.'],
    [c => bad(c, ['jsonld', 'entity', 'jsonld_err'], ['fail', 'warn']), 'Search engines and AI have to guess what your business does, where you are and who you serve. When they guess, you get left out of answers.'],
    [c => bad(c, ['canonical', 'sameas', 'contact'], ['fail', 'warn']), 'Search engines can mostly tell what you do, but some of the signals that confirm who you are are missing or mixed.'],
    [() => true, 'How your pages show up in Google results, and when they’re shared on social, could be clearer and more compelling.'],
  ],
  readable: [
    [c => bad(c, ['thin']) && c.some(x => x.key === 'js_shell'), 'Much of your content only appears after the page runs code. Most AI tools never see it.'],
    [c => bad(c, ['thin'], ['fail', 'warn']), 'Some of your pages have very little text that search engines and AI can actually read.'],
    [c => bad(c, ['sitemap']), 'Search engines don’t have a clear map of your site, so some pages may never be found.'],
    [c => bad(c, ['weight', 'base64', 'speed'], ['fail', 'warn']), 'Some pages are heavy or slow to load, which costs you visitors and search ranking.'],
    [() => true, 'Your site is mostly easy to read, with a few loose ends that make search engines work harder than they should.'],
  ],
};
export function summarise(audit) {
  const overall = score(audit.checks);
  const areas = AREAS.map(([key, name]) => {
    const cs = audit.checks.filter(c => c.area === key);
    if (!cs.some(c => c.status in VAL)) return { name, status: 'unknown', line: UNKNOWN };
    const s = score(cs).score;
    const status = cs.some(c => c.status === 'fail' && c.weight >= 3) || s < 60 ? 'risk' : s < 85 ? 'attention' : 'good';
    const line = status === 'good' ? GOOD[key] : LINES[key].find(([test]) => test(cs))[1];
    return { name, status, line };
  });
  const headline = audit.blocked ? 'Your site’s security stopped part of our check.' :
    { A: 'Your website is in great shape.', B: 'Your website is in good shape, with a few gaps.', C: 'A few things are holding your website back.',
      D: 'Your website has some real gaps.', F: 'Your website has some serious gaps.' }[overall.grade];
  return { domain: audit.domain, grade: overall.grade, score: overall.score, headline, areas, checkedAt: audit.checkedAt };
}

// ----------------------------------------------------------------------------- full technical report (Dave only)
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function fixes(a) {
  const d = a.domain, st = a.stack, host = a.canon;
  const dnsHow = {
    crazydomains: 'Crazy Domains: Domains > Manage > DNS Settings > Add record. Leave Sub Domain BLANK for the root (it appends the domain itself); otherwise type only the prefix. Delete any old record with the same name first.',
    cloudflare: 'Cloudflare: DNS > Records > Add record. "@" for root, otherwise the prefix. mta-sts CNAME must be DNS only (grey cloud).',
    godaddy: 'GoDaddy: Domain Portfolio > DNS > Add New Record. Host "@" for root, otherwise the prefix.',
    netlifydns: 'Netlify: Domains > DNS settings > Add new record.', squarespace: 'Squarespace: Domains > DNS > Custom records.',
    namecheap: 'Namecheap: Advanced DNS > Add new record. Host "@" for root.',
  }[st.dnsKey] || 'In the DNS provider: "@" (or blank) for the root, otherwise just the prefix (e.g. _dmarc).';
  const hdr = snip => (st.hostKey === 'netlify' ? 'Netlify: add to the _headers file in the site root and redeploy:\n' :
    st.hostKey === 'cloudflare' ? 'Cloudflare: Rules > Transform Rules > Modify Response Header:\n' :
    st.cms === 'WordPress' ? 'WordPress: host header settings, a security plugin or .htaccess:\n' : 'Add these response headers at the host/CDN:\n') + snip;
  const cert = st.hostKey === 'netlify' ? 'Netlify: Domain management > HTTPS > Verify DNS configuration, then Provision certificate. Right after a DNS change, wait 15-60 min and retry. Check no CAA record blocks letsencrypt.org.'
    : 'Re-issue/renew the certificate at the host; check DNS points at the host and no CAA record blocks the issuer.';
  const inc = { google: 'include:_spf.google.com', m365: 'include:spf.protection.outlook.com', zoho: 'include:zohomail.com', fastmail: 'include:spf.messagingengine.com' }[st.emailKey] || 'include:<email provider>';
  const dkim = { google: 'Google Admin > Apps > Google Workspace > Gmail > Authenticate email > Generate new record (2048-bit, selector google). Add TXT at google._domainkey, then Start authentication.',
    m365: 'Microsoft Defender > Email & collaboration > Policies > Email authentication settings > DKIM > enable; add the selector1/selector2 CNAMEs.' }[st.emailKey]
    || 'Enable DKIM signing in the email provider admin and publish its DNS record.';
  const policy = a.mx.some(m => m.endsWith('aspmx.l.google.com')) ? 'mx: aspmx.l.google.com\nmx: *.aspmx.l.google.com'
    : a.mx.some(m => m.endsWith('mail.protection.outlook.com')) ? 'mx: *.mail.protection.outlook.com' : a.mx.map(m => 'mx: ' + m).join('\n');
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return {
    https_works: cert, cert_valid: cert, cert_expiry: cert,
    https_redirect: 'Force a 301 from http:// to https://' + (st.hostKey === 'netlify' ? ' (automatic on Netlify once the certificate is active).' : '.'),
    host_redirect: 'Choose one primary host and 301 the other to it; canonical, og:url and sitemap must use it.' + (st.hostKey === 'netlify' ? ' Netlify: Domain management > set primary domain.' : ''),
    hsts: hdr('/*\n  Strict-Transport-Security: max-age=31536000; includeSubDomains'),
    sec_headers: hdr('/*\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: SAMEORIGIN\n  Referrer-Policy: strict-origin-when-cross-origin\n  Permissions-Policy: camera=(), microphone=(), geolocation=()'),
    csp: 'Optional: add a Content-Security-Policy, starting in Report-Only mode.', mixed: 'Change http:// asset URLs to https:// or relative paths.',
    caa: `Optional: CAA record at root, value 0 issue "letsencrypt.org". ${dnsHow}`, dnssec: 'Optional: enable DNSSEC at the registrar.',
    mx: 'No MX: lock the domain down with SPF "v=spf1 -all" and DMARC "v=DMARC1; p=reject;".',
    spf: `${dnsHow}\nOne TXT at root: v=spf1 ${inc} ~all (add includes for any other senders: newsletters, CRM, invoicing).`,
    spf_multi: `Merge into ONE v=spf1 record. ${dnsHow}`, spf_all: 'End SPF with ~all or -all.',
    dkim, dkim_weak: 'Rotate DKIM to 2048-bit. ' + dkim,
    dmarc: `${dnsHow}\nTXT at _dmarc: v=DMARC1; p=none; rua=mailto:<owner>@${d}\nAfter 1-2 weeks of clean reports move to p=quarantine, then p=reject.`,
    dmarc_policy: 'Monitor-only. After 1-2 weeks of reports showing only legitimate senders (check Xero, Mailchimp, CRM, forms), change to p=quarantine, later p=reject.',
    dmarc_rua: `Add rua=mailto:<owner>@${d} to the _dmarc record.`, dmarc_multi: 'Keep exactly one _dmarc TXT record.',
    mta_sts: (st.hostKey === 'netlify' ? 'Separate small Netlify project: mta-sts.txt + _redirects ("/.well-known/mta-sts.txt /mta-sts.txt 200"). CNAME mta-sts -> <project>.netlify.app, add the domain in that project, provision the certificate.\n'
      : `Serve the policy at https://mta-sts.${d}/.well-known/mta-sts.txt with a valid certificate.\n`) +
      `${dnsHow}\nTXT _mta-sts: v=STSv1; id=${today}\nTXT _smtp._tls: v=TLSRPTv1; rua=mailto:<owner>@${d}\nPolicy:\nversion: STSv1\nmode: testing\n${policy}\nmax_age: 86400`,
    mta_sts_fetch: `Policy not reachable over valid HTTPS. ${cert}`, mta_sts_mode: `After ~2 weeks clean, mode: enforce, max_age: 604800, redeploy and bump the _mta-sts id (e.g. ${today}).`,
    mta_sts_mx: `Policy mx lines must cover every MX:\n${policy}`, tlsrpt: `${dnsHow}\nTXT _smtp._tls: v=TLSRPTv1; rua=mailto:<owner>@${d}`,
    robots: `Add /robots.txt:\nUser-agent: *\nAllow: /\n\nSitemap: https://${host}/sitemap.xml`, robots_html: 'Serve a real text file at /robots.txt.',
    robots_all: 'Remove "Disallow: /" for User-agent: *.', ai_search_block: 'Remove the Disallow rules for these bots in robots.txt.',
    ai_train_block: 'Business choice; does not affect AI search answers.',
    ua_block: (st.cdn === 'Cloudflare' ? 'Cloudflare: Security > Bots: turn off "Block AI bots" / allow verified bots. ' : 'Check firewall / bot protection / security plugin. ') + 'Spoofed test requests can be blocked even when real bots pass; confirm in logs.',
    waf: 'Bot protection refuses cloud networks; make sure verified search and AI bots are allowlisted.',
    llms: 'Add /llms.txt: Markdown summary (# Name, summary, ## Services, ## Key pages with links, ## Contact).',
    sitemap: `Publish /sitemap.xml (absolute https://${host}/ URLs) and add a Sitemap: line to robots.txt.` + (st.cms === 'WordPress' ? ' WordPress: Yoast / Rank Math / core wp-sitemap.' : st.cms === 'Astro' ? ' Astro: @astrojs/sitemap.' : ''),
    sitemap_host: `Sitemap URLs must use https://${host}/`, sitemap_urls: 'List only final 200 URLs in the sitemap.',
    soft404: 'Return a real 404 status for missing pages' + (st.hostKey === 'netlify' ? ' (Netlify: 404.html in the site root).' : '.'),
    noindex: 'Remove noindex (meta robots / X-Robots-Tag) from pages that should rank.', pages: 'Site could not be read; check availability and bot protection.',
    title: 'Unique titles, ~30-65 characters.', desc: 'Unique meta descriptions, ~70-160 characters.',
    canonical: `<link rel="canonical" href="https://${host}/path/"> on every page.`, h1: 'Exactly one <h1> per page.', lang: 'Add <html lang="en-AU">.',
    og: 'Add og:title, og:description, og:image (1200x630), og:url, twitter:card.',
    jsonld: 'Add JSON-LD: Organization / LocalBusiness / ProfessionalService on home (name, url, logo, address, phone, email, sameAs) + WebSite; WebPage, BreadcrumbList, Service, FAQPage elsewhere. Validate at validator.schema.org.',
    entity: 'Add Organization / LocalBusiness JSON-LD on the home page.', jsonld_err: 'Fix the JSON-LD syntax; invalid blocks are ignored.',
    sameas: 'Add sameAs links (LinkedIn, Instagram, Facebook, Google Business Profile) to the Organization JSON-LD.',
    contact: 'Show email/phone and service area in plain HTML and in JSON-LD.',
    thin: 'Content is rendered by JavaScript; pre-render / server-render it (static build or SSR).',
    weight: 'Keep HTML under ~300 KB; move images, fonts and big inline CSS/JS into files.',
    base64: 'Move inline base64 images/fonts into /assets/ files with long cache headers.' + (st.hostKey === 'netlify' ? ' _headers: /assets/*  Cache-Control: public, max-age=31536000, immutable' : ''),
    speed: 'Use static hosting / CDN caching.', alt: 'Add alt text to content images.',
  };
}
export function reportHtml(a) {
  const s = summarise(a), fx = fixes(a);
  const groups = [['safety', 'Website safety'], ['email', 'Email protection'], ['access', 'Found by AI assistants'], ['understood', 'Understood by Google & AI'], ['readable', 'Easy for search engines to read']];
  const pill = { pass: 'Pass', warn: 'Improve', fail: 'Fix', info: 'Note' };
  const prio = c => c.status === 'fail' ? (c.weight >= 2 ? 1 : 2) : c.status === 'warn' ? (c.weight >= 3 ? 2 : 3) : 9;
  const top = a.checks.filter(c => prio(c) < 9).sort((x, y) => prio(x) - prio(y) || y.weight - x.weight);
  const row = c => `<div class="row"><span class="pill ${c.status}">${pill[c.status]}</span><div><b>${esc(c.title)}</b><p>${esc(c.detail)}</p>${c.status !== 'pass' && fx[c.key] ? `<details><summary>Fix</summary><pre>${esc(fx[c.key])}</pre></details>` : ''}</div></div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${esc(a.domain)} | Full website check</title><style>
:root{--ink:#0E0E0E;--muted:#5C5C5C;--line:#DADADA;--mist:#F1F1F1;--accent:#B91C1C;--pass:#15803D;--warn:#B45309;--fail:#B91C1C;--info:#475569}
*{box-sizing:border-box}body{margin:0;background:var(--mist);color:#262626;font:16px/1.5 "Source Sans 3",system-ui,sans-serif}
h1,h2,b{font-family:Montserrat,"Helvetica Neue",Arial,sans-serif;color:var(--ink)}.wrap{max-width:940px;margin:0 auto;padding:0 16px}
header{background:var(--ink);color:#fff;padding:32px 0}header h1{color:#fff;margin:0 0 6px;font-size:30px}header p{margin:0;color:#ccc}
.card{background:#fff;border:1px solid var(--line);padding:20px;margin:18px 0}.card h2{margin:0 0 8px;font-size:19px}
.row{display:grid;grid-template-columns:72px minmax(0,1fr);gap:12px;padding:10px 0;border-top:1px solid var(--line)}.row p{margin:2px 0 0;color:var(--muted);font-size:15px;overflow-wrap:anywhere}
.pill{font:700 11px Montserrat,sans-serif;letter-spacing:.06em;text-transform:uppercase;color:#fff;text-align:center;padding:5px 0;align-self:start}
.pill.pass{background:var(--pass)}.pill.warn{background:var(--warn)}.pill.fail{background:var(--fail)}.pill.info{background:var(--info)}
summary{cursor:pointer;color:var(--accent);font-weight:600;margin-top:6px}pre{white-space:pre-wrap;background:var(--mist);padding:10px;font:13px/1.5 ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
.big{font:800 44px Montserrat,sans-serif;color:var(--ink)}.meta{color:var(--muted);font-size:14px}
@media print{details{display:block}body{background:#fff}}</style></head><body>
<header><div class="wrap"><h1>${esc(a.domain)}</h1><p>Full website check · ${esc(a.checkedAt.slice(0, 16).replace('T', ' '))} UTC · ${a.ms} ms</p></div></header><main class="wrap">
<section class="card"><span class="big">${s.grade}</span> <span class="meta">${s.score}/100 · ${esc(s.headline)}</span>
<p class="meta">Host: ${esc(a.stack.host)}${a.stack.cms ? ' + ' + esc(a.stack.cms) : ''} · DNS: ${esc(a.stack.dns)} · Email: ${esc(a.stack.email)} · Primary host: ${esc(a.canon)}</p>
<h2>What the visitor saw</h2>${s.areas.map(x => `<p><b>${esc(x.name)}</b> (${x.status}): ${esc(x.line)}</p>`).join('')}</section>
<section class="card"><h2>Fix first</h2>${top.slice(0, 8).map(row).join('') || '<p>Nothing urgent.</p>'}</section>
${groups.map(([k, n]) => `<section class="card"><h2>${n}</h2>${a.checks.filter(c => c.area === k).map(row).join('')}</section>`).join('')}
<p class="meta">Passive check of public DNS, the TLS certificate and public pages. Generated for Fusion Media; not for distribution.</p></main>
<script>addEventListener('beforeprint',()=>document.querySelectorAll('details').forEach(d=>d.open=true))</script></body></html>`;
}
