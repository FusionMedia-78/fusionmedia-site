// POST /api/scan  { domain }  ->  plain-English summary only (grade, five areas, one line each).
// The technical detail never leaves the server.
import { normaliseDomain, runAudit, summarise } from '../lib/audit.mjs';

const recent = new Map(); // ip -> [timestamps]   (soft limit, per function instance)
const cache = new Map();  // domain -> { t, value }
const LIMIT = 12, WINDOW = 10 * 60 * 1000, TTL = 10 * 60 * 1000;

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex' },
});

export default async (req, context) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  let body = {};
  try { body = await req.json(); } catch { /* empty */ }
  const domain = normaliseDomain(body.domain);
  if (!domain) return json({ error: 'Please enter a website address, like yourbusiness.com.au' }, 400);

  const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'unknown';
  const now = Date.now();
  const hits = (recent.get(ip) || []).filter(t => now - t < WINDOW);
  if (hits.length >= LIMIT) return json({ error: 'That’s a lot of checks in a short time. Please try again in a few minutes.' }, 429);
  recent.set(ip, [...hits, now]);

  const hit = cache.get(domain);
  if (hit && now - hit.t < TTL) return json(hit.value);

  try {
    const audit = await runAudit(domain);
    if (!audit.reachable) {
      return json({ error: `We couldn’t reach ${domain}. Check the address is right and the site is live, then try again.` }, 422);
    }
    const value = summarise(audit);
    cache.set(domain, { t: now, value });
    return json(value);
  } catch {
    return json({ error: 'Something went wrong running the check. Please try again.' }, 500);
  }
};

export const config = { path: '/api/scan' };
