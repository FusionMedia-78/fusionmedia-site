// GET /api/report?domain=example.com   (password protected, for Dave)
// Full technical report with stack-aware fixes. Add &format=json for raw data.
// Set REPORT_PASSWORD in Netlify: Project configuration > Environment variables.
import crypto from 'node:crypto';
import { normaliseDomain, runAudit, reportHtml } from '../lib/audit.mjs';

const env = k => globalThis.Netlify?.env?.get(k) ?? process.env[k];

export default async (req) => {
  const pw = env('REPORT_PASSWORD');
  if (!pw) return new Response('Reports are switched off: REPORT_PASSWORD is not set in Netlify.', { status: 503 });

  const auth = req.headers.get('authorization') || '';
  const given = auth.startsWith('Basic ') ? Buffer.from(auth.slice(6), 'base64').toString('utf8').split(':').slice(1).join(':') : '';
  const a = crypto.createHash('sha256').update(given).digest(), b = crypto.createHash('sha256').update(pw).digest();
  if (!crypto.timingSafeEqual(a, b)) {
    return new Response('Password required', { status: 401, headers: { 'www-authenticate': 'Basic realm="Fusion Media reports", charset="UTF-8"' } });
  }

  const url = new URL(req.url);
  const domain = normaliseDomain(url.searchParams.get('domain'));
  if (!domain) return new Response('Add ?domain=example.com to the address.', { status: 400 });

  const audit = await runAudit(domain, { deep: true, budget: 9000 });
  const headers = { 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' };
  if (url.searchParams.get('format') === 'json') {
    return new Response(JSON.stringify(audit, null, 1), { headers: { ...headers, 'content-type': 'application/json; charset=utf-8' } });
  }
  return new Response(reportHtml(audit), { headers: { ...headers, 'content-type': 'text/html; charset=utf-8' } });
};

export const config = { path: '/api/report' };
