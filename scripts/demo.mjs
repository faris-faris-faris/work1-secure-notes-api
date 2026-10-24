#!/usr/bin/env node
/**
 * End-to-end walkthrough of the API.
 *
 * Every step prints the request, the status and the relevant part of the
 * response, and checks the expected security property. It is meant to be run
 * in a terminal and screenshotted: the transcript is the evidence.
 *
 * Usage: node scripts/demo.mjs [base-url]
 */
const BASE = (process.argv[2] || process.env.DEMO_BASE || 'http://127.0.0.1:3000').replace(/\/$/, '');

let passed = 0;
let failed = 0;

const color = (code, text) => `\u001b[${code}m${text}\u001b[0m`;
const bold = (text) => color('1', text);
const green = (text) => color('32', text);
const red = (text) => color('31', text);
const dim = (text) => color('2', text);

function check(label, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`${green('PASS')} ${label}`);
  } else {
    failed += 1;
    console.log(`${red('FAIL')} ${label}${detail ? `  ${dim(detail)}` : ''}`);
  }
}

async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: response.status, headers: response.headers, text, json };
}

function short(value, max = 90) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text) return '(empty)';
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function step(n, title) {
  console.log(`\n${bold(`[${n}] ${title}`)}`);
}

async function main() {
  console.log(bold('Campus Notes API — Work 1 walkthrough'));
  console.log(dim(`target ${BASE}\n`));

  step(1, 'GET /health (no authentication)');
  const health = await call('GET', '/health');
  console.log(`GET /health -> ${health.status} ${short(health.text, 60)}`);
  check('liveness probe returns 200', health.status === 200);

  step(2, 'POST /auth/login — wrong password');
  const wrong = await call('POST', '/auth/login', { body: { login: 'alice', password: 'not-the-password' } });
  console.log(`POST /auth/login (wrong) -> ${wrong.status} ${short(wrong.json?.error)}`);
  check('wrong password is refused with 401', wrong.status === 401);

  step(3, 'POST /auth/login — correct credentials');
  const login = await call('POST', '/auth/login', { body: { login: 'alice', password: 'Passw0rd!Alice' } });
  console.log(`POST /auth/login -> ${login.status} expires_in=${login.json?.expires_in} role=${login.json?.user?.role}`);
  const token = login.json?.access_token;
  const refresh = login.json?.refresh_token;
  check('JWT issued with a 15-minute lifetime', login.status === 200 && login.json.expires_in === 900);
  check('refresh token issued', typeof refresh === 'string' && refresh.length > 40);
  console.log(dim(`token: ${short(token, 48)}`));

  step(4, 'GET /api/data without a token');
  const noToken = await call('GET', '/api/data');
  console.log(`GET /api/data -> ${noToken.status} ${short(noToken.text, 80)}`);
  check('anonymous access is denied with 401', noToken.status === 401 && noToken.json?.error?.code === 'missing_token');

  step(5, 'GET /api/data with a forged token');
  const forged = await call('GET', '/api/data', { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.forged-signature' });
  console.log(`GET /api/data (forged) -> ${forged.status} ${short(forged.json?.error)}`);
  check('a token with a bad signature is rejected', forged.status === 401);

  step(6, 'GET /api/data with the real token');
  const feed = await call('GET', '/api/data', { token });
  console.log(`GET /api/data -> ${feed.status} total=${feed.json?.total} items=${feed.json?.items?.length}`);
  console.log(dim(`first item: ${short(feed.json?.items?.[0]?.title)}`));
  check('the feed is readable by an authenticated user', feed.status === 200 && feed.json.items.length > 0);

  step(7, 'POST /api/notes — create (the "own method")');
  const created = await call('POST', '/api/notes', {
    token,
    body: { title: 'Lab 1 security review', body: 'All checks passed on the patched image.', category: 'general' },
  });
  console.log(`POST /api/notes -> ${created.status} id=${created.json?.id} author=${created.json?.author?.login}`);
  check('authenticated creation returns 201', created.status === 201);

  step(8, 'PATCH someone else\'s note — broken access control');
  const bob = await call('POST', '/auth/login', { body: { login: 'bob', password: 'Passw0rd!Bob' } });
  const patched = await call('PATCH', `/api/notes/${created.json.id}`, {
    token: bob.json.access_token,
    body: { body: 'defaced by another user' },
  });
  console.log(`PATCH /api/notes/${created.json.id} as bob -> ${patched.status} ${short(patched.json?.error)}`);
  check('another user cannot edit the note (403)', patched.status === 403);

  step(9, 'POST /auth/login with a SQL injection payload');
  const sqliLogin = await call('POST', '/auth/login', { body: { login: "alice' OR '1'='1", password: 'x' } });
  console.log(`POST /auth/login (SQLi) -> ${sqliLogin.status} ${short(sqliLogin.json?.error)}`);
  check('SQL injection cannot bypass authentication', sqliLogin.status === 401);

  step(10, 'GET /api/data?q=… with a SQL injection payload');
  const sqliSearch = await call('GET', `/api/data?q=${encodeURIComponent("' OR 1=1 --")}`, { token });
  console.log(`GET /api/data?q=' OR 1=1 -- -> ${sqliSearch.status} total=${sqliSearch.json?.total}`);
  check('the payload is treated as literal text (0 matches)', sqliSearch.status === 200 && sqliSearch.json.total === 0);

  step(11, 'POST /api/notes with a stored-XSS payload');
  const xss = await call('POST', '/api/notes', {
    token,
    body: { title: 'XSS probe', body: '<script>alert("XSS")</script>', category: 'general' },
  });
  console.log(`stored body: ${short(xss.json?.body, 100)}`);
  check('the script tag is HTML-escaped on output', xss.status === 201 && xss.text.includes('&lt;script&gt;') && !xss.text.includes('<script>'));

  step(12, 'POST /auth/refresh — rotation and reuse detection');
  const rotated = await call('POST', '/auth/refresh', { body: { refresh_token: refresh } });
  console.log(`POST /auth/refresh -> ${rotated.status} new refresh token differs=${rotated.json?.refresh_token !== refresh}`);
  check('the refresh token is rotated', rotated.status === 200 && rotated.json.refresh_token !== refresh);
  const replay = await call('POST', '/auth/refresh', { body: { refresh_token: refresh } });
  console.log(`replay the old refresh token -> ${replay.status} ${short(replay.json?.error)}`);
  check('reuse revokes the family (401 token_reuse)', replay.status === 401 && replay.json.error.code === 'token_reuse');

  step(13, 'PATCH + DELETE the note as its owner');
  const own = await call('PATCH', `/api/notes/${created.json.id}`, { token, body: { category: 'exam' } });
  console.log(`PATCH own note -> ${own.status} category=${own.json?.category}`);
  const removed = await call('DELETE', `/api/notes/${created.json.id}`, { token });
  console.log(`DELETE own note -> ${removed.status}`);
  check('owner update and delete succeed', own.status === 200 && removed.status === 204);

  step(14, 'Brute-force lockout');
  let last;
  for (let i = 0; i < 6; i += 1) {
    last = await call('POST', '/auth/login', { body: { login: 'bob', password: 'wrong' } });
  }
  console.log(`6th failed login -> ${last.status} Retry-After=${last.headers.get('retry-after')} s`);
  check('repeated failures return 429 with Retry-After', last.status === 429 && Number(last.headers.get('retry-after')) > 0);

  console.log(`\n${bold('RESULT:')} ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(`demo aborted: ${error.message}`);
  process.exit(2);
});
