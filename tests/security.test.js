import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import request from 'supertest';

import { loadConfig } from '../src/config.js';
import { makeApp, bearer, DEMO_USERS, tokenFor } from './helpers.js';

describe('HTTP hardening', () => {
  let instance;
  let app;
  let token;

  before(async () => {
    instance = makeApp();
    app = instance.app;
    token = await tokenFor(app, DEMO_USERS.admin);
  });
  after(() => instance.close());

  it('sets the security headers on success responses', async () => {
    const response = await request(app).get('/health');
    assert.equal(response.status, 200);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.equal(response.headers['x-frame-options'], 'DENY');
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.match(response.headers['content-security-policy'], /default-src 'none'/);
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.match(response.headers['cross-origin-resource-policy'], /same-site/);
  });

  it('sets the same headers on errors and 404s', async () => {
    const unauthorized = await request(app).get('/api/data');
    assert.equal(unauthorized.status, 401);
    assert.equal(unauthorized.headers['x-content-type-options'], 'nosniff');
    assert.equal(unauthorized.headers['cache-control'], 'no-store');

    const missing = await request(app).get('/api/nope').set(bearer(token));
    assert.equal(missing.status, 404);
    assert.equal(missing.body.error.code, 'not_found');
    assert.equal(missing.headers['x-content-type-options'], 'nosniff');
  });

  it('does not advertise the framework', async () => {
    const response = await request(app).get('/health');
    assert.equal(response.headers['x-powered-by'], undefined);
  });

  it('does not require authentication for the liveness probe', async () => {
    const response = await request(app).get('/health');
    assert.equal(response.status, 200);
    assert.equal(response.body.status, 'ok');
  });

  it('returns a JSON 404 for an unknown endpoint', async () => {
    const response = await request(app).get('/definitely-not-here');
    assert.equal(response.status, 404);
    assert.equal(response.body.error.code, 'not_found');
  });

  it('does not allow an unsupported method on an existing path', async () => {
    const response = await request(app).get('/api/notes');
    assert.equal(response.status, 404);
  });
});

describe('configuration guards', () => {
  const original = { ...process.env };

  after(() => {
    process.env = { ...original };
  });

  it('refuses to start in production without a strong JWT secret', () => {
    process.env = { ...original, NODE_ENV: 'production', SEED_DEMO_USERS: 'false' };
    delete process.env.JWT_SECRET;
    assert.throws(() => loadConfig(), /JWT_SECRET/);

    process.env.JWT_SECRET = 'too-short';
    assert.throws(() => loadConfig(), /JWT_SECRET/);

    process.env.JWT_SECRET = 'a'.repeat(64);
    const config = loadConfig();
    assert.equal(config.env, 'production');
    assert.equal(config.seedDemoUsers, false);
  });

  it('refuses demo users in production', () => {
    process.env = { ...original, NODE_ENV: 'production', SEED_DEMO_USERS: 'true' };
    process.env.JWT_SECRET = 'a'.repeat(64);
    assert.throws(() => loadConfig(), /SEED_DEMO_USERS/);
  });

  it('generates a fresh random secret in development', () => {
    process.env = { ...original };
    delete process.env.NODE_ENV;
    delete process.env.JWT_SECRET;
    assert.notEqual(loadConfig().jwtSecret, loadConfig().jwtSecret);
  });

  it('rejects an invalid numeric setting', () => {
    process.env = { ...original };
    delete process.env.NODE_ENV;
    delete process.env.JWT_SECRET;
    process.env.PORT = 'not-a-port';
    assert.throws(() => loadConfig(), /PORT/);
  });
});
