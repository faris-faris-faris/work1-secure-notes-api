import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import jwt from 'jsonwebtoken';
import request from 'supertest';

import { bearer, DEMO_USERS, login, makeApp } from './helpers.js';
import { escapeHtml, hashPassword, verifyPassword } from '../src/security.js';

describe('authentication', () => {
  let instance;
  let app;

  before(() => {
    instance = makeApp({ loginMaxAttempts: 4 });
    app = instance.app;
  });
  after(() => instance.close());

  it('issues a JWT and a refresh token for valid credentials', async () => {
    const response = await login(app, DEMO_USERS.admin);
    assert.equal(response.status, 200);
    assert.equal(response.body.token_type, 'Bearer');
    assert.equal(response.body.expires_in, 900);
    assert.equal(response.body.user.login, 'alice');
    assert.equal(response.body.user.role, 'admin');
    assert.equal(typeof response.body.refresh_token, 'string');
    assert.ok(response.body.refresh_token.length >= 40);

    const parts = response.body.access_token.split('.');
    assert.equal(parts.length, 3);
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    assert.deepEqual(header, { alg: 'HS256', typ: 'JWT' });
  });

  it('accepts the login case-insensitively', async () => {
    const response = await login(app, { login: 'ALICE', password: DEMO_USERS.admin.password });
    assert.equal(response.status, 200);
    assert.equal(response.body.user.login, 'alice');
  });

  it('rejects a wrong password with 401', async () => {
    const response = await login(app, { login: 'alice', password: 'wrong-password' });
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'invalid_credentials');
    assert.match(response.headers['www-authenticate'], /Bearer/);
  });

  it('answers unknown user and wrong password identically (no enumeration)', async () => {
    const unknown = await login(app, { login: 'nobody', password: 'whatever-123' });
    const wrong = await login(app, { login: 'bob', password: 'whatever-123' });
    assert.equal(unknown.status, 401);
    assert.equal(wrong.status, 401);
    assert.deepEqual(unknown.body, wrong.body);
  });

  it('rejects a missing field with a validation error', async () => {
    const response = await request(app).post('/auth/login').send({ login: 'alice' });
    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'validation_error');
    assert.ok(response.body.error.details.some((d) => d.field === 'password'));
  });

  it('rejects unknown extra fields (mass assignment guard)', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({ login: 'alice', password: 'x', role: 'admin' });
    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'validation_error');
  });

  it('denies a protected endpoint without a token', async () => {
    const response = await request(app).get('/api/data');
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'missing_token');
  });

  it('denies a malformed Authorization header', async () => {
    const response = await request(app).get('/api/data').set('Authorization', 'Token abc');
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'missing_token');
  });

  it('denies a token signed with another key', async () => {
    const forged = jwt.sign({ sub: '1', role: 'admin' }, 'attacker-secret', {
      algorithm: 'HS256',
      issuer: instance.config.jwtIssuer,
      audience: instance.config.jwtAudience,
    });
    const response = await request(app).get('/api/data').set(bearer(forged));
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'invalid_token');
  });

  it('denies an unsigned (alg: none) token', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString('base64url');
    const response = await request(app).get('/api/data').set(bearer(`${header}.${payload}.`));
    assert.equal(response.status, 401);
  });

  it('denies an expired token', async () => {
    const expired = jwt.sign(
      { sub: '1', role: 'admin' },
      instance.config.jwtSecret,
      {
        algorithm: 'HS256',
        issuer: instance.config.jwtIssuer,
        audience: instance.config.jwtAudience,
        expiresIn: -30,
      },
    );
    const response = await request(app).get('/api/data').set(bearer(expired));
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'token_expired');
  });

  it('denies a token issued for another audience', async () => {
    const foreign = jwt.sign(
      { sub: '1' },
      instance.config.jwtSecret,
      { algorithm: 'HS256', issuer: instance.config.jwtIssuer, audience: 'someone-else', expiresIn: 60 },
    );
    const response = await request(app).get('/api/data').set(bearer(foreign));
    assert.equal(response.status, 401);
  });

  it('stops working after the account is deleted', async () => {
    const user = instance.repo.createUser({ login: 'temp', displayName: 'Temp', password: 'TempPassw0rd!' });
    const response = await login(app, { login: 'temp', password: 'TempPassw0rd!' });
    assert.equal(response.status, 200);
    instance.repo.db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    const after = await request(app).get('/api/data').set(bearer(response.body.access_token));
    assert.equal(after.status, 401);
    assert.equal(after.body.error.code, 'invalid_token');
  });

  it('locks out after the configured number of failed attempts', async () => {
    instance.limiter.clear(); // earlier tests also failed logins for bob
    const attempt = () => login(app, { login: 'bob', password: 'wrong' });
    for (let i = 0; i < 4; i += 1) {
      const response = await attempt();
      assert.equal(response.status, 401, `attempt ${i + 1} should be 401`);
    }
    const blocked = await attempt();
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers['retry-after']) >= 1);
    // Even the correct password is refused while the window is open.
    const correct = await login(app, DEMO_USERS.user);
    assert.equal(correct.status, 429);
  });

  it('never stores the password in plaintext', async () => {
    const row = instance.repo.findUserByLogin('alice');
    assert.ok(row.password_hash.startsWith('scrypt$'));
    assert.ok(!row.password_hash.includes('Passw0rd!Alice'));
    assert.equal(row.role, 'admin');
  });
});

describe('password hashing primitives', () => {
  const params = { cost: 1024, blockSize: 8, parallelization: 1 };

  it('produces a unique salt per hash', () => {
    const a = hashPassword('same-password', params);
    const b = hashPassword('same-password', params);
    assert.notEqual(a, b);
    assert.ok(verifyPassword('same-password', a));
    assert.ok(verifyPassword('same-password', b));
  });

  it('rejects a wrong password and malformed hashes', () => {
    const hash = hashPassword('correct horse battery staple', params);
    assert.equal(verifyPassword('incorrect', hash), false);
    assert.equal(verifyPassword('x', 'not-a-hash'), false);
    assert.equal(verifyPassword('x', ''), false);
    assert.equal(verifyPassword('x', 'scrypt$1$2$3$4'), false);
  });

  it('escapes the HTML-significant characters', () => {
    assert.equal(escapeHtml('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
    assert.equal(escapeHtml("a'b`c"), 'a&#39;b&#96;c');
    assert.equal(escapeHtml('plain text'), 'plain text');
  });
});
