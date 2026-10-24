import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import request from 'supertest';

import { bearer, DEMO_USERS, login, makeApp } from './helpers.js';

describe('refresh-token sessions', () => {
  let instance;
  let app;

  before(() => {
    instance = makeApp();
    app = instance.app;
  });
  after(() => instance.close());

  it('rotates the refresh token on every use', async () => {
    const first = await login(app, DEMO_USERS.admin);
    const rotated = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: first.body.refresh_token });

    assert.equal(rotated.status, 200);
    assert.notEqual(rotated.body.refresh_token, first.body.refresh_token);
    assert.notEqual(rotated.body.access_token, first.body.access_token);
    assert.equal(rotated.body.user.login, 'alice');

    // The new access token works.
    const me = await request(app).get('/api/me').set(bearer(rotated.body.access_token));
    assert.equal(me.status, 200);
    assert.equal(me.body.login, 'alice');
  });

  it('revokes the whole family when a rotated token is replayed', async () => {
    const session = await login(app, DEMO_USERS.user);
    const refreshed = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: session.body.refresh_token });
    assert.equal(refreshed.status, 200);

    const replay = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: session.body.refresh_token });
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error.code, 'token_reuse');

    // The legitimate successor is dead too: the attacker cannot keep the
    // session alive after the reuse is detected.
    const successor = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: refreshed.body.refresh_token });
    assert.equal(successor.status, 401);
    assert.equal(successor.body.error.code, 'invalid_token');
  });

  it('rejects an unknown or malformed refresh token', async () => {
    const unknown = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: 'x'.repeat(64) });
    assert.equal(unknown.status, 401);
    assert.equal(unknown.body.error.code, 'invalid_token');

    const malformed = await request(app).post('/auth/refresh').send({ refresh_token: 'short' });
    assert.equal(malformed.status, 400);
  });

  it('rejects an expired refresh token', async () => {
    const session = await login(app, DEMO_USERS.admin);
    instance.repo.db
      .prepare('UPDATE refresh_tokens SET expires_at = ? WHERE user_id = ?')
      .run(new Date(Date.now() - 60_000).toISOString(), 1);

    const response = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: session.body.refresh_token });
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, 'token_expired');
  });

  it('revokes the session on logout', async () => {
    const session = await login(app, DEMO_USERS.admin);
    const logout = await request(app)
      .post('/auth/logout')
      .send({ refresh_token: session.body.refresh_token });
    assert.equal(logout.status, 204);

    const refresh = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: session.body.refresh_token });
    assert.equal(refresh.status, 401);
    assert.equal(refresh.body.error.code, 'invalid_token');
  });
});
