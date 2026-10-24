import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import request from 'supertest';

import { bearer, DEMO_USERS, makeApp, tokenFor } from './helpers.js';

describe('notes API', () => {
  let instance;
  let app;
  let adminToken;
  let userToken;
  let otherToken;
  let bobNoteId;

  before(async () => {
    instance = makeApp();
    app = instance.app;
    adminToken = await tokenFor(app, DEMO_USERS.admin);
    userToken = await tokenFor(app, DEMO_USERS.user);
    instance.repo.createUser({ login: 'carol', displayName: 'Carol', password: 'CarolPassw0rd!' });
    otherToken = await tokenFor(app, { login: 'carol', password: 'CarolPassw0rd!' });

    // Bob's note is the object other users must not be able to modify.
    const created = await request(app)
      .post('/api/notes')
      .set(bearer(userToken))
      .send({ title: 'Bob private draft', body: 'Only Bob (and an admin) may edit this.', category: 'general' });
    assert.equal(created.status, 201);
    bobNoteId = created.body.id;
  });
  after(() => instance.close());

  it('returns the feed to an authenticated user', async () => {
    const response = await request(app).get('/api/data').set(bearer(userToken));
    assert.equal(response.status, 200);
    assert.equal(response.body.total, 4);
    assert.equal(response.body.items.length, 4);
    assert.equal(response.body.limit, 20);
    assert.equal(response.body.offset, 0);
    assert.equal(response.body.sort, 'newest');
    assert.equal(response.headers['content-type'], 'application/json; charset=utf-8');
    // Newest first.
    assert.equal(response.body.items[0].title, 'Bob private draft');
  });

  it('paginates deterministically', async () => {
    const page1 = await request(app).get('/api/data?limit=2&offset=0').set(bearer(userToken));
    const page2 = await request(app).get('/api/data?limit=2&offset=2').set(bearer(userToken));
    assert.equal(page1.status, 200);
    assert.equal(page2.status, 200);
    assert.equal(page1.body.items.length, 2);
    assert.equal(page2.body.items.length, 2);
    const ids = new Set([...page1.body.items, ...page2.body.items].map((item) => item.id));
    assert.equal(ids.size, 4);
  });

  it('sorts only by whitelisted columns', async () => {
    const byTitle = await request(app).get('/api/data?sort=title').set(bearer(userToken));
    assert.equal(byTitle.status, 200);
    const titles = byTitle.body.items.map((item) => item.title);
    assert.deepEqual(titles, [...titles].sort((a, b) => a.localeCompare(b)));

    const rejected = await request(app)
      .get('/api/data?sort=id%3B%20DROP%20TABLE%20notes')
      .set(bearer(userToken));
    assert.equal(rejected.status, 400);
    // The table is still there.
    assert.equal(instance.repo.countNotes(), 4);
  });

  it('treats a SQL injection payload in the search term as literal text', async () => {
    for (const payload of ["' OR 1=1 --", "' UNION SELECT * FROM users --", "'; DROP TABLE notes; --"]) {
      const response = await request(app)
        .get('/api/data')
        .query({ q: payload })
        .set(bearer(userToken));
      assert.equal(response.status, 200, payload);
      assert.equal(response.body.total, 0, `${payload} must not match anything`);
    }
    assert.equal(instance.repo.countNotes(), 4);
  });

  it('escapes LIKE wildcards so "%" is a literal character', async () => {
    const created = await request(app)
      .post('/api/notes')
      .set(bearer(userToken))
      .send({ title: 'Attendance rule', body: 'Students need 100% attendance to sit the exam.', category: 'exam' });
    assert.equal(created.status, 201);

    const percent = await request(app).get('/api/data').query({ q: '%' }).set(bearer(userToken));
    assert.equal(percent.status, 200);
    assert.equal(percent.body.total, 1);
    assert.equal(percent.body.items[0].title, 'Attendance rule');

    const underscore = await request(app).get('/api/data').query({ q: '_' }).set(bearer(userToken));
    assert.equal(underscore.body.total, 0);
  });

  it('filters by category', async () => {
    const response = await request(app).get('/api/data?category=exam').set(bearer(userToken));
    assert.equal(response.status, 200);
    assert.ok(response.body.items.every((item) => item.category === 'exam'));
  });

  it('rejects unknown query parameters', async () => {
    const response = await request(app).get('/api/data?debug=1').set(bearer(userToken));
    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'validation_error');
  });

  it('creates a note and returns 201 with a Location header', async () => {
    const response = await request(app)
      .post('/api/notes')
      .set(bearer(adminToken))
      .send({ title: 'Lab 1 submission', body: 'Upload the PDF before Friday.', category: 'general' });
    assert.equal(response.status, 201);
    assert.equal(response.headers.location, `/api/notes/${response.body.id}`);
    assert.equal(response.body.author.login, 'alice');
    assert.equal(response.body.author.role, undefined);
  });

  it('rejects invalid and unknown fields on create', async () => {
    const cases = [
      [{ body: 'no title', category: 'general' }, 'title'],
      [{ title: 'x', body: 'too short title', category: 'general' }, 'title'],
      [{ title: 'Valid title', body: 'x', category: 'nonsense' }, 'category'],
      [{ title: 'Valid title', body: 'x', category: 'general', author_id: 1 }, '(body)'],
    ];
    for (const [payload, field] of cases) {
      const response = await request(app).post('/api/notes').set(bearer(adminToken)).send(payload);
      assert.equal(response.status, 400, JSON.stringify(payload));
      assert.ok(
        response.body.error.details.some((detail) => detail.field === field),
        `expected a detail for ${field}, got ${JSON.stringify(response.body.error.details)}`,
      );
    }
  });

  it('rejects control characters in text fields', async () => {
    const response = await request(app)
      .post('/api/notes')
      .set(bearer(adminToken))
      .send({ title: 'Bad\u001btitle', body: 'escape sequence', category: 'general' });
    assert.equal(response.status, 400);
  });

  it('lets the author edit a note', async () => {
    const response = await request(app)
      .patch(`/api/notes/${bobNoteId}`)
      .set(bearer(userToken))
      .send({ body: 'Updated by the author.' });
    assert.equal(response.status, 200);
    assert.equal(response.body.body, 'Updated by the author.');
  });

  it('forbids editing someone else\'s note (IDOR)', async () => {
    const response = await request(app)
      .patch(`/api/notes/${bobNoteId}`)
      .set(bearer(otherToken))
      .send({ body: 'defaced' });
    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, 'forbidden');
  });

  it('lets an administrator moderate any note', async () => {
    const response = await request(app)
      .patch(`/api/notes/${bobNoteId}`)
      .set(bearer(adminToken))
      .send({ category: 'event' });
    assert.equal(response.status, 200);
    assert.equal(response.body.category, 'event');
  });

  it('returns 404 for a note that does not exist or a non-numeric id', async () => {
    for (const id of ['999999', '1%20OR%201=1', 'abc']) {
      const response = await request(app).get(`/api/notes/${id}`).set(bearer(userToken));
      assert.equal(response.status, 404, id);
    }
  });

  it('deletes a note for its author and then 404s', async () => {
    const created = await request(app)
      .post('/api/notes')
      .set(bearer(userToken))
      .send({ title: 'Temporary note', body: 'delete me', category: 'general' });
    const id = created.body.id;

    const forbiddenDelete = await request(app).delete(`/api/notes/${id}`).set(bearer(otherToken));
    assert.equal(forbiddenDelete.status, 403);

    const deleted = await request(app).delete(`/api/notes/${id}`).set(bearer(userToken));
    assert.equal(deleted.status, 204);

    const gone = await request(app).get(`/api/notes/${id}`).set(bearer(userToken));
    assert.equal(gone.status, 404);
  });

  it('escapes stored XSS payloads on output while storing the raw text', async () => {
    const payloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      'javascript:alert(document.cookie)',
      '<iframe src="https://evil.example"></iframe>',
    ];

    for (const payload of payloads) {
      const created = await request(app)
        .post('/api/notes')
        .set(bearer(userToken))
        .send({ title: 'XSS test', body: payload, category: 'general' });
      assert.equal(created.status, 201);
      assert.ok(!created.text.includes('<script'), 'raw script tag leaked');
      assert.ok(!created.text.includes('<img src=x'), 'raw img tag leaked');
      assert.ok(!created.text.includes('<svg onload'), 'raw svg tag leaked');
      assert.ok(!created.text.includes('<iframe'), 'raw iframe tag leaked');
      // The escaping is reversible: the client receives HTML entities.
      if (payload.startsWith('<script')) {
        assert.ok(created.body.body.includes('&lt;script&gt;'));
      }
    }

    // The database keeps the original text: escaping happens at the boundary,
    // so the data itself is not corrupted.
    const row = instance.repo.db
      .prepare('SELECT body FROM notes WHERE body LIKE ?')
      .get('%<script>alert("XSS")</script>%');
    assert.ok(row, 'raw payload should be stored');
  });

  it('reports the identity carried by the token', async () => {
    const response = await request(app).get('/api/me').set(bearer(adminToken));
    assert.equal(response.status, 200);
    assert.equal(response.body.login, 'alice');
    assert.equal(response.body.role, 'admin');
    assert.equal(response.body.token.issuer, 'campus-notes-api');
    assert.ok(new Date(response.body.token.expires_at) > new Date());
    assert.equal(typeof response.body.token.token_id, 'string');
  });

  it('rejects an oversized body with 413', async () => {
    const response = await request(app)
      .post('/api/notes')
      .set(bearer(userToken))
      .send({ title: 'Huge', body: 'A'.repeat(70 * 1024), category: 'general' });
    assert.equal(response.status, 413);
    assert.equal(response.body.error.code, 'payload_too_large');
  });

  it('rejects malformed JSON with 400', async () => {
    const response = await request(app)
      .post('/api/notes')
      .set(bearer(userToken))
      .set('Content-Type', 'application/json')
      .send('{"title": "broken",');
    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'invalid_json');
  });
});
