/**
 * Test helpers.
 *
 * Each test file gets a complete application with its own in-memory database,
 * so tests never share state and can run in any order.
 */
import request from 'supertest';

import { createApp } from '../src/app.js';

export const silentLogger = {
  info() {},
  error() {},
  warn() {},
};

export const DEMO_USERS = {
  admin: { login: 'alice', password: 'Passw0rd!Alice' },
  user: { login: 'bob', password: 'Passw0rd!Bob' },
};

/**
 * @param {object} [overrides] config overrides
 */
export function makeApp(overrides = {}) {
  return createApp({
    config: {
      env: 'test',
      // Cheap scrypt parameters keep the suite fast; production uses 2^15.
      scryptCost: 1024,
      scryptBlockSize: 8,
      scryptParallelization: 1,
      jwtSecret: 'test-secret-that-is-long-enough-for-hs256-000000',
      accessTtlSeconds: 900,
      ...overrides,
    },
    databasePath: ':memory:',
    logger: silentLogger,
  });
}

/** Log in and return the raw response. */
export function login(app, { login: name, password }) {
  return request(app).post('/auth/login').send({ login: name, password });
}

/** Log in and return the access token, failing loudly if login did not work. */
export async function tokenFor(app, user = DEMO_USERS.admin) {
  const response = await login(app, user);
  if (response.status !== 200) {
    throw new Error(`login failed for ${user.login}: ${response.status} ${JSON.stringify(response.body)}`);
  }
  return response.body.access_token;
}

/** Authorization header object. */
export function bearer(token) {
  return { Authorization: `Bearer ${token}` };
}
