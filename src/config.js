/**
 * Configuration is read once, from the environment, and validated.
 *
 * The guiding rule: a development default may be convenient, but a production
 * process must refuse to start with a default secret. That is the difference
 * between "it works on my laptop" and "it is safe to deploy".
 */
import crypto from 'node:crypto';
import path from 'node:path';

const TRUE = new Set(['1', 'true', 'yes', 'on']);

function intFromEnv(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max} (got ${JSON.stringify(raw)})`);
  }
  return value;
}

function boolFromEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return TRUE.has(String(raw).toLowerCase());
}

/**
 * @param {object} [overrides] test-only overrides; production code passes nothing
 */
export function loadConfig(overrides = {}) {
  const env = process.env.NODE_ENV || 'development';

  const config = {
    env,
    port: intFromEnv('PORT', 3000, { min: 1, max: 65535 }),
    host: process.env.HOST || '127.0.0.1',
    databasePath: process.env.DATABASE_PATH || path.join(process.cwd(), 'data', 'campus-notes.db'),

    // Signing material. A random per-boot key is fine for a throwaway demo and
    // deliberately painful in production: every restart would invalidate all
    // tokens, and a multi-instance deployment would reject each other's tokens.
    jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(48).toString('base64url'),
    jwtIssuer: process.env.JWT_ISSUER || 'campus-notes-api',
    jwtAudience: process.env.JWT_AUDIENCE || 'campus-notes-client',
    accessTtlSeconds: intFromEnv('ACCESS_TTL_SECONDS', 900, { min: 60, max: 3600 }),
    clockToleranceSeconds: intFromEnv('JWT_CLOCK_TOLERANCE_SECONDS', 5, { min: 0, max: 60 }),

    refreshTtlSeconds: intFromEnv('REFRESH_TTL_SECONDS', 7 * 24 * 3600, { min: 300, max: 30 * 24 * 3600 }),

    // scrypt cost. N must be a power of two. 2^15 keeps a login around 80-120 ms
    // on a laptop, which is slow for an attacker and invisible for a user.
    scryptCost: intFromEnv('SCRYPT_COST', 32768, { min: 1024, max: 1 << 20 }),
    scryptBlockSize: intFromEnv('SCRYPT_BLOCK_SIZE', 8, { min: 1, max: 32 }),
    scryptParallelization: intFromEnv('SCRYPT_PARALLELIZATION', 1, { min: 1, max: 16 }),

    loginMaxAttempts: intFromEnv('LOGIN_MAX_ATTEMPTS', 5, { min: 1, max: 100 }),
    loginWindowSeconds: intFromEnv('LOGIN_WINDOW_SECONDS', 300, { min: 10, max: 3600 }),

    maxBodyBytes: intFromEnv('MAX_BODY_BYTES', 64 * 1024, { min: 1024, max: 1024 * 1024 }),
    maxPageSize: intFromEnv('MAX_PAGE_SIZE', 50, { min: 1, max: 200 }),

    // Set to true when the API runs behind a reverse proxy you control, so
    // X-Forwarded-For can be trusted for rate limiting.
    trustProxy: boolFromEnv('TRUST_PROXY', false),

    seedDemoUsers: boolFromEnv('SEED_DEMO_USERS', true),
  };

  if (env === 'production') {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      throw new Error('JWT_SECRET (>= 32 characters) is required when NODE_ENV=production');
    }
    if (process.env.SEED_DEMO_USERS && TRUE.has(process.env.SEED_DEMO_USERS.toLowerCase())) {
      throw new Error('SEED_DEMO_USERS must be false in production');
    }
    config.seedDemoUsers = false;
    config.trustProxy = true;
  }

  return { ...config, ...overrides };
}
