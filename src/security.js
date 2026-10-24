/**
 * Security primitives.
 *
 * Everything here assumes the input is hostile until proven otherwise:
 * password hashing, token issuing/verification, output encoding, and the login
 * rate limiter.
 */
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { unauthorized, rateLimited } from './errors.js';

// ---------------------------------------------------------------------------
// Passwords: scrypt (memory-hard, in the standard library, no native build)
// ---------------------------------------------------------------------------

const SCRYPT_PREFIX = 'scrypt';

/**
 * Hash a password with a fresh random salt.
 *
 * scrypt is memory-hard: raising N raises both time *and* memory for an
 * offline attacker, which is exactly what a GPU/ASIC farm is bad at. The
 * parameters are exported with the hash so a future cost increase can be
 * rolled out without invalidating existing rows.
 *
 * @param {string} password
 * @param {{cost:number, blockSize:number, parallelization:number}} params
 * @returns {string} `scrypt$N$r$p$salt$hash`
 */
export function hashPassword(password, { cost, blockSize, parallelization }) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password.normalize('NFKC'), salt, 32, {
    N: cost,
    r: blockSize,
    p: parallelization,
    maxmem: 256 * cost * blockSize,
  });
  return [
    SCRYPT_PREFIX,
    cost,
    blockSize,
    parallelization,
    salt.toString('base64url'),
    derived.toString('base64url'),
  ].join('$');
}

/**
 * Verify a password against a stored hash in constant time.
 *
 * Returns false for malformed rows instead of throwing: a corrupted hash must
 * not become a 500 that tells an attacker which account is broken.
 *
 * @param {string} password
 * @param {string} stored
 * @returns {boolean}
 */
export function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$');
    if (parts.length !== 6 || parts[0] !== SCRYPT_PREFIX) return false;
    const [, n, r, p, saltB64, hashB64] = parts;
    const cost = Number(n);
    const blockSize = Number(r);
    const parallelization = Number(p);
    if (![cost, blockSize, parallelization].every(Number.isInteger)) return false;

    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(hashB64, 'base64url');
    const actual = crypto.scryptSync(String(password).normalize('NFKC'), salt, expected.length, {
      N: cost,
      r: blockSize,
      p: parallelization,
      maxmem: 256 * cost * blockSize,
    });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/**
 * A hash that costs the same as a real one, for logins against unknown users.
 * Without it, "unknown user" returns in 1 ms and "wrong password" in 100 ms,
 * which is a usable account-enumeration oracle.
 */
export function dummyVerify(password, config) {
  verifyPassword(String(password), hashPassword('not-a-real-password', {
    cost: config.scryptCost,
    blockSize: config.scryptBlockSize,
    parallelization: config.scryptParallelization,
  }));
  return false;
}

// ---------------------------------------------------------------------------
// JWT access tokens
// ---------------------------------------------------------------------------

/**
 * @param {{id:number, login:string, role:string}} user
 * @param {object} config
 * @returns {{token:string, expiresIn:number}}
 */
export function issueAccessToken(user, config) {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign(
    {
      sub: String(user.id),
      login: user.login,
      role: user.role,
      jti: crypto.randomBytes(12).toString('base64url'),
    },
    config.jwtSecret,
    {
      algorithm: 'HS256',
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      expiresIn: config.accessTtlSeconds,
      notBefore: 0,
      header: { typ: 'JWT', alg: 'HS256' },
    },
  );
  return { token, expiresIn: config.accessTtlSeconds, issuedAt: now };
}

/**
 * Verify a bearer token.
 *
 * The algorithm list is pinned: accepting the `alg` header the client sent is
 * how `alg: none` and RS256->HS256 confusion attacks work. Issuer, audience,
 * expiry and the required claims are all checked as well.
 *
 * @param {string} token
 * @param {object} config
 * @returns {import('jsonwebtoken').JwtPayload}
 */
export function verifyAccessToken(token, config) {
  try {
    const claims = jwt.verify(token, config.jwtSecret, {
      algorithms: ['HS256'],
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      clockTolerance: config.clockToleranceSeconds,
      complete: false,
    });
    if (typeof claims !== 'object' || claims === null || typeof claims.sub !== 'string') {
      throw new Error('missing subject');
    }
    return claims;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw unauthorized('Token has expired.', 'token_expired');
    }
    throw unauthorized('Invalid token.', 'invalid_token');
  }
}

/**
 * Extract the token from `Authorization: Bearer <token>`.
 * @param {import('express').Request} req
 * @returns {string}
 */
export function bearerToken(req) {
  const header = req.get('authorization') || '';
  const [scheme, ...rest] = header.trim().split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== 'bearer' || rest.length !== 1) {
    throw unauthorized('Missing or malformed Authorization header (expected "Bearer <token>").', 'missing_token');
  }
  return rest[0];
}

// ---------------------------------------------------------------------------
// Refresh tokens (opaque, hashed at rest, rotated on every use)
// ---------------------------------------------------------------------------

/** @returns {string} 256 bits of randomness, URL-safe */
export function newRefreshToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** Only the hash is stored: a database leak must not hand over live sessions. */
export function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

// ---------------------------------------------------------------------------
// Output encoding (XSS)
// ---------------------------------------------------------------------------

const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
};

/**
 * Escape the characters that turn text into markup.
 *
 * The API stores user text verbatim and encodes it on the way out, because the
 * same text may later be rendered by a client that is not HTML (a mobile app,
 * a CLI). Encoding at the output boundary is the rule from the OWASP XSS
 * Prevention Cheat Sheet, and it makes stored XSS inert for any HTML consumer.
 *
 * @param {string} value
 * @returns {string}
 */
export function escapeHtml(value) {
  return String(value).replace(/[&<>"'`]/g, (char) => HTML_ESCAPES[char]);
}

/**
 * Recursively escape every string in a JSON-shaped value.
 * @template T
 * @param {T} value
 * @returns {T}
 */
export function escapeDeep(value) {
  if (typeof value === 'string') return escapeHtml(value);
  if (Array.isArray(value)) return value.map(escapeDeep);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, escapeDeep(val)]));
  }
  return value;
}

// ---------------------------------------------------------------------------
// Login rate limiter (A07 — brute force)
// ---------------------------------------------------------------------------

/**
 * Fixed-window failure counter keyed by `ip|login`.
 *
 * Two details matter more than the algorithm:
 *   * `check()` never allocates, so probing random logins cannot grow the map;
 *   * the map is bounded and evicts expired buckets first, so a distributed
 *     spray cannot exhaust memory either.
 */
export class LoginRateLimiter {
  constructor({ maxKeys = 5000 } = {}) {
    this.maxKeys = maxKeys;
    /** @type {Map<string, number[]>} */
    this.buckets = new Map();
  }

  /** @param {string} key @param {number} windowSeconds */
  check(key, maxAttempts, windowSeconds) {
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.length === 0) return;
    const now = Date.now();
    const cutoff = now - windowSeconds * 1000;
    while (bucket.length > 0 && bucket[0] <= cutoff) bucket.shift();
    if (bucket.length >= maxAttempts) {
      const retryAfter = Math.ceil((bucket[0] + windowSeconds * 1000 - now) / 1000);
      throw rateLimited(retryAfter);
    }
  }

  /** @param {string} key @param {number} windowSeconds */
  recordFailure(key, windowSeconds) {
    const now = Date.now();
    const cutoff = now - windowSeconds * 1000;
    if (this.buckets.size >= this.maxKeys) {
      for (const [existingKey, timestamps] of this.buckets) {
        if (timestamps.length === 0 || timestamps[timestamps.length - 1] <= cutoff) {
          this.buckets.delete(existingKey);
        }
      }
      while (this.buckets.size >= this.maxKeys) {
        const oldest = this.buckets.keys().next().value;
        this.buckets.delete(oldest);
      }
    }
    const bucket = this.buckets.get(key) || [];
    while (bucket.length > 0 && bucket[0] <= cutoff) bucket.shift();
    bucket.push(now);
    this.buckets.set(key, bucket);
  }

  /** @param {string} key */
  reset(key) {
    this.buckets.delete(key);
  }

  clear() {
    this.buckets.clear();
  }
}

/**
 * Key on the client address *and* the login, so one noisy IP cannot lock out
 * every account, and one targeted account cannot be locked out from one IP
 * alone (both directions are attacked in practice).
 * @param {import('express').Request} req
 * @param {string} login
 */
export function loginRateKey(req, login) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  return `${ip}|${login.toLowerCase()}`;
}
