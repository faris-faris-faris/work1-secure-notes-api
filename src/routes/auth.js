/**
 * Authentication endpoints: login, refresh, logout.
 *
 * The design is the standard split between a short-lived access token (kept in
 * memory by the client) and a long-lived, rotating refresh token (stored in an
 * HttpOnly cookie or a secure store). Rotation plus reuse detection means a
 * stolen refresh token is useful at most once, and its use invalidates the
 * whole session family.
 */
import crypto from 'node:crypto';
import { Router } from 'express';

import { unauthorized } from '../errors.js';
import {
  dummyVerify,
  hashRefreshToken,
  issueAccessToken,
  loginRateKey,
  newRefreshToken,
  verifyPassword,
} from '../security.js';
import { escapeHtml } from '../security.js';
import { loginSchema, parse, refreshSchema } from '../validation.js';

/**
 * @param {{config: object, repo: object, limiter: import('../security.js').LoginRateLimiter}} deps
 */
export function authRouter({ config, repo, limiter }) {
  const router = Router();

  function sessionPayload(user, accessToken, expiresIn, refreshToken) {
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      user: {
        id: user.id,
        login: user.login,
        display_name: escapeHtml(user.display_name),
        role: user.role,
      },
    };
  }

  function startSession(user) {
    const { token, expiresIn } = issueAccessToken(
      { id: user.id, login: user.login, role: user.role },
      config,
    );
    const refreshToken = newRefreshToken();
    repo.createRefreshToken({
      tokenHash: hashRefreshToken(refreshToken),
      familyId: crypto.randomUUID(),
      userId: user.id,
      ttlSeconds: config.refreshTtlSeconds,
    });
    return sessionPayload(user, token, expiresIn, refreshToken);
  }

  // POST /auth/login { login, password }
  router.post('/login', (req, res) => {
    const { login, password } = parse(loginSchema, req.body);

    const rateKey = loginRateKey(req, login);
    limiter.check(rateKey, config.loginMaxAttempts, config.loginWindowSeconds);

    const user = repo.findUserByLogin(login);
    // Unknown user and wrong password take the same path: a dummy scrypt run
    // keeps the response time flat, and the message is identical.
    const authenticated = user
      ? verifyPassword(password, user.password_hash)
      : dummyVerify(password, config);

    if (!authenticated) {
      limiter.recordFailure(rateKey, config.loginWindowSeconds);
      throw unauthorized('Invalid login or password.', 'invalid_credentials');
    }

    limiter.reset(rateKey);
    res.status(200).json(startSession(user));
  });

  // POST /auth/refresh { refresh_token }
  router.post('/refresh', (req, res) => {
    const { refresh_token: presented } = parse(refreshSchema, req.body);
    const tokenHash = hashRefreshToken(presented);
    const row = repo.findRefreshToken(tokenHash);

    if (!row) throw unauthorized('Invalid refresh token.', 'invalid_token');
    if (row.revoked_at) throw unauthorized('Session has been revoked.', 'invalid_token');

    if (row.rotated_at) {
      // Reuse of a token that was already exchanged: either the client is
      // buggy or the token was stolen. Kill the family; the legitimate client
      // simply logs in again.
      repo.revokeRefreshFamily(row.family_id);
      throw unauthorized('Refresh token already used; the session was revoked.', 'token_reuse');
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      throw unauthorized('Refresh token has expired.', 'token_expired');
    }

    const user = repo.findUserById(row.user_id);
    if (!user) throw unauthorized('Account no longer exists.', 'invalid_token');

    repo.markRefreshRotated(tokenHash);
    const nextRefresh = newRefreshToken();
    repo.createRefreshToken({
      tokenHash: hashRefreshToken(nextRefresh),
      familyId: row.family_id,
      userId: user.id,
      ttlSeconds: config.refreshTtlSeconds,
    });

    const { token, expiresIn } = issueAccessToken(
      { id: user.id, login: user.login, role: user.role },
      config,
    );
    res.status(200).json(sessionPayload(user, token, expiresIn, nextRefresh));
  });

  // POST /auth/logout { refresh_token } — idempotent
  router.post('/logout', (req, res) => {
    const { refresh_token: presented } = parse(refreshSchema, req.body);
    repo.revokeRefreshToken(hashRefreshToken(presented));
    res.status(204).end();
  });

  return router;
}
