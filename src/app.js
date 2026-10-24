/**
 * Application factory.
 *
 * `createApp()` builds a complete, isolated instance (own database, own rate
 * limiter), which is what makes the test suite honest: every test file talks to
 * a real HTTP stack and a real SQLite database, not to mocks of them.
 */
import express from 'express';

import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import { ApiError } from './errors.js';
import { makeAuthMiddleware } from './middleware/auth.js';
import { authRouter } from './routes/auth.js';
import { notesRouter } from './routes/notes.js';
import { LoginRateLimiter } from './security.js';

/**
 * Response hardening applied to every response, including errors.
 * @type {import('express').RequestHandler}
 */
function securityHeaders(req, res, next) {
  res.set({
    // The API is JSON-only: nothing it returns should ever be rendered as a
    // document, loaded as a script, or framed.
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
    'Cross-Origin-Resource-Policy': 'same-site',
    // Tokens and notes must not be cached by a shared proxy or the browser.
    'Cache-Control': 'no-store',
  });
  if (req.secure) {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

/**
 * @param {object} [options]
 * @param {object} [options.config] configuration overrides (tests)
 * @param {string} [options.databasePath]
 * @param {Console} [options.logger]
 */
export function createApp({ config: overrides = {}, databasePath, logger = console } = {}) {
  const config = loadConfig(overrides);
  const repo = openDatabase(databasePath ?? config.databasePath, { config, logger });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  const limiter = new LoginRateLimiter();
  const requireAuth = makeAuthMiddleware({ config, repo });

  app.use(securityHeaders);
  app.use(express.json({ limit: config.maxBodyBytes, strict: true }));

  if (config.env !== 'test') {
    // Access log without bodies or query strings: both can contain credentials
    // or personal data, and a log is the easiest place to leak them.
    app.use((req, res, next) => {
      const startedAt = process.hrtime.bigint();
      res.on('finish', () => {
        const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
        logger.info?.(`${req.method} ${req.path} ${res.statusCode} ${ms.toFixed(1)}ms`);
      });
      next();
    });
  }

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', uptime_seconds: Math.round(process.uptime()) });
  });

  app.use('/auth', authRouter({ config, repo, limiter }));
  app.use('/api', notesRouter({ config, repo, requireAuth }));

  app.use((_req, _res, next) => {
    next(new ApiError('Endpoint not found.', { status: 404, code: 'not_found' }));
  });

  // Central error handler. Only ApiError messages are shown; everything else
  // becomes a generic 500 so no stack trace, SQL text or path escapes.
  app.use((error, req, res, _next) => {
    if (res.headersSent) return;

    if (error instanceof ApiError) {
      res.status(error.status);
      for (const [name, value] of Object.entries(error.headers || {})) res.set(name, value);
      res.json({
        error: {
          code: error.code,
          message: error.message,
          ...(error.details ? { details: error.details } : {}),
        },
      });
      return;
    }

    if (error?.type === 'entity.too.large') {
      res.status(413).json({
        error: { code: 'payload_too_large', message: `Request body exceeds ${config.maxBodyBytes} bytes.` },
      });
      return;
    }

    if (error?.type === 'entity.parse.failed' || (error instanceof SyntaxError && 'body' in error)) {
      res.status(400).json({ error: { code: 'invalid_json', message: 'Request body is not valid JSON.' } });
      return;
    }

    logger.error?.('[api] unhandled error', error);
    res.status(500).json({ error: { code: 'internal_error', message: 'Internal server error.' } });
  });

  return {
    app,
    repo,
    config,
    limiter,
    close() {
      repo.close();
    },
  };
}
