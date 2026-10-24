/**
 * Authentication middleware.
 *
 * Applied to every endpoint that is not /auth/* or /health. It verifies the
 * JWT and then re-reads the subject from the database, so a deleted (or newly
 * disabled) account cannot keep using a token that is still cryptographically
 * valid.
 */
import { unauthorized } from '../errors.js';
import { bearerToken, verifyAccessToken } from '../security.js';

export function makeAuthMiddleware({ config, repo }) {
  /**
   * @type {import('express').RequestHandler}
   */
  return function requireAuth(req, _res, next) {
    try {
      const token = bearerToken(req);
      const claims = verifyAccessToken(token, config);
      const user = repo.findUserById(Number(claims.sub));
      if (!user) {
        throw unauthorized('Account no longer exists.', 'invalid_token');
      }
      req.user = { id: user.id, login: user.login, displayName: user.display_name, role: user.role };
      req.claims = claims;
      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Authorisation for a note: the author or an administrator. Centralised so a
 * new route cannot accidentally forget the check.
 * @param {{id:number, role:string}} user
 * @param {{author_id:number}} note
 */
export function canModifyNote(user, note) {
  return note.author_id === user.id || user.role === 'admin';
}
