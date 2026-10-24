/**
 * One error type for the whole API.
 *
 * Anything thrown as an ApiError is safe to show to a client: it was written
 * for a client. Anything else is a bug, and the handler turns it into a generic
 * 500 so that stack traces, SQL text and file paths never leave the process.
 */
export class ApiError extends Error {
  /**
   * @param {string} message client-safe message
   * @param {object} [options]
   * @param {number} [options.status]
   * @param {string} [options.code]
   * @param {Record<string,string>} [options.headers]
   * @param {unknown} [options.details]
   */
  constructor(message, { status = 400, code = 'bad_request', headers = {}, details } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.headers = headers;
    this.details = details;
    this.expose = true;
  }
}

export const unauthorized = (message = 'Authentication required.', code = 'unauthorized') =>
  new ApiError(message, {
    status: 401,
    code,
    headers: { 'WWW-Authenticate': `Bearer error="${code}"` },
  });

export const forbidden = (message = 'You are not allowed to perform this action.') =>
  new ApiError(message, { status: 403, code: 'forbidden' });

export const notFound = (message = 'Resource not found.') =>
  new ApiError(message, { status: 404, code: 'not_found' });

export const validation = (message, details) =>
  new ApiError(message, { status: 400, code: 'validation_error', details });

export const rateLimited = (retryAfterSeconds) =>
  new ApiError('Too many attempts. Try again later.', {
    status: 429,
    code: 'rate_limited',
    headers: { 'Retry-After': String(Math.max(1, retryAfterSeconds)) },
  });
