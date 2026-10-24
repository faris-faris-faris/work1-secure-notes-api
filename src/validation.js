/* eslint-disable no-control-regex -- detecting control characters is the point */
/**
 * Request validation schemas.
 *
 * Every field has an explicit upper bound: an unbounded string is a memory and
 * log-storage liability even when it is stored safely.
 */
import { z } from 'zod';

import { validation } from './errors.js';

// Control characters are never legitimate in these fields and are the raw
// material of log-injection and header-injection tricks.
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const ANY_CONTROL = /[\u0000-\u001f\u007f]/;

const cleanText = (schema, { allowNewlines }) =>
  schema.refine(
    (value) => !(allowNewlines ? CONTROL_CHARS : ANY_CONTROL).test(value),
    { message: 'contains illegal control characters' },
  );

export const loginSchema = z
  .object({
    login: z.string().min(1).max(64),
    password: z.string().min(1).max(256),
  })
  .strict();

export const refreshSchema = z
  .object({
    refresh_token: z.string().min(20).max(512),
  })
  .strict();

export const listQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(50).default(20),
    offset: z.coerce.number().int().min(0).max(100000).default(0),
    q: cleanText(z.string().max(120), { allowNewlines: false }).default(''),
    category: z.enum(['general', 'exam', 'event', 'lost-and-found']).optional(),
    sort: z.enum(['newest', 'oldest', 'title']).default('newest'),
  })
  .strict();

const categorySchema = z.enum(['general', 'exam', 'event', 'lost-and-found']);

export const createNoteSchema = z
  .object({
    title: cleanText(z.string().trim().min(3).max(120), { allowNewlines: false }),
    body: cleanText(z.string().trim().min(1).max(4000), { allowNewlines: true }),
    category: categorySchema.default('general'),
  })
  .strict();

export const updateNoteSchema = z
  .object({
    title: cleanText(z.string().trim().min(3).max(120), { allowNewlines: false }).optional(),
    body: cleanText(z.string().trim().min(1).max(4000), { allowNewlines: true }).optional(),
    category: categorySchema.optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, {
    message: 'at least one field must be provided',
  });

/**
 * Parse with a schema, or throw a 400 that lists the offending fields.
 * @template T
 * @param {import('zod').ZodType<T>} schema
 * @param {unknown} data
 * @returns {T}
 */
export function parse(schema, data) {
  const result = schema.safeParse(data ?? {});
  if (result.success) return result.data;
  const details = result.error.issues.map((issue) => ({
    field: issue.path.join('.') || '(body)',
    message: issue.message,
  }));
  throw validation('Request validation failed.', details);
}
