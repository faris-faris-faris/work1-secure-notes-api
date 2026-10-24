/**
 * Notes endpoints (the protected part of the API).
 *
 * The list is readable by any authenticated user; writes are restricted to the
 * author or an administrator. That ownership check is the A01 (Broken Access
 * Control) part of the exercise: an object identifier from the URL is never
 * trusted on its own.
 */
import { Router } from 'express';

import { forbidden, notFound } from '../errors.js';
import { canModifyNote } from '../middleware/auth.js';
import { escapeHtml } from '../security.js';
import { createNoteSchema, listQuerySchema, parse, updateNoteSchema } from '../validation.js';

/**
 * Shape a database row for the client.
 *
 * All user-controlled text is HTML-escaped here, at the output boundary, so
 * the raw text stays editable in the database while the API can never hand a
 * live `<script>` to an HTML client.
 * @param {object} row
 */
function presentNote(row) {
  return {
    id: row.id,
    title: escapeHtml(row.title),
    body: escapeHtml(row.body),
    category: row.category,
    author: {
      id: row.author_id,
      login: escapeHtml(row.author_login),
      display_name: escapeHtml(row.author_display_name),
    },
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function noteId(raw) {
  const id = Number(raw);
  if (!Number.isInteger(id) || id < 1) throw notFound('Note not found.');
  return id;
}

/**
 * @param {{config: object, repo: object, requireAuth: import('express').RequestHandler}} deps
 */
export function notesRouter({ repo, requireAuth }) {
  const router = Router();

  // GET /api/data?limit&offset&q&category&sort
  router.get('/data', requireAuth, (req, res) => {
    const query = parse(listQuerySchema, req.query);
    const { items, total } = repo.listNotes(query);
    res.status(200).json({
      items: items.map(presentNote),
      total,
      limit: query.limit,
      offset: query.offset,
      sort: query.sort,
    });
  });

  // GET /api/notes/:id
  router.get('/notes/:id', requireAuth, (req, res) => {
    const row = repo.getNote(noteId(req.params.id));
    if (!row) throw notFound('Note not found.');
    res.status(200).json(presentNote(row));
  });

  // POST /api/notes — the "own method" required by the lab
  router.post('/notes', requireAuth, (req, res) => {
    const input = parse(createNoteSchema, req.body);
    const row = repo.createNote({ ...input, authorId: req.user.id });
    res.status(201).location(`/api/notes/${row.id}`).json(presentNote(row));
  });

  // PATCH /api/notes/:id — author or admin only
  router.patch('/notes/:id', requireAuth, (req, res) => {
    const id = noteId(req.params.id);
    const existing = repo.getNote(id);
    if (!existing) throw notFound('Note not found.');
    if (!canModifyNote(req.user, existing)) {
      throw forbidden('Only the author or an administrator may edit this note.');
    }
    const input = parse(updateNoteSchema, req.body);
    const row = repo.updateNote(id, input);
    res.status(200).json(presentNote(row));
  });

  // DELETE /api/notes/:id — author or admin only
  router.delete('/notes/:id', requireAuth, (req, res) => {
    const id = noteId(req.params.id);
    const existing = repo.getNote(id);
    if (!existing) throw notFound('Note not found.');
    if (!canModifyNote(req.user, existing)) {
      throw forbidden('Only the author or an administrator may delete this note.');
    }
    repo.deleteNote(id);
    res.status(204).end();
  });

  // GET /api/me — who does the token say I am
  router.get('/me', requireAuth, (req, res) => {
    res.status(200).json({
      id: req.user.id,
      login: escapeHtml(req.user.login),
      display_name: escapeHtml(req.user.displayName),
      role: req.user.role,
      token: {
        issuer: req.claims.iss,
        audience: req.claims.aud,
        expires_at: new Date(req.claims.exp * 1000).toISOString(),
        token_id: req.claims.jti,
      },
    });
  });

  return router;
}
