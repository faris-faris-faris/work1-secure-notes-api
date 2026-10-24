/**
 * Persistence layer.
 *
 * This module is the only place in the project that contains SQL. Every
 * statement that carries user data uses a bound parameter (`?`); nothing is
 * built by string concatenation. The two things SQL cannot parameterise --
 * identifiers and sort order -- are handled with fixed whitelists below.
 */
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

import { hashPassword } from './security.js';

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  login         TEXT    NOT NULL UNIQUE,
  display_name  TEXT    NOT NULL,
  password_hash TEXT    NOT NULL,
  role          TEXT    NOT NULL CHECK (role IN ('user', 'admin')),
  created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  title      TEXT    NOT NULL,
  body       TEXT    NOT NULL,
  category   TEXT    NOT NULL CHECK (category IN ('general', 'exam', 'event', 'lost-and-found')),
  author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT    NOT NULL,
  updated_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_created ON notes (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_author  ON notes (author_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT    NOT NULL UNIQUE,
  family_id  TEXT    NOT NULL,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issued_at  TEXT    NOT NULL,
  expires_at TEXT    NOT NULL,
  rotated_at TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_user   ON refresh_tokens (user_id);
`;

// ORDER BY cannot be parameterised. A whitelist is the only safe way to let a
// client choose it: the value from the query string must never reach SQL text.
const SORT_CLAUSES = Object.freeze({
  newest: 'n.created_at DESC, n.id DESC',
  oldest: 'n.created_at ASC, n.id ASC',
  title: 'n.title COLLATE NOCASE ASC, n.id ASC',
});

export const SORT_OPTIONS = Object.freeze(Object.keys(SORT_CLAUSES));

/**
 * Escape LIKE wildcards so a search for `100%` looks for the literal string
 * `100%` instead of matching everything.
 * @param {string} term
 */
function likePattern(term) {
  return `%${term.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
}

const NOTE_COLUMNS = `
  n.id, n.title, n.body, n.category, n.author_id, n.created_at, n.updated_at,
  u.login AS author_login, u.display_name AS author_display_name
`;

/**
 * @param {string} databasePath
 * @param {{config: object, logger?: Console}} options
 */
export function openDatabase(databasePath, { config, logger = console } = {}) {
  if (databasePath !== ':memory:') {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- the path comes from validated configuration
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  }
  const db = new DatabaseSync(databasePath);
  db.exec(SCHEMA);

  /** @type {Map<string, ReturnType<DatabaseSync['prepare']>>} */
  const statements = new Map();
  /** @param {string} sql */
  const stmt = (sql) => {
    let prepared = statements.get(sql);
    if (!prepared) {
      prepared = db.prepare(sql);
      statements.set(sql, prepared);
    }
    return prepared;
  };

  if (config.seedDemoUsers) seedDemoUsers(db, config, logger);

  return {
    db,

    close() {
      statements.clear();
      db.close();
    },

    // -- users ------------------------------------------------------------
    findUserByLogin(login) {
      return stmt('SELECT * FROM users WHERE login = ? COLLATE NOCASE').get(login);
    },

    findUserById(id) {
      return stmt('SELECT * FROM users WHERE id = ?').get(id);
    },

    createUser({ login, displayName, password, role = 'user' }) {
      const now = new Date().toISOString();
      const passwordHash = hashPassword(password, {
        cost: config.scryptCost,
        blockSize: config.scryptBlockSize,
        parallelization: config.scryptParallelization,
      });
      const result = stmt(
        `INSERT INTO users (login, display_name, password_hash, role, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).run(login, displayName, passwordHash, role, now);
      return this.findUserById(Number(result.lastInsertRowid));
    },

    // -- notes ------------------------------------------------------------
    listNotes({ limit, offset, q = '', category = null, sort = 'newest' }) {
      const orderBy = SORT_CLAUSES[sort] || SORT_CLAUSES.newest;
      const where = [];
      const params = [];

      if (q) {
        where.push(`(n.title LIKE ? ESCAPE '\\' OR n.body LIKE ? ESCAPE '\\')`);
        params.push(likePattern(q), likePattern(q));
      }
      if (category) {
        where.push('n.category = ?');
        params.push(category);
      }
      const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

      const total = stmt(
        `SELECT COUNT(*) AS count FROM notes n ${whereSql}`,
      ).get(...params).count;

      const items = stmt(
        `SELECT ${NOTE_COLUMNS}
           FROM notes n
           JOIN users u ON u.id = n.author_id
           ${whereSql}
          ORDER BY ${orderBy}
          LIMIT ? OFFSET ?`,
      ).all(...params, limit, offset);

      return { items, total };
    },

    getNote(id) {
      return stmt(
        `SELECT ${NOTE_COLUMNS}
           FROM notes n
           JOIN users u ON u.id = n.author_id
          WHERE n.id = ?`,
      ).get(id);
    },

    createNote({ title, body, category, authorId }) {
      const now = new Date().toISOString();
      const result = stmt(
        `INSERT INTO notes (title, body, category, author_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(title, body, category, authorId, now, now);
      return this.getNote(Number(result.lastInsertRowid));
    },

    updateNote(id, { title, body, category }) {
      const current = this.getNote(id);
      if (!current) return undefined;
      const now = new Date().toISOString();
      stmt(
        `UPDATE notes
            SET title = ?, body = ?, category = ?, updated_at = ?
          WHERE id = ?`,
      ).run(title ?? current.title, body ?? current.body, category ?? current.category, now, id);
      return this.getNote(id);
    },

    deleteNote(id) {
      return stmt('DELETE FROM notes WHERE id = ?').run(id).changes > 0;
    },

    countNotes() {
      return stmt('SELECT COUNT(*) AS count FROM notes').get().count;
    },

    // -- refresh-token sessions -------------------------------------------
    createRefreshToken({ tokenHash, familyId, userId, ttlSeconds }) {
      const now = new Date();
      const expires = new Date(now.getTime() + ttlSeconds * 1000);
      stmt(
        `INSERT INTO refresh_tokens (token_hash, family_id, user_id, issued_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).run(tokenHash, familyId, userId, now.toISOString(), expires.toISOString());
    },

    findRefreshToken(tokenHash) {
      return stmt('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash);
    },

    markRefreshRotated(tokenHash) {
      stmt('UPDATE refresh_tokens SET rotated_at = ? WHERE token_hash = ?').run(
        new Date().toISOString(),
        tokenHash,
      );
    },

    revokeRefreshFamily(familyId) {
      stmt('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(
        new Date().toISOString(),
        familyId,
      );
    },

    revokeRefreshToken(tokenHash) {
      const result = stmt(
        'UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL',
      ).run(new Date().toISOString(), tokenHash);
      return result.changes > 0;
    },
  };
}

/**
 * Two demo accounts so the reviewer can call the API immediately. They are
 * seeded with the same hashing code as real users, never as literals.
 */
function seedDemoUsers(db, config, logger) {
  const count = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (count > 0) return;

  const now = new Date().toISOString();
  const insertUser = db.prepare(
    `INSERT INTO users (login, display_name, password_hash, role, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  );
  const insertNote = db.prepare(
    `INSERT INTO notes (title, body, category, author_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );

  const users = [
    { login: 'alice', displayName: 'Alice (course admin)', password: 'Passw0rd!Alice', role: 'admin' },
    { login: 'bob', displayName: 'Bob (student)', password: 'Passw0rd!Bob', role: 'user' },
  ];
  const ids = {};
  for (const user of users) {
    const hash = hashPassword(user.password, {
      cost: config.scryptCost,
      blockSize: config.scryptBlockSize,
      parallelization: config.scryptParallelization,
    });
    const result = insertUser.run(user.login, user.displayName, hash, user.role, now);
    ids[user.login] = Number(result.lastInsertRowid);
  }

  const notes = [
    ['Welcome to the campus notice board', 'This API is the Work 1 deliverable: notes are public to authenticated users, editing is limited to the author.', 'general', 'alice'],
    ['Discrete mathematics — extra consultation', 'Room B-312, Thursday 16:00. Bring your question sheets.', 'exam', 'alice'],
    ['Found: a blue umbrella near the library', 'Handed to the security desk on the ground floor.', 'lost-and-found', 'bob'],
  ];
  for (const [title, body, category, login] of notes) {
    insertNote.run(title, body, category, ids[login], now, now);
  }
  logger.info?.(`[db] seeded ${users.length} demo users and ${notes.length} notes`);
}
