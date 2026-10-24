import js from '@eslint/js';
import security from 'eslint-plugin-security';

/**
 * Flat ESLint configuration.
 *
 * `eslint-plugin-security` is the SAST layer: it flags dynamic code execution,
 * non-literal `require`, object injection through computed keys, unsafe regex
 * and similar patterns that a normal style linter ignores.
 */
export default [
  {
    ignores: ['node_modules/**', 'coverage/**', 'docs/**', 'cve/**'],
  },
  js.configs.recommended,
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        URL: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        __dirname: 'readonly',
      },
    },
    plugins: { security },
    rules: {
      ...security.configs.recommended.rules,
      // `detect-object-injection` flags every computed property access, which in
      // this codebase is always a local map keyed by a literal or by a value
      // that was already validated against an allow-list. Keeping it on would
      // produce a wall of false positives and train everyone to ignore the tool.
      'security/detect-object-injection': 'off',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      eqeqeq: ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'error',
    },
  },
];
