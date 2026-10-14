'use strict';

// All settings come from environment variables, so the same code runs locally
// (against copies under data/ and hp-db on 127.0.0.1:5433) and in Docker
// (against the mounted volumes and hp-db:5432).
//
// Database: the standard PG* variables win; otherwise the POSTGRES_* names
// from the repo's .env are used, so `node --env-file=../../.env` is enough.
//
// Log files: each *_LOG is the live file. Rotated copies next to it (for
// example cowrie.json.2026-10-13 next to cowrie.json) are read too. Set a
// *_LOG to an empty string to turn that service off.

const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

function env(name, fallback) {
  const value = process.env[name];
  return value === undefined ? fallback : value;
}

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer, got ${JSON.stringify(raw)}`);
  }
  return value;
}

function loadConfig() {
  return {
    db: {
      host: env('PGHOST', '127.0.0.1'),
      port: intEnv('PGPORT', 5433),
      user: env('PGUSER', process.env.POSTGRES_USER),
      password: env('PGPASSWORD', process.env.POSTGRES_PASSWORD),
      database: env('PGDATABASE', env('POSTGRES_DB', 'honeypot')),
    },
    logs: {
      'flask-http': env('FLASK_LOG', path.join(REPO_ROOT, 'data/flask/http.json')),
      cowrie: env('COWRIE_LOG', path.join(REPO_ROOT, 'data/cowrie/log/cowrie.json')),
      dionaea: env('DIONAEA_LOG', path.join(REPO_ROOT, 'data/dionaea/log/dionaea.json')),
    },
    binariesDir: env('DIONAEA_BINARIES_DIR', path.join(REPO_ROOT, 'data/dionaea/lib/dionaea/binaries')),
    pollIntervalMs: intEnv('POLL_INTERVAL_MS', 1000),
    binariesIntervalMs: intEnv('BINARIES_INTERVAL_MS', 10_000),
    summaryIntervalMs: intEnv('SUMMARY_INTERVAL_MS', 60_000),
    maxLineBytes: intEnv('MAX_LINE_BYTES', 1024 * 1024),
  };
}

// The config as it is safe to print: the password is never included.
function describeConfig(config) {
  const { password, ...db } = config.db;
  return {
    ...config,
    db: { ...db, password: password ? '(set)' : '(not set)' },
  };
}

module.exports = { loadConfig, describeConfig };
