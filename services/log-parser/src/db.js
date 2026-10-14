'use strict';

// Everything that talks to PostgreSQL. All SQL lives in this file.

const { Pool } = require('pg');

// The events columns the parser writes, in the order used for inserts. id and
// ingested_at are filled by the database.
const EVENT_COLUMNS = [
  'event_time', 'service', 'event_type', 'src_ip', 'src_port', 'session_id',
  'username', 'password', 'command', 'http_method', 'http_path', 'user_agent',
  'email', 'tags', 'raw', 'source_file', 'source_file_id', 'source_offset',
  'source_seq',
];

// The database refused the data in a line, as opposed to being unreachable.
// Retrying would fail again, so the caller counts the line as malformed and
// moves on.
class LineRejectedError extends Error {
  constructor(cause) {
    super(`database rejected the line: ${cause.message}`);
    this.name = 'LineRejectedError';
    this.cause = cause;
  }
}

// SQLSTATE classes 22 (bad data, e.g. an invalid inet value) and 23 (a CHECK
// or NOT NULL rule broken) mean the line itself is the problem. Anything else,
// such as a lost connection, is worth retrying.
function isDataError(err) {
  return typeof err.code === 'string' && err.code.length === 5 && /^(22|23)/.test(err.code);
}

function createPool(dbConfig, { log, ...extra } = {}) {
  const pool = new Pool({
    ...dbConfig,
    max: 2,
    connectionTimeoutMillis: 5000,
    application_name: 'log-parser',
    ...extra,
  });
  // Without this handler, an idle connection dropped by the server (e.g. a
  // database restart) would crash the process.
  pool.on('error', (err) => log?.warn('idle database connection lost', { error: err.message }));
  return pool;
}

function createDb(pool) {
  // Byte offset of the last line stored from this file, or null if nothing
  // from it is stored yet. The parser re-reads that line (its insert is
  // skipped as a duplicate) and continues after it.
  async function getResumeOffset(service, fileId) {
    const { rows } = await pool.query(
      `SELECT max(source_offset)::text AS offset
         FROM events
        WHERE service = $1 AND source_file_id = $2`,
      [service, fileId],
    );
    return rows[0].offset === null ? null : Number(rows[0].offset);
  }

  // Stores all rows and malware samples from one line in a single
  // transaction: all of them or none.
  //
  // Returns { inserted, duplicates, newMalware }. Rows whose source position
  // is already stored are skipped by ON CONFLICT and counted as duplicates.
  async function insertLine({ rows, malware = [] }) {
    const client = await pool.connect();
    let broken = false;
    try {
      await client.query('BEGIN');
      let inserted = 0;
      if (rows.length > 0) {
        const { text, values } = buildEventsInsert(rows);
        inserted = (await client.query(text, values)).rowCount;
      }
      let newMalware = 0;
      for (const sample of malware) {
        if (await upsertMalwareWith(client, sample)) newMalware += 1;
      }
      await client.query('COMMIT');
      return { inserted, duplicates: rows.length - inserted, newMalware };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { broken = true; });
      if (isDataError(err)) throw new LineRejectedError(err);
      broken = true;
      throw err;
    } finally {
      // A connection that failed is thrown away instead of reused.
      client.release(broken);
    }
  }

  async function upsertMalware(sample) {
    try {
      return await upsertMalwareWith(pool, sample);
    } catch (err) {
      if (isDataError(err)) throw new LineRejectedError(err);
      throw err;
    }
  }

  async function ping() {
    await pool.query('SELECT 1');
  }

  return { getResumeOffset, insertLine, upsertMalware, ping };
}

function buildEventsInsert(rows) {
  const values = [];
  const tuples = rows.map((row) => {
    const placeholders = EVENT_COLUMNS.map((column) => {
      values.push(column === 'raw' ? JSON.stringify(row.raw) : row[column]);
      return `$${values.length}`;
    });
    return `(${placeholders.join(', ')})`;
  });
  const text =
    `INSERT INTO events (${EVENT_COLUMNS.join(', ')})
     VALUES ${tuples.join(',\n            ')}
     ON CONFLICT ON CONSTRAINT events_source_position_key DO NOTHING`;
  return { text, values };
}

// Adds a sample, or updates it if this sighting is earlier than the stored
// first_seen, so first_seen and first_src_ip always describe the earliest
// sighting, whatever order the files are read in. Returns true for a new
// sha256.
async function upsertMalwareWith(queryable, sample) {
  const { rows } = await queryable.query(
    `INSERT INTO malware_samples (sha256, service, file_path, file_size, first_seen, first_src_ip)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (sha256) DO UPDATE
        SET first_seen   = EXCLUDED.first_seen,
            first_src_ip = EXCLUDED.first_src_ip,
            service      = EXCLUDED.service,
            file_path    = EXCLUDED.file_path,
            file_size    = COALESCE(EXCLUDED.file_size, malware_samples.file_size)
      WHERE EXCLUDED.first_seen < malware_samples.first_seen
     RETURNING (xmax = 0) AS inserted`,
    [sample.sha256, sample.service, sample.file_path, sample.file_size,
      sample.first_seen, sample.first_src_ip],
  );
  // No row back: the stored sighting was earlier, nothing changed.
  // xmax = 0: a brand-new row. Otherwise an existing row was moved earlier.
  return rows.length > 0 && rows[0].inserted === true;
}

module.exports = { createPool, createDb, LineRejectedError, isDataError, EVENT_COLUMNS };
