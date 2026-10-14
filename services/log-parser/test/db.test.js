'use strict';

// Runs against the real hp-db, but inside a throwaway schema built from
// db/init.sql, so the real events table is never touched.
//
//   npm run test:db      (loads the repo's .env)
//   PGHOST=... PGUSER=... PGPASSWORD=... npm test    (how CI runs it)
//
// Skipped when no database user and password are configured, e.g. plain
// `npm test`. With REQUIRE_DB_TESTS=1 (set in CI) a missing configuration is
// a failure instead, so a typo in CI cannot turn these tests into silent skips.

const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('../src/config');
const { createPool, createDb, LineRejectedError } = require('../src/db');

const config = loadConfig();
const configured = Boolean(config.db.user && config.db.password);
const describeDb = configured ? describe : describe.skip;

if (!configured && process.env.REQUIRE_DB_TESTS === '1') {
  test('database is configured (REQUIRE_DB_TESTS=1)', () => {
    throw new Error('REQUIRE_DB_TESTS=1 but PGUSER/PGPASSWORD (or POSTGRES_USER/POSTGRES_PASSWORD) are not set');
  });
}

const INIT_SQL = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'db', 'init.sql'), 'utf8');
const SCHEMA = `jest_${process.pid}_${Date.now()}`;

describeDb('database writer (schema from db/init.sql)', () => {
  let adminPool;
  let pool;
  let db;

  beforeAll(async () => {
    adminPool = createPool(config.db);
    await adminPool.query(`CREATE SCHEMA ${SCHEMA}`);
    pool = createPool(config.db, { options: `-c search_path=${SCHEMA}` });
    await pool.query(INIT_SQL);
    db = createDb(pool);
  });

  afterAll(async () => {
    await pool?.end();
    await adminPool?.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await adminPool?.end();
  });

  beforeEach(async () => {
    await pool.query('TRUNCATE events, malware_samples');
  });

  function row(overrides = {}) {
    return {
      event_time: '2026-10-07T08:25:19.999267Z',
      service: 'dionaea',
      event_type: 'ftp.connection',
      src_ip: '172.28.0.1',
      src_port: 57510,
      session_id: null,
      username: null,
      password: null,
      command: null,
      http_method: null,
      http_path: null,
      user_agent: null,
      email: null,
      tags: [],
      raw: { test: true },
      source_file: '/logs/dionaea/dionaea.json',
      source_file_id: 'file-a',
      source_offset: 0,
      source_seq: 0,
      ...overrides,
    };
  }

  const count = async () => Number((await pool.query('SELECT count(*) FROM events')).rows[0].count);

  test('all rows of a line go in together', async () => {
    const result = await db.insertLine({
      rows: [row(), row({ source_seq: 1, event_type: 'ftp.login', username: 'admin' })],
    });
    expect(result).toEqual({ inserted: 2, duplicates: 0, newMalware: 0 });
    expect(await count()).toBe(2);
  });

  test('if one row of a line is refused, none of its rows are stored', async () => {
    const bad = row({ source_seq: 1, src_port: 70000 }); // breaks the CHECK rule
    await expect(db.insertLine({ rows: [row(), bad] })).rejects.toBeInstanceOf(LineRejectedError);
    expect(await count()).toBe(0);
  });

  test('a refused line also rolls back its malware rows', async () => {
    await expect(db.insertLine({
      rows: [row({ src_ip: 'not-an-ip' })],
      malware: [{ sha256: 'a'.repeat(64), service: 'cowrie', file_path: null, file_size: null,
        first_seen: '2026-10-07T00:00:00Z', first_src_ip: '172.28.0.1' }],
    })).rejects.toBeInstanceOf(LineRejectedError);
    expect(Number((await pool.query('SELECT count(*) FROM malware_samples')).rows[0].count)).toBe(0);
  });

  test('re-inserting the same source position is skipped by ON CONFLICT', async () => {
    const line = { rows: [row(), row({ source_seq: 1 })] };
    await db.insertLine(line);
    const again = await db.insertLine(line);
    expect(again).toEqual({ inserted: 0, duplicates: 2, newMalware: 0 });
    expect(await count()).toBe(2);
  });

  test('identical-looking events at different offsets are both kept', async () => {
    await db.insertLine({ rows: [row({ source_offset: 0 })] });
    await db.insertLine({ rows: [row({ source_offset: 733 })] });
    expect(await count()).toBe(2);
  });

  test('timestamps keep their microseconds and are stored as UTC', async () => {
    await db.insertLine({ rows: [row({ event_time: '2026-09-05T23:30:00.123456+05:30' })] });
    const { rows } = await pool.query(
      `SELECT to_char(event_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') AS utc FROM events`,
    );
    expect(rows[0].utc).toBe('2026-09-05T18:00:00.123456');
  });

  test('tags and raw arrive as text[] and jsonb', async () => {
    await db.insertLine({ rows: [row({ tags: ['http_login', 'sqli_like'], raw: { a: [1, 'x'] } })] });
    const { rows } = await pool.query(`SELECT tags, raw->'a'->>1 AS second FROM events`);
    expect(rows[0]).toEqual({ tags: ['http_login', 'sqli_like'], second: 'x' });
  });

  describe('resume offset', () => {
    test('is the highest stored offset for that service and file', async () => {
      for (const offset of [0, 120, 300]) {
        await db.insertLine({ rows: [row({ source_offset: offset })] });
      }
      await db.insertLine({ rows: [row({ source_offset: 999, source_file_id: 'file-b' })] });
      await db.insertLine({ rows: [row({ source_offset: 5000, service: 'cowrie', event_type: 'x' })] });

      expect(await db.getResumeOffset('dionaea', 'file-a')).toBe(300);
      expect(await db.getResumeOffset('dionaea', 'file-b')).toBe(999);
      expect(await db.getResumeOffset('cowrie', 'file-a')).toBe(5000);
    });

    test('is null for a file never stored', async () => {
      expect(await db.getResumeOffset('dionaea', 'never-seen')).toBeNull();
    });

    test('handles offsets beyond 2^31 (files over 2 GB)', async () => {
      await db.insertLine({ rows: [row({ source_offset: 3_000_000_000 })] });
      expect(await db.getResumeOffset('dionaea', 'file-a')).toBe(3_000_000_000);
    });
  });

  describe('malware samples keep the earliest sighting', () => {
    const SHA = 'b'.repeat(64);
    const sample = (firstSeen, ip) => ({
      sha256: SHA, service: 'cowrie', file_path: `downloads/${ip}`, file_size: null,
      first_seen: firstSeen, first_src_ip: ip,
    });
    const stored = async () => (await pool.query(
      `SELECT to_char(first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') AS first_seen,
              host(first_src_ip) AS ip, file_path FROM malware_samples`,
    )).rows;

    test('a new sha256 is inserted and reported as new', async () => {
      expect(await db.upsertMalware(sample('2026-10-10T12:00:00Z', '198.51.100.2'))).toBe(true);
      expect(await stored()).toEqual([
        { first_seen: '2026-10-10T12:00:00', ip: '198.51.100.2', file_path: 'downloads/198.51.100.2' },
      ]);
    });

    test('an earlier sighting replaces first_seen and first_src_ip', async () => {
      await db.upsertMalware(sample('2026-10-10T12:00:00Z', '198.51.100.2'));
      expect(await db.upsertMalware(sample('2026-10-09T08:00:00Z', '203.0.113.7'))).toBe(false);
      expect(await stored()).toEqual([
        { first_seen: '2026-10-09T08:00:00', ip: '203.0.113.7', file_path: 'downloads/203.0.113.7' },
      ]);
    });

    test('a later sighting changes nothing', async () => {
      await db.upsertMalware(sample('2026-10-09T08:00:00Z', '203.0.113.7'));
      expect(await db.upsertMalware(sample('2026-10-11T00:00:00Z', '192.0.2.99'))).toBe(false);
      expect(await stored()).toEqual([
        { first_seen: '2026-10-09T08:00:00', ip: '203.0.113.7', file_path: 'downloads/203.0.113.7' },
      ]);
    });

    test('malware in insertLine is counted as new once', async () => {
      const line = { rows: [row()], malware: [sample('2026-10-10T12:00:00Z', '198.51.100.2')] };
      expect((await db.insertLine(line)).newMalware).toBe(1);
      expect((await db.insertLine(line)).newMalware).toBe(0);
    });

    test('a known file_size is not wiped by a sighting without one', async () => {
      await db.upsertMalware({ ...sample('2026-10-10T12:00:00Z', '198.51.100.2'), file_size: 4096 });
      await db.upsertMalware(sample('2026-10-01T00:00:00Z', '203.0.113.7'));
      const { rows } = await pool.query('SELECT file_size FROM malware_samples');
      expect(rows[0].file_size).toBe('4096');
    });
  });
});
