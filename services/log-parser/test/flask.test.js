'use strict';

const { normalizeFlask } = require('../src/normalize/flask');
const { readFixture, normalizeContent } = require('./helpers');

const LOGIN = {
  timestamp: '2026-09-05T18:00:00+00:00',
  service: 'flask-http',
  src_ip: '172.28.0.1',
  method: 'POST',
  path: '/login',
  username: 'admin',
  password: 'admin123',
  user_agent: 'Mozilla/5.0',
  tags: ['http_login'],
};

function line(overrides = {}) {
  return JSON.stringify({ ...LOGIN, ...overrides });
}

describe('sample file (the example in docs/LOG_CONTRACT.md plus a signup)', () => {
  const { rows, others } = normalizeContent(readFixture('flask.json'), normalizeFlask);

  test('every line becomes one row', () => {
    expect(others).toEqual([]);
    expect(rows).toHaveLength(2);
  });

  test('login line maps to every column', () => {
    expect(rows[0]).toEqual({
      event_time: '2026-09-05T18:00:00+00:00',
      service: 'flask-http',
      event_type: 'http_login',
      src_ip: '172.28.0.1',
      src_port: null,
      session_id: null,
      username: 'admin',
      password: 'admin123',
      command: null,
      http_method: 'POST',
      http_path: '/login',
      user_agent: 'Mozilla/5.0',
      email: null,
      tags: ['http_login'],
      raw: LOGIN,
      source_seq: 0,
      source_offset: 0,
    });
  });

  test('signup line keeps the email', () => {
    expect(rows[1]).toMatchObject({
      event_type: 'http_signup',
      http_path: '/signup',
      email: 'jdoe@example.com',
      event_time: '2026-09-05T18:00:07.512334+00:00',
    });
  });
});

test('double submit: two identical lines are two rows, told apart only by offset', () => {
  const content = `${line()}\n${line()}\n`;
  const { rows } = normalizeContent(content, normalizeFlask);

  expect(rows).toHaveLength(2);
  const { source_offset: first, ...restFirst } = rows[0];
  const { source_offset: second, ...restSecond } = rows[1];
  expect(restFirst).toEqual(restSecond);
  expect(first).toBe(0);
  expect(second).toBe(Buffer.byteLength(line()) + 1);
});

describe('invalid src_ip is stored, not skipped', () => {
  test.each([
    ['garbage text', 'not-an-ip'],
    ['empty string', ''],
    ["Flask's fallback value", 'unknown'],
    ['an out-of-range address', '300.1.2.3'],
  ])('%s', (_name, badIp) => {
    const result = normalizeFlask(line({ src_ip: badIp, tags: ['http_login', 'sqli_like'] }));

    expect(result.status).toBe('rows');
    expect(result.rows).toHaveLength(1);
    const [row] = result.rows;
    expect(row.src_ip).toBe('0.0.0.0');
    expect(row.tags).toEqual(['http_login', 'sqli_like', 'invalid_src_ip']);
    expect(row.raw.src_ip).toBe(badIp);
    expect(row.username).toBe('admin');
    expect(result.warnings).toEqual([
      expect.objectContaining({ code: 'invalid_src_ip' }),
    ]);
  });

  test('missing src_ip is treated the same way', () => {
    const { src_ip: _dropped, ...withoutIp } = LOGIN;
    const result = normalizeFlask(JSON.stringify(withoutIp));

    expect(result.rows[0].src_ip).toBe('0.0.0.0');
    expect(result.rows[0].tags).toContain('invalid_src_ip');
    expect(result.warnings[0].code).toBe('invalid_src_ip');
  });

  test('a valid address produces no warning', () => {
    const result = normalizeFlask(line());
    expect(result.warnings).toEqual([]);
    expect(result.rows[0].tags).not.toContain('invalid_src_ip');
  });
});

test('IPv4-mapped IPv6 src_ip is stored as plain IPv4', () => {
  const result = normalizeFlask(line({ src_ip: '::ffff:203.0.113.9' }));
  expect(result.rows[0].src_ip).toBe('203.0.113.9');
  expect(result.rows[0].raw.src_ip).toBe('::ffff:203.0.113.9');
});

test.each([
  ['malformed JSON', '{"timestamp": "2026-09-05T18:00:00+00:00", "path": "/login"', 'invalid_json'],
  ['a JSON array', '[1, 2, 3]', 'not_a_json_object'],
  ['missing timestamp', JSON.stringify({ ...LOGIN, timestamp: undefined }), 'invalid_timestamp'],
  ['timestamp without a zone', line({ timestamp: '2026-09-05T18:00:00' }), 'invalid_timestamp'],
])('%s is malformed', (_name, input, reason) => {
  expect(normalizeFlask(input)).toEqual({ status: 'malformed', reason });
});

test('a blank line is skipped, not malformed', () => {
  expect(normalizeFlask('')).toEqual({ status: 'skipped', reason: 'empty_line' });
});

test('NUL in attacker input does not break the row', () => {
  const [row] = normalizeFlask(line({ username: 'admin\u0000' })).rows;
  expect(row.username).toBe('admin\\u0000');
  expect(row.raw.username).toBe('admin\\u0000');
});

test('an unknown path is kept as http_request', () => {
  expect(normalizeFlask(line({ path: '/wp-login.php' })).rows[0].event_type).toBe('http_request');
});

test('non-string tags are dropped', () => {
  expect(normalizeFlask(line({ tags: ['http_login', 7, null] })).rows[0].tags).toEqual(['http_login']);
  expect(normalizeFlask(line({ tags: 'http_login' })).rows[0].tags).toEqual([]);
});
