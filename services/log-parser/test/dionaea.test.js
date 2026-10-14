'use strict';

const { normalizeDionaea } = require('../src/normalize/dionaea');
const { readSample, normalizeContent } = require('./helpers');

const BASE = {
  connection: { protocol: 'ftpd', transport: 'tcp', type: 'accept' },
  dst_ip: '172.28.0.12',
  dst_port: 21,
  src_hostname: '',
  src_ip: '172.28.0.1',
  src_port: 41404,
  timestamp: '2026-10-14T07:11:05.505842',
};

function line(fields) {
  return JSON.stringify({ ...BASE, ...fields });
}

// Copied from the live hp-dionaea log on 2026-10-14.
const REAL_LISTEN_LINE =
  '{"connection": {"protocol": "ftpdatalisten", "transport": "tcp", "type": "listen"}, "dst_ip": "172.28.0.12", "dst_port": 37155, "src_hostname": "", "src_ip": "", "src_port": 0, "timestamp": "2026-10-13T22:10:25.498199"}';

describe('docs/samples/dionaea.json', () => {
  const { rows, others } = normalizeContent(readSample('dionaea.json'), normalizeDionaea);

  test('one line becomes 7 rows: connection, 1 login, 5 commands', () => {
    expect(others).toEqual([]);
    expect(rows.map((r) => [r.source_seq, r.event_type, r.username, r.password, r.command])).toEqual([
      [0, 'ftp.connection', null, null, null],
      [1, 'ftp.login', 'admin', 'admin123', null],
      [2, 'ftp.command', null, null, 'USER admin'],
      [3, 'ftp.command', null, null, 'PASS admin123'],
      [4, 'ftp.command', null, null, 'PWD'],
      [5, 'ftp.command', null, null, 'EPSV'],
      [6, 'ftp.command', null, null, 'PASV'],
    ]);
  });

  test('all rows share the line: same time, IP, port, offset and raw', () => {
    for (const row of rows) {
      expect(row).toMatchObject({
        service: 'dionaea',
        event_time: '2026-10-07T08:25:19.999267Z',
        src_ip: '172.28.0.1',
        src_port: 57510,
        source_offset: 0,
        tags: [],
      });
      expect(row.raw.credentials).toEqual([{ password: 'admin123', username: 'admin' }]);
    }
  });

  test('the zone-less timestamp gets Z appended and keeps its microseconds', () => {
    expect(rows[0].event_time).toBe('2026-10-07T08:25:19.999267Z');
  });
});

test('a real listen record is skipped', () => {
  expect(normalizeDionaea(REAL_LISTEN_LINE)).toEqual({ status: 'skipped', reason: 'listen' });
});

test('listen is skipped before checking timestamp or IP', () => {
  expect(normalizeDionaea(JSON.stringify({ connection: { protocol: 'ftpd', type: 'listen' } })))
    .toEqual({ status: 'skipped', reason: 'listen' });
});

describe('multi-row ordering', () => {
  const result = normalizeDionaea(line({
    ftp: {
      commands: [
        { command: 'USER', arguments: ['root'] },
        { command: 'PASS', arguments: ['toor'] },
        { command: 'USER', arguments: ['admin'] },
        { command: 'PASS', arguments: ['1234'] },
        { command: 'STOR', arguments: ['bot', 'x86'] },
      ],
    },
    credentials: [
      { username: 'root', password: 'toor' },
      { username: 'admin', password: '1234' },
    ],
  }));

  test('connection first, then logins in order, then commands in order', () => {
    expect(result.rows.map((r) => [r.source_seq, r.event_type, r.username ?? r.command])).toEqual([
      [0, 'ftp.connection', null],
      [1, 'ftp.login', 'root'],
      [2, 'ftp.login', 'admin'],
      [3, 'ftp.command', 'USER root'],
      [4, 'ftp.command', 'PASS toor'],
      [5, 'ftp.command', 'USER admin'],
      [6, 'ftp.command', 'PASS 1234'],
      [7, 'ftp.command', 'STOR bot x86'],
    ]);
  });

  test('reading the same line again gives identical rows and seq numbers', () => {
    const again = normalizeDionaea(line({
      ftp: { commands: result.rows[0].raw.ftp.commands },
      credentials: result.rows[0].raw.credentials,
    }));
    expect(again.rows).toEqual(result.rows);
  });
});

test('a connection with no credentials or commands is one row', () => {
  const result = normalizeDionaea(line({}));
  expect(result.rows).toHaveLength(1);
  expect(result.rows[0]).toMatchObject({ event_type: 'ftp.connection', source_seq: 0 });
});

test('bad entries inside the arrays are skipped with a warning, seq stays gap-free', () => {
  const result = normalizeDionaea(line({
    credentials: ['oops', { username: 'a', password: 'b' }],
    ftp: { commands: [{ arguments: ['x'] }, { command: 'QUIT', arguments: 'not-a-list' }] },
  }));
  expect(result.rows.map((r) => [r.source_seq, r.event_type, r.username ?? r.command])).toEqual([
    [0, 'ftp.connection', null],
    [1, 'ftp.login', 'a'],
    [2, 'ftp.command', 'QUIT'],
  ]);
  expect(result.warnings.map((w) => w.code)).toEqual(['bad_item', 'bad_item']);
});

test('IPv4-mapped IPv6 src_ip is stored as plain IPv4 on every row', () => {
  const result = normalizeDionaea(line({
    src_ip: '::ffff:203.0.113.50',
    credentials: [{ username: 'u', password: 'p' }],
  }));
  expect(result.rows.map((r) => r.src_ip)).toEqual(['203.0.113.50', '203.0.113.50']);
  expect(result.rows[0].raw.src_ip).toBe('::ffff:203.0.113.50');
});

describe("FTP's data channel is stored as ftp.data", () => {
  // Copied from the live hp-dionaea log on 2026-10-14: the data connection a
  // client opened to upload a file.
  const REAL_DATA_CHANNEL_LINE =
    '{"connection": {"protocol": "ftpdatalisten", "transport": "tcp", "type": "accept"}, "dst_ip": "172.28.0.12", "dst_port": 46795, "src_hostname": "", "src_ip": "172.28.0.2", "src_port": 46838, "timestamp": "2026-10-14T08:08:04.151281"}';

  test('a real passive-mode data connection becomes one ftp.data row', () => {
    const result = normalizeDionaea(REAL_DATA_CHANNEL_LINE);
    expect(result.status).toBe('rows');
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({
      event_type: 'ftp.data',
      source_seq: 0,
      src_ip: '172.28.0.2',
      src_port: 46838,
      event_time: '2026-10-14T08:08:04.151281Z',
    });
    expect(result.rows[0].raw.connection.protocol).toBe('ftpdatalisten');
  });

  test('an active-mode data connection (ftpdatacon) gets the same name', () => {
    const result = normalizeDionaea(line({ connection: { protocol: 'ftpdatacon', transport: 'tcp', type: 'connect' } }));
    expect(result.rows[0].event_type).toBe('ftp.data');
  });

  test('a data-channel listen record is still skipped', () => {
    expect(normalizeDionaea(REAL_LISTEN_LINE)).toEqual({ status: 'skipped', reason: 'listen' });
  });

  test('the control connection keeps its ftp.connection name', () => {
    expect(normalizeDionaea(line({})).rows[0].event_type).toBe('ftp.connection');
  });
});

test('SMB uses the same pattern under its own name', () => {
  const result = normalizeDionaea(line({
    connection: { protocol: 'smbd', transport: 'tcp', type: 'accept' },
    credentials: [{ username: 'guest', password: '' }],
  }));
  expect(result.rows.map((r) => r.event_type)).toEqual(['smb.connection', 'smb.login']);
});

test('an unknown protocol name is used unchanged', () => {
  const result = normalizeDionaea(line({ connection: { protocol: 'epmapper', type: 'accept' } }));
  expect(result.rows[0].event_type).toBe('epmapper.connection');
});

test.each([
  ['malformed JSON', '{"connection": {"protocol": "ftpd"', 'invalid_json'],
  ['missing connection', JSON.stringify({ ...BASE, connection: undefined }), 'missing_connection'],
  ['connection without protocol', line({ connection: { type: 'accept' } }), 'missing_connection'],
  ['missing timestamp', line({ timestamp: undefined }), 'invalid_timestamp'],
  ['unparseable timestamp', line({ timestamp: '07/10/2026 08:25' }), 'invalid_timestamp'],
  ['empty src_ip on a non-listen record', line({ src_ip: '' }), 'invalid_src_ip'],
])('%s is malformed', (_name, input, reason) => {
  expect(normalizeDionaea(input)).toEqual({ status: 'malformed', reason });
});
