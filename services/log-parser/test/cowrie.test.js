'use strict';

const { normalizeCowrie } = require('../src/normalize/cowrie');
const { readSample, normalizeContent } = require('./helpers');

const BASE = {
  session: '76595541dd9c',
  protocol: 'ssh',
  src_ip: '172.28.0.1',
  src_port: 33906,
  dst_ip: '172.28.0.11',
  dst_port: 2222,
  sensor: 'd265e7e23cd3',
  timestamp: '2026-09-11T02:48:24.237542Z',
};

function line(fields) {
  return JSON.stringify({ ...BASE, ...fields });
}

const SHA = 'a'.repeat(64);

describe('docs/samples/cowrie.json', () => {
  const { rows, others } = normalizeContent(readSample('cowrie.json'), normalizeCowrie);

  test('15 lines: 11 stored, 4 skipped as noise, none malformed', () => {
    expect(rows).toHaveLength(11);
    expect(others.map((o) => o.status)).toEqual(Array(4).fill('skipped'));
    expect(others.map((o) => o.reason)).toEqual([
      'cowrie.client.size',
      'cowrie.session.params',
      'cowrie.log.closed',
      'cowrie.client.size',
    ]);
  });

  test('stored event types, in file order', () => {
    expect(rows.map((r) => r.event_type)).toEqual([
      'cowrie.session.connect',
      'cowrie.client.version',
      'cowrie.client.kex',
      'cowrie.login.success',
      'cowrie.command.input',
      'cowrie.command.input',
      'cowrie.session.closed',
      'cowrie.session.connect',
      'cowrie.client.version',
      'cowrie.client.kex',
      'cowrie.login.success',
    ]);
  });

  test('login line maps to every column', () => {
    const login = rows[3];
    expect(login).toEqual({
      event_time: '2026-09-11T02:48:04.928571Z',
      service: 'cowrie',
      event_type: 'cowrie.login.success',
      src_ip: '172.28.0.1',
      src_port: 33906,
      session_id: '76595541dd9c',
      username: 'root',
      password: 'Hacker01',
      command: null,
      http_method: null,
      http_path: null,
      user_agent: null,
      email: null,
      tags: [],
      raw: expect.objectContaining({ eventid: 'cowrie.login.success', password: 'Hacker01' }),
      source_seq: 0,
      source_offset: login.source_offset,
    });
  });

  test('typed commands fill the command column', () => {
    expect(rows.filter((r) => r.command !== null).map((r) => r.command)).toEqual(['ls', 'exit']);
  });

  test('every row has seq 0 and its own byte offset', () => {
    expect(rows.every((r) => r.source_seq === 0)).toBe(true);
    expect(new Set(rows.map((r) => r.source_offset)).size).toBe(rows.length);
  });

  test('the hassh fingerprint is reachable through raw', () => {
    expect(rows[2].raw.hassh).toBe('701158e75b508e76f0410d5d22ef9df0');
  });

  test('no malware rows from this sample', () => {
    const results = readSample('cowrie.json').trim().split('\n').map(normalizeCowrie);
    expect(results.flatMap((r) => r.malware ?? [])).toEqual([]);
  });
});

describe('malware from download and upload events', () => {
  test('file_download adds a malware_samples row from shasum', () => {
    const result = normalizeCowrie(line({
      eventid: 'cowrie.session.file_download',
      url: 'http://198.51.100.7/bot.sh',
      outfile: `var/lib/cowrie/downloads/${SHA}`,
      shasum: SHA,
      destfile: '',
    }));

    expect(result.status).toBe('rows');
    expect(result.rows[0].event_type).toBe('cowrie.session.file_download');
    expect(result.malware).toEqual([{
      sha256: SHA,
      service: 'cowrie',
      file_path: `var/lib/cowrie/downloads/${SHA}`,
      file_size: null,
      first_seen: '2026-09-11T02:48:24.237542Z',
      first_src_ip: '172.28.0.1',
    }]);
  });

  test('file_upload uses filename when there is no outfile', () => {
    const result = normalizeCowrie(line({
      eventid: 'cowrie.session.file_upload',
      filename: 'payload.bin',
      shasum: SHA.toUpperCase(),
    }));
    expect(result.malware).toEqual([expect.objectContaining({ sha256: SHA, file_path: 'payload.bin' })]);
  });

  test('a download without a valid shasum is stored, with a warning and no malware row', () => {
    const result = normalizeCowrie(line({ eventid: 'cowrie.session.file_download', shasum: 'abc' }));
    expect(result.rows).toHaveLength(1);
    expect(result.malware).toEqual([]);
    expect(result.warnings).toEqual([expect.objectContaining({ code: 'invalid_shasum' })]);
  });

  test('file_download.failed has no file, so no malware row and no warning', () => {
    const result = normalizeCowrie(line({ eventid: 'cowrie.session.file_download.failed', url: 'http://x/y' }));
    expect(result.rows).toHaveLength(1);
    expect(result.malware).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  test('other events never produce malware rows, even with a shasum field', () => {
    expect(normalizeCowrie(line({ eventid: 'cowrie.log.closed', shasum: SHA })).status).toBe('skipped');
    expect(normalizeCowrie(line({ eventid: 'cowrie.session.closed', shasum: SHA })).malware).toEqual([]);
  });
});

test('command.failed also fills the command column', () => {
  const [row] = normalizeCowrie(line({ eventid: 'cowrie.command.failed', input: 'nmap -sS 10.0.0.0/8' })).rows;
  expect(row.command).toBe('nmap -sS 10.0.0.0/8');
});

test('client.kex is kept', () => {
  expect(normalizeCowrie(line({ eventid: 'cowrie.client.kex', hassh: 'x' })).status).toBe('rows');
});

test('an eventid unknown today is stored, not dropped', () => {
  const result = normalizeCowrie(line({ eventid: 'cowrie.some.future.event' }));
  expect(result.status).toBe('rows');
  expect(result.rows[0].event_type).toBe('cowrie.some.future.event');
});

test('IPv4-mapped IPv6 src_ip is stored as plain IPv4', () => {
  const [row] = normalizeCowrie(line({ eventid: 'cowrie.session.connect', src_ip: '::ffff:198.51.100.7' })).rows;
  expect(row.src_ip).toBe('198.51.100.7');
});

test.each([
  ['malformed JSON', '{"eventid": "cowrie.session.connect", ', 'invalid_json'],
  ['missing eventid', line({}), 'missing_eventid'],
  ['eventid from another program', line({ eventid: 'dionaea.connection' }), 'missing_eventid'],
  ['missing timestamp', line({ eventid: 'cowrie.session.connect', timestamp: undefined }), 'invalid_timestamp'],
  ['unparseable timestamp', line({ eventid: 'cowrie.session.connect', timestamp: 'now' }), 'invalid_timestamp'],
  ['invalid src_ip', line({ eventid: 'cowrie.session.connect', src_ip: 'nope' }), 'invalid_src_ip'],
])('%s is malformed', (_name, input, reason) => {
  expect(normalizeCowrie(input)).toEqual({ status: 'malformed', reason });
});

test('a skipped event is skipped even if the rest of the line is broken', () => {
  expect(normalizeCowrie(JSON.stringify({ eventid: 'cowrie.client.size' }))).toEqual({
    status: 'skipped',
    reason: 'cowrie.client.size',
  });
});
