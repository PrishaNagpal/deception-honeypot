'use strict';

const {
  parseLine,
  cleanDeep,
  text,
  parseTimestamp,
  normalizeIp,
  normalizePort,
  normalizeSha256,
} = require('../src/normalize/common');

describe('parseLine', () => {
  test('returns the object for a JSON object line', () => {
    expect(parseLine('{"a": 1}')).toEqual({ value: { a: 1 } });
  });

  test.each([
    ['{"a": 1', 'invalid_json'],
    ['not json at all', 'invalid_json'],
    ['42', 'not_a_json_object'],
    ['"text"', 'not_a_json_object'],
    ['[1, 2]', 'not_a_json_object'],
    ['null', 'not_a_json_object'],
  ])('%j is an error: %s', (line, error) => {
    expect(parseLine(line)).toEqual({ error });
  });

  test('blank lines are empty, not errors', () => {
    expect(parseLine('')).toEqual({ empty: true });
    expect(parseLine('   \r')).toEqual({ empty: true });
  });
});

describe('parseTimestamp', () => {
  test('keeps timestamps that carry a zone, microseconds included', () => {
    expect(parseTimestamp('2026-09-11T02:47:56.680233Z')).toBe('2026-09-11T02:47:56.680233Z');
    expect(parseTimestamp('2026-09-05T18:00:00+00:00')).toBe('2026-09-05T18:00:00+00:00');
    expect(parseTimestamp('2026-09-05T23:30:00+05:30')).toBe('2026-09-05T23:30:00+05:30');
  });

  test('a missing zone becomes UTC only when assumeUtc is set', () => {
    expect(parseTimestamp('2026-10-07T08:25:19.999267', { assumeUtc: true }))
      .toBe('2026-10-07T08:25:19.999267Z');
    expect(parseTimestamp('2026-10-07T08:25:19.999267')).toBeNull();
  });

  test.each([
    [undefined],
    [null],
    [1760000000],
    [''],
    ['yesterday'],
    ['2026-10-07 08:25:19Z'],
    ['2026-02-30T00:00:00Z'],
    ['2026-13-01T00:00:00Z'],
    ['2026-10-07T25:00:00Z'],
  ])('rejects %j', (value) => {
    expect(parseTimestamp(value, { assumeUtc: true })).toBeNull();
  });
});

describe('normalizeIp', () => {
  test('keeps plain IPv4 and IPv6', () => {
    expect(normalizeIp('172.28.0.1')).toBe('172.28.0.1');
    expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1');
  });

  test('turns IPv4-mapped IPv6 into plain IPv4', () => {
    expect(normalizeIp('::ffff:172.28.0.1')).toBe('172.28.0.1');
    expect(normalizeIp('::FFFF:203.0.113.9')).toBe('203.0.113.9');
  });

  test.each([[undefined], [null], [''], ['unknown'], ['999.1.1.1'], ['1.2.3.4, 5.6.7.8'], ['fe80::1%eth0']])(
    'rejects %j',
    (value) => {
      expect(normalizeIp(value)).toBeNull();
    },
  );
});

test('normalizePort accepts 0-65535 integers only', () => {
  expect(normalizePort(2222)).toBe(2222);
  expect(normalizePort(0)).toBe(0);
  expect(normalizePort(65536)).toBeNull();
  expect(normalizePort(-1)).toBeNull();
  expect(normalizePort('2222')).toBeNull();
  expect(normalizePort(undefined)).toBeNull();
});

test('normalizeSha256 lowercases valid hashes and rejects the rest', () => {
  const hash = 'b373fccc4859a5456245f7245d53feb68592a9179d484bf04fe49865919c9b05';
  expect(normalizeSha256(hash.toUpperCase())).toBe(hash);
  expect(normalizeSha256(hash.slice(1))).toBeNull();
  expect(normalizeSha256('z'.repeat(64))).toBeNull();
  expect(normalizeSha256(undefined)).toBeNull();
});

describe('characters PostgreSQL refuses', () => {
  test('NUL becomes the visible text \\u0000', () => {
    expect(text('ad\u0000min')).toBe('ad\\u0000min');
  });

  test('an unpaired surrogate becomes U+FFFD', () => {
    expect(text('a\uD800b')).toBe('a�b');
  });

  test('cleanDeep cleans nested values and keys', () => {
    expect(cleanDeep({ 'k\u0000': ['x\u0000', { y: '\uDC00' }], n: 1, b: true, z: null })).toEqual({
      'k\\u0000': ['x\\u0000', { y: '�' }],
      n: 1,
      b: true,
      z: null,
    });
  });
});

test('text turns numbers into strings and everything else into null', () => {
  expect(text(1234)).toBe('1234');
  expect(text(undefined)).toBeNull();
  expect(text({ a: 1 })).toBeNull();
  expect(text(NaN)).toBeNull();
});
