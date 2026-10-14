'use strict';

// Helpers shared by the three normalizers.
//
// A normalizer takes one log line (a string without its newline) and returns
// one of three results:
//
//   { status: 'rows',      rows, malware, warnings }  store these rows
//   { status: 'skipped',   reason }                    nothing to store, on purpose
//   { status: 'malformed', reason }                    bad input: warn and count
//
// Rows use the column names of the events table in db/init.sql. The normalizer
// sets source_seq; the tailer adds source_file, source_file_id and
// source_offset, because only it knows where the line came from.

const net = require('node:net');

// One events row with every column the normalizers fill, set to "empty".
function baseRow() {
  return {
    event_time: null,
    service: null,
    event_type: null,
    src_ip: null,
    src_port: null,
    session_id: null,
    username: null,
    password: null,
    command: null,
    http_method: null,
    http_path: null,
    user_agent: null,
    email: null,
    tags: [],
    raw: null,
    source_seq: 0,
  };
}

function rowsResult(rows, { malware = [], warnings = [] } = {}) {
  return { status: 'rows', rows, malware, warnings };
}

function skipped(reason) {
  return { status: 'skipped', reason };
}

function malformed(reason) {
  return { status: 'malformed', reason };
}

// Parses a line into a plain JSON object. Returns { empty: true } for a blank
// line, and { error } for anything else that is not an object (bad JSON, or
// valid JSON that is a number, string, array or null).
function parseLine(line) {
  if (line.trim() === '') return { empty: true };
  let value;
  try {
    value = JSON.parse(line);
  } catch {
    return { error: 'invalid_json' };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { error: 'not_a_json_object' };
  }
  return { value };
}

// PostgreSQL refuses two things that can legally appear in JSON strings: the
// NUL character (\u0000) and unpaired UTF-16 surrogates. An attacker controls
// usernames, passwords and commands, so either could end up in a log line, and
// one rejected insert would drop the whole line. Replace NUL with the visible
// six characters "\u0000" and broken surrogates with U+FFFD.
function cleanString(value) {
  return value.toWellFormed().replace(/\u0000/g, '\\u0000');
}

// cleanString applied to every string (keys included) inside a parsed line, so
// it can be stored as jsonb.
function cleanDeep(value) {
  if (typeof value === 'string') return cleanString(value);
  if (Array.isArray(value)) return value.map(cleanDeep);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[cleanString(key)] = cleanDeep(item);
    }
    return out;
  }
  return value;
}

// Value for a text column: strings are cleaned, numbers become strings,
// anything else (missing, null, objects) is NULL.
function text(value) {
  if (typeof value === 'string') return cleanString(value);
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
}

const ISO_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})?$/;

// Checks an ISO 8601 timestamp and returns it as a string PostgreSQL reads as
// one exact instant, or null if it is unusable.
//
// The string is returned instead of a JavaScript Date because Date keeps only
// milliseconds, while Cowrie and Dionaea write microseconds and timestamptz
// stores them.
//
// assumeUtc: Dionaea writes no zone ("2026-10-07T08:25:19.999267"). Its
// container clock is UTC, so for Dionaea a missing zone means UTC and "Z" is
// appended. For the other services a missing zone is an error, because the
// instant would be ambiguous.
function parseTimestamp(value, { assumeUtc = false } = {}) {
  if (typeof value !== 'string') return null;
  const match = ISO_TIMESTAMP.exec(value);
  if (!match) return null;

  const [, year, month, day, hour, minute, second, , zone] = match;
  // Reject impossible dates such as 2026-02-30 or 25:00, which the pattern
  // alone lets through.
  const date = new Date(Date.UTC(+year, +month - 1, +day, +hour, +minute, +second));
  if (
    date.getUTCFullYear() !== +year ||
    date.getUTCMonth() !== +month - 1 ||
    date.getUTCDate() !== +day ||
    date.getUTCHours() !== +hour ||
    date.getUTCMinutes() !== +minute ||
    date.getUTCSeconds() !== +second
  ) {
    return null;
  }

  if (zone) return value;
  return assumeUtc ? `${value}Z` : null;
}

// Returns a valid IP address as text for the inet column, or null.
//
// An IPv4 address written in IPv6 form ("::ffff:172.28.0.1") is turned into
// plain IPv4 ("172.28.0.1"). Both mean the same machine, but stored as text
// they would not match each other in a join with ip_reputation.
function normalizeIp(value) {
  if (typeof value !== 'string') return null;
  let ip = value.trim();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  // Zone suffixes such as "fe80::1%eth0" pass net.isIP but not inet.
  if (ip.includes('%')) return null;
  return net.isIP(ip) ? ip : null;
}

// A port number for the src_port column, or null when missing or out of range.
function normalizePort(value) {
  return Number.isInteger(value) && value >= 0 && value <= 65535 ? value : null;
}

// A SHA-256 hash as 64 lowercase hex characters (malware_samples requires
// lowercase), or null.
function normalizeSha256(value) {
  if (typeof value !== 'string') return null;
  const hash = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(hash) ? hash : null;
}

module.exports = {
  baseRow,
  rowsResult,
  skipped,
  malformed,
  parseLine,
  cleanString,
  cleanDeep,
  text,
  parseTimestamp,
  normalizeIp,
  normalizePort,
  normalizeSha256,
};
