'use strict';

// Cowrie SSH decoy (cowrie.json): one line per event, many events per SSH
// session, tied together by the session id. One line becomes one row, except
// the event types listed in SKIPPED_EVENTS, which become none.

const {
  baseRow,
  rowsResult,
  skipped,
  malformed,
  parseLine,
  cleanDeep,
  text,
  parseTimestamp,
  normalizeIp,
  normalizePort,
  normalizeSha256,
} = require('./common');

// Known noise. Everything not listed here is stored, so event types added in a
// future Cowrie version are kept rather than silently dropped.
const SKIPPED_EVENTS = new Set([
  // The attacker's terminal width and height.
  'cowrie.client.size',
  // The fake system architecture Cowrie pretends to be: our setting, not
  // attacker behaviour.
  'cowrie.session.params',
  // Cowrie finished writing its terminal recording. The session length is
  // already in cowrie.session.closed.
  'cowrie.log.closed',
]);

// Events whose input field is what the attacker typed.
const COMMAND_EVENTS = new Set(['cowrie.command.input', 'cowrie.command.failed']);

// Events that carry the SHA-256 of a file the attacker fetched or uploaded.
const FILE_EVENTS = new Set(['cowrie.session.file_download', 'cowrie.session.file_upload']);

function normalizeCowrie(line) {
  const parsed = parseLine(line);
  if (parsed.empty) return skipped('empty_line');
  if (parsed.error) return malformed(parsed.error);
  const record = parsed.value;

  const eventId = record.eventid;
  if (typeof eventId !== 'string' || !eventId.startsWith('cowrie.')) {
    return malformed('missing_eventid');
  }
  if (SKIPPED_EVENTS.has(eventId)) return skipped(eventId);

  const eventTime = parseTimestamp(record.timestamp);
  if (!eventTime) return malformed('invalid_timestamp');

  // Cowrie takes src_ip from the TCP connection itself, so the attacker cannot
  // choose it. An unusable value means a damaged line, not an attack.
  const srcIp = normalizeIp(record.src_ip);
  if (!srcIp) return malformed('invalid_src_ip');

  const row = baseRow();
  Object.assign(row, {
    event_time: eventTime,
    service: 'cowrie',
    event_type: eventId,
    src_ip: srcIp,
    src_port: normalizePort(record.src_port),
    session_id: text(record.session),
    username: text(record.username),
    password: text(record.password),
    command: COMMAND_EVENTS.has(eventId) ? text(record.input) : null,
    raw: cleanDeep(record),
  });

  const malware = [];
  const warnings = [];
  if (FILE_EVENTS.has(eventId)) {
    const sha256 = normalizeSha256(record.shasum);
    if (sha256) {
      malware.push({
        sha256,
        service: 'cowrie',
        file_path: text(record.outfile) ?? text(record.filename),
        file_size: null,
        first_seen: eventTime,
        first_src_ip: srcIp,
      });
    } else {
      warnings.push({
        code: 'invalid_shasum',
        message: `${eventId} without a valid shasum: ${JSON.stringify(record.shasum)}`,
      });
    }
  }

  return rowsResult([row], { malware, warnings });
}

module.exports = { normalizeCowrie, SKIPPED_EVENTS };
