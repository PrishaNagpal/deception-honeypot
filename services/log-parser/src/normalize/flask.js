'use strict';

// Flask decoy (data/flask/http.json): one line per login or signup form post.
// One line becomes one row.

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
} = require('./common');

const EVENT_TYPE_BY_PATH = {
  '/login': 'http_login',
  '/signup': 'http_signup',
};

// Stored instead of a src_ip that is not a valid IP address.
const INVALID_SRC_IP = '0.0.0.0';

function normalizeFlask(line) {
  const parsed = parseLine(line);
  if (parsed.empty) return skipped('empty_line');
  if (parsed.error) return malformed(parsed.error);
  const record = parsed.value;

  const eventTime = parseTimestamp(record.timestamp);
  if (!eventTime) return malformed('invalid_timestamp');

  const row = baseRow();
  const warnings = [];
  const tags = Array.isArray(record.tags)
    ? record.tags.filter((tag) => typeof tag === 'string').map(text)
    : [];

  // The Flask app takes src_ip from the X-Forwarded-For header when one is
  // sent, and that header is written by the client. An attacker can therefore
  // put anything there: a fake address, or text that is not an address at all.
  //
  // If lines with an unusable src_ip were skipped, sending a garbage header
  // would hide an attack from the database entirely. So the event is kept:
  // src_ip becomes 0.0.0.0 (the column cannot be empty), the tag
  // invalid_src_ip marks it, and the value the attacker sent stays in raw. The
  // warning lets the parser count these separately.
  //
  // A fake but valid address cannot be detected here and is stored as sent.
  let srcIp = normalizeIp(record.src_ip);
  if (!srcIp) {
    srcIp = INVALID_SRC_IP;
    tags.push('invalid_src_ip');
    warnings.push({
      code: 'invalid_src_ip',
      message: `invalid src_ip ${JSON.stringify(record.src_ip)}, stored as ${INVALID_SRC_IP}`,
    });
  }

  const path = text(record.path);
  Object.assign(row, {
    event_time: eventTime,
    service: 'flask-http',
    event_type: EVENT_TYPE_BY_PATH[path] ?? 'http_request',
    src_ip: srcIp,
    username: text(record.username),
    password: text(record.password),
    http_method: text(record.method),
    http_path: path,
    user_agent: text(record.user_agent),
    email: text(record.email),
    tags,
    raw: cleanDeep(record),
  });

  return rowsResult([row], { warnings });
}

module.exports = { normalizeFlask, INVALID_SRC_IP };
