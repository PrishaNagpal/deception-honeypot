'use strict';

// Dionaea FTP/SMB decoy (dionaea.json): one line per connection, written when
// the connection closes, with everything that happened nested inside it.
//
// One line becomes several rows, always in this order so that re-reading a
// line gives the same source_seq values:
//   seq 0       <proto>.connection   the connection itself
//   then        <proto>.login        one per entry in credentials[]
//   then        <proto>.command      one per entry in ftp.commands[]

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
} = require('./common');

// Dionaea's protocol names end in "d" for daemon. The event types use the
// plain protocol name. Unknown protocols are used unchanged.
const PROTOCOL_NAMES = {
  ftpd: 'ftp',
  smbd: 'smb',
  httpd: 'http',
  mssqld: 'mssql',
  mysqld: 'mysql',
  tftpd: 'tftp',
  pptpd: 'pptp',
  mqttd: 'mqtt',
  sipd: 'sip',
};

function normalizeDionaea(line) {
  const parsed = parseLine(line);
  if (parsed.empty) return skipped('empty_line');
  if (parsed.error) return malformed(parsed.error);
  const record = parsed.value;

  const connection = record.connection;
  if (connection === null || typeof connection !== 'object' || typeof connection.protocol !== 'string') {
    return malformed('missing_connection');
  }
  // Dionaea opening a port to listen on, not an attacker. src_ip is empty.
  if (connection.type === 'listen') return skipped('listen');

  const eventTime = parseTimestamp(record.timestamp, { assumeUtc: true });
  if (!eventTime) return malformed('invalid_timestamp');

  // Taken from the TCP connection, so an unusable value means a damaged line.
  const srcIp = normalizeIp(record.src_ip);
  if (!srcIp) return malformed('invalid_src_ip');

  const protocol = PROTOCOL_NAMES[connection.protocol] ?? connection.protocol;
  const raw = cleanDeep(record);
  const warnings = [];
  const rows = [];

  function addRow(eventType, fields = {}) {
    rows.push(Object.assign(baseRow(), {
      event_time: eventTime,
      service: 'dionaea',
      event_type: eventType,
      src_ip: srcIp,
      src_port: normalizePort(record.src_port),
      raw,
      source_seq: rows.length,
    }, fields));
  }

  addRow(`${protocol}.connection`);

  for (const credential of listOf(record.credentials)) {
    if (credential === null || typeof credential !== 'object') {
      warnings.push({ code: 'bad_item', message: 'credentials[] entry is not an object' });
      continue;
    }
    addRow(`${protocol}.login`, {
      username: text(credential.username),
      password: text(credential.password),
    });
  }

  for (const entry of listOf(record.ftp?.commands)) {
    if (entry === null || typeof entry !== 'object' || typeof entry.command !== 'string') {
      warnings.push({ code: 'bad_item', message: 'ftp.commands[] entry has no command' });
      continue;
    }
    const args = listOf(entry.arguments).map(text).filter((arg) => arg !== null);
    addRow(`${protocol}.command`, { command: text([entry.command, ...args].join(' ')) });
  }

  return rowsResult(rows, { warnings });
}

function listOf(value) {
  return Array.isArray(value) ? value : [];
}

module.exports = { normalizeDionaea };
