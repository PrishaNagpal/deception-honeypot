'use strict';

// Dionaea FTP/SMB decoy (dionaea.json): one line per connection, written when
// the connection closes, with everything that happened nested inside it.
//
// One line becomes several rows, always in this order so that re-reading a
// line gives the same source_seq values:
//   seq 0       <proto>.connection   the connection itself (ftp.data for
//                                    FTP's data channel)
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

// Connections whose seq-0 event type is not "<proto>.connection". Dionaea
// logs FTP's data channel (the second connection a client opens to send or
// receive a file) as its own connection: ftpdatalisten when the client
// connects in (passive mode, seen in our logs). ftpdatacon, where Dionaea
// connects out to the client (active mode), has not been seen yet but is the
// same channel. normalizeDionaea skips listen records first, so only real
// client traffic gets here.
const CONNECTION_EVENT_TYPES = {
  ftpdatalisten: 'ftp.data',
  ftpdatacon: 'ftp.data',
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

  addRow(CONNECTION_EVENT_TYPES[connection.protocol] ?? `${protocol}.connection`);

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
