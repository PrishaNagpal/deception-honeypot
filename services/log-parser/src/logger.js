'use strict';

// Plain-text log lines on stdout (stderr for warnings and errors), which is
// where `docker logs` looks in Stage 3:
//
//   2026-10-14T07:40:00.123Z WARN malformed line service=cowrie offset=812 reason=invalid_json
//
// Also keeps the counters behind the summary line.

const SERVICES = ['flask-http', 'cowrie', 'dionaea'];

function formatValue(value) {
  if (typeof value === 'string' && /^[^\s"=]+$/.test(value)) return value;
  return JSON.stringify(value);
}

function createLogger({ write = defaultWrite } = {}) {
  function log(level, message, fields = {}) {
    const parts = [new Date().toISOString(), level, message];
    for (const [key, value] of Object.entries(fields)) {
      if (value !== undefined) parts.push(`${key}=${formatValue(value)}`);
    }
    write(level, parts.join(' '));
  }

  return {
    info: (message, fields) => log('INFO', message, fields),
    warn: (message, fields) => log('WARN', message, fields),
    error: (message, fields) => log('ERROR', message, fields),
  };
}

function defaultWrite(level, line) {
  (level === 'INFO' ? process.stdout : process.stderr).write(`${line}\n`);
}

// Counters since the parser started. Per service:
//   lines           complete lines read
//   rows_inserted   new rows written to events
//   already_stored  lines whose rows were all in the database already
//                   (re-read after a restart or a file copy)
//   skipped         lines with nothing to store on purpose (noise eventids,
//                   Dionaea listen records, blank lines)
//   malformed       lines that could not be used, by reason
//   invalid_src_ip  Flask lines stored with src_ip 0.0.0.0
// Plus malware rows: new sha256 values, and files hashed from Dionaea's
// binaries and FTP upload folders.
function createStats(now = () => Date.now()) {
  const startedAt = now();
  const services = {};
  for (const service of SERVICES) {
    services[service] = {
      lines: 0,
      rows_inserted: 0,
      already_stored: 0,
      skipped: 0,
      malformed: {},
      invalid_src_ip: 0,
    };
  }
  const malware = { new_samples: 0, files_hashed: 0 };

  function summaryLine() {
    const uptime = Math.round((now() - startedAt) / 1000);
    const parts = [`summary uptime=${uptime}s`];
    for (const [service, s] of Object.entries(services)) {
      const malformedTotal = Object.values(s.malformed).reduce((a, b) => a + b, 0);
      const reasons = Object.entries(s.malformed).map(([r, n]) => `${r}:${n}`).join(',');
      parts.push(
        `| ${service} lines=${s.lines} inserted=${s.rows_inserted} already_stored=${s.already_stored}` +
          ` skipped=${s.skipped} malformed=${malformedTotal}${reasons ? `(${reasons})` : ''}` +
          (service === 'flask-http' ? ` invalid_src_ip=${s.invalid_src_ip}` : ''),
      );
    }
    parts.push(`| malware new_samples=${malware.new_samples} files_hashed=${malware.files_hashed}`);
    return parts.join(' ');
  }

  return {
    services,
    malware,
    addMalformed(service, reason) {
      const counts = services[service].malformed;
      counts[reason] = (counts[reason] ?? 0) + 1;
    },
    summaryLine,
  };
}

module.exports = { createLogger, createStats, SERVICES };
