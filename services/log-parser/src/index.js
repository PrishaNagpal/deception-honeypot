'use strict';

// Entry point: node src/index.js
//
// Starts one polling loop per honeypot log, one per Dionaea file folder
// (downloaded binaries and FTP uploads), and a summary line every 60 seconds.
// Stops cleanly on Ctrl+C or `docker stop` (SIGINT / SIGTERM): the line being
// stored is finished, nothing is half written, and the next start resumes
// from the database.

const { loadConfig, describeConfig } = require('./config');
const { createLogger, createStats } = require('./logger');
const { createPool, createDb, LineRejectedError } = require('./db');
const { FileTailer, LogSource } = require('./tailer');
const { BinariesScanner } = require('./binaries');
const normalizers = require('./normalize');

const MAX_BACKOFF_MS = 30_000;
const PREVIEW_CHARS = 120;

// Thrown inside a loop when shutdown has been requested, so a long read stops
// between two lines instead of at the end of the file.
class StoppingError extends Error {}

// Decides what happens to one complete log line. Throws only when the line
// should be retried later (database unreachable, or shutting down); the
// tailer then keeps its place.
async function processLine({ db, stats, log, signal }, service, { line, offset, fileId, path }) {
  if (signal?.aborted) throw new StoppingError();
  const counts = stats.services[service];
  const result = normalizers[service](line);

  if (result.status === 'skipped') {
    counts.skipped += 1;
  } else if (result.status === 'malformed') {
    stats.addMalformed(service, result.reason);
    log.warn('malformed line', { service, file: path, offset, reason: result.reason, preview: preview(line) });
  } else {
    const rows = result.rows.map((row) => ({
      ...row,
      source_file: path,
      source_file_id: fileId,
      source_offset: offset,
    }));
    let stored;
    try {
      stored = await db.insertLine({ rows, malware: result.malware });
    } catch (err) {
      if (!(err instanceof LineRejectedError)) throw err;
      stats.addMalformed(service, 'db_rejected');
      log.warn('malformed line', { service, file: path, offset, reason: 'db_rejected', error: err.cause.message });
      counts.lines += 1;
      return;
    }

    counts.rows_inserted += stored.inserted;
    stats.malware.new_samples += stored.newMalware;
    if (stored.inserted === 0) {
      counts.already_stored += 1;
    } else {
      // Only for newly stored lines, so a re-read after a restart does not
      // count or log the same problem twice.
      for (const warning of result.warnings) {
        if (warning.code === 'invalid_src_ip') counts.invalid_src_ip += 1;
        log.warn(warning.message, { service, file: path, offset, code: warning.code });
      }
    }
  }
  counts.lines += 1;
}

function preview(line) {
  return line.length > PREVIEW_CHARS ? `${line.slice(0, PREVIEW_CHARS)}...` : line;
}

// Runs fn every intervalMs until the signal fires. A failure is logged and
// retried after 1 s, 2 s, 4 s ... up to 30 s; success returns to the normal
// interval.
async function runLoop(name, intervalMs, fn, { log, signal }) {
  let failures = 0;
  while (!signal.aborted) {
    try {
      await fn();
      if (failures > 0) log.info(`${name} recovered`, { after_failures: failures });
      failures = 0;
    } catch (err) {
      if (err instanceof StoppingError) break;
      failures += 1;
      const retryMs = Math.min(1000 * 2 ** (failures - 1), MAX_BACKOFF_MS);
      log.error(`${name} failed`, { error: err.message, retry_in_s: retryMs / 1000 });
      await sleep(retryMs, signal);
      continue;
    }
    await sleep(intervalMs, signal);
  }
}

// Tries the database until it answers. Returns false if stopped first.
async function waitForDatabase(db, config, { log, signal }) {
  let failures = 0;
  while (!signal.aborted) {
    try {
      await db.ping();
      log.info('database connected', { host: config.db.host, port: config.db.port });
      return true;
    } catch (err) {
      failures += 1;
      const retryMs = Math.min(1000 * 2 ** (failures - 1), MAX_BACKOFF_MS);
      log.error('database not reachable', { error: err.message, retry_in_s: retryMs / 1000 });
      await sleep(retryMs, signal);
    }
  }
  return false;
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    }
    signal.addEventListener('abort', done, { once: true });
  });
}

async function main() {
  const log = createLogger();
  const config = loadConfig();
  const safe = describeConfig(config);
  log.info('starting', { node: process.version, db: safe.db, logs: safe.logs, binaries: safe.binariesDir, uploads: safe.uploadsDir });

  if (!config.db.user || !config.db.password) {
    log.error('database user or password not set (PGUSER/PGPASSWORD or POSTGRES_USER/POSTGRES_PASSWORD)');
    process.exitCode = 1;
    return;
  }

  const controller = new AbortController();
  const { signal } = controller;
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.once(sig, () => {
      log.info('stopping', { signal: sig });
      controller.abort();
    });
  }

  const stats = createStats();
  const pool = createPool(config.db, { log });
  const db = createDb(pool);
  const ctx = { db, stats, log, signal };

  const sources = [];
  const loops = [];
  if (await waitForDatabase(db, config, { log, signal })) {
    for (const [service, livePath] of Object.entries(config.logs)) {
      if (!livePath) continue;
      const source = new LogSource({
        livePath,
        makeTailer: (filePath) => new FileTailer({
          filePath,
          maxLineBytes: config.maxLineBytes,
          log,
          getResumeOffset: (fileId) => db.getResumeOffset(service, fileId),
          onLine: (lineInfo) => processLine(ctx, service, lineInfo),
          onMalformed: ({ reason, offset, path }) => {
            stats.addMalformed(service, reason);
            stats.services[service].lines += 1;
            log.warn('malformed line', { service, file: path, offset, reason });
          },
        }),
      });
      sources.push(source);
      loops.push(runLoop(`${service} log`, config.pollIntervalMs, () => source.poll(), { log, signal }));
    }

    const fileFolders = [
      { name: 'dionaea binaries', dir: config.binariesDir, pathPrefix: 'dionaea/binaries' },
      { name: 'dionaea ftp uploads', dir: config.uploadsDir, pathPrefix: 'dionaea/ftp/root' },
    ];
    for (const { name, dir, pathPrefix } of fileFolders) {
      if (!dir) continue;
      const scanner = new BinariesScanner({
        dir,
        pathPrefix,
        log,
        upsertMalware: (sample) => db.upsertMalware(sample),
        onHashed: ({ isNew }) => {
          stats.malware.files_hashed += 1;
          if (isNew) stats.malware.new_samples += 1;
        },
      });
      loops.push(runLoop(name, config.binariesIntervalMs, () => scanner.scan(), { log, signal }));
    }
  }

  const summaryTimer = setInterval(() => log.info(stats.summaryLine()), config.summaryIntervalMs);

  await Promise.all(loops);
  clearInterval(summaryTimer);
  await Promise.all(sources.map((source) => source.close()));
  log.info(stats.summaryLine());
  await pool.end();
  log.info('stopped');
}

if (require.main === module) {
  main().catch((err) => {
    // Only startup problems (e.g. an invalid setting) get here; log and line
    // errors are handled inside the loops.
    process.stderr.write(`${new Date().toISOString()} ERROR fatal ${err.stack}\n`);
    process.exitCode = 1;
  });
}

module.exports = { processLine, runLoop, sleep, StoppingError };
