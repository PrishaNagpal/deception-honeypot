'use strict';

// Reads a growing log file line by line, by polling.
//
// Why polling: fs.watch relies on the operating system announcing changes,
// and Docker Desktop bind mounts on WSL often never deliver those
// announcements. Asking "how big is the file now?" once a second cannot miss
// anything.
//
// Words used below:
//   position   byte offset in the file of the next line to hand out. Bytes
//              read after it but not yet ending in a newline wait in `pending`.
//   file id    sha256 of the file's first line. It identifies the file's
//              content, not its name, so a copy or a renamed file keeps its
//              id, and a new file at the same path gets a new one.
//
// The tailer only reads. What happens to each line is up to onLine, which may
// be slow (it writes to the database) or throw (database down). When onLine
// throws, the tailer keeps its place, so the same line is handed out again on
// the next poll and nothing is lost.

const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const path = require('node:path');

const NEWLINE = 0x0a;
const CHUNK_BYTES = 64 * 1024;
const noop = () => {};

class FileTailer {
  // onLine({ line, offset, fileId, path })            async, may throw
  // onMalformed({ reason, offset, fileId, path })      bytes that are not a usable line
  // getResumeOffset(fileId) -> offset or null          async: where to restart reading
  constructor({ filePath, onLine, onMalformed = noop, getResumeOffset, maxLineBytes, log = {} }) {
    this.path = filePath;
    this.onLine = onLine;
    this.onMalformed = onMalformed;
    this.getResumeOffset = getResumeOffset;
    this.maxLineBytes = maxLineBytes;
    this.log = { info: log.info ?? noop, warn: log.warn ?? noop };

    this.handle = null; // the open file
    this.dev = null; // which file is open: device and inode numbers
    this.ino = null;
    this.waitingLogged = false;
    this.resetFileState();
  }

  resetFileState() {
    this.fileId = null; // null until the first line is complete
    this.position = 0;
    this.pending = Buffer.alloc(0);
    this.discarding = false; // inside a line longer than maxLineBytes
    this.checkedSize = -1; // file size when the file id was last verified
  }

  // Reads everything new since the last poll. Throws only when onLine or
  // getResumeOffset throws; the next poll then retries from the same line.
  async poll() {
    if (!this.handle) {
      if (!(await this.open())) return;
    } else {
      const change = await this.pathChange();
      if (change) {
        // Finish the old file through the open handle (a renamed or deleted
        // file can still be read), then move on.
        await this.finish(change);
        if (change === 'deleted' || !(await this.open())) return;
      }
    }

    if (this.fileId === null && !(await this.start())) return;
    if (await this.checkReplaced()) {
      if (!(await this.start())) return;
    }
    await this.readToEnd();
  }

  // Reads to the end once, reports an unfinished last line, and closes. For
  // rotated files, which will not grow any more.
  async drainOnce() {
    try {
      await this.poll();
      if (this.handle && this.fileId !== null) {
        this.reportUnfinishedLine();
      }
    } finally {
      await this.close();
    }
  }

  async close() {
    if (this.handle) {
      await this.handle.close().catch(noop);
      this.handle = null;
    }
    this.resetFileState();
  }

  // Opens the path. Returns false if it does not exist (yet).
  async open() {
    let handle;
    try {
      handle = await fs.open(this.path, 'r');
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      if (!this.waitingLogged) {
        this.log.info('waiting for file', { file: this.path });
        this.waitingLogged = true;
      }
      return false;
    }
    const stat = await handle.stat();
    this.handle = handle;
    this.dev = stat.dev;
    this.ino = stat.ino;
    this.waitingLogged = false;
    this.resetFileState();
    return true;
  }

  // Compares the path with the open file: 'deleted', 'rotated' (the path now
  // names a different file) or null (same file).
  async pathChange() {
    let stat;
    try {
      stat = await fs.stat(this.path);
    } catch (err) {
      if (err.code === 'ENOENT') return 'deleted';
      throw err;
    }
    return stat.dev !== this.dev || stat.ino !== this.ino ? 'rotated' : null;
  }

  // Reads the rest of the open file, then closes it.
  async finish(reason) {
    if (this.fileId !== null) {
      await this.readToEnd();
      this.reportUnfinishedLine();
    }
    this.log.info(`file ${reason}`, { file: this.path, file_id: short(this.fileId), read_to: this.position });
    await this.handle.close().catch(noop);
    this.handle = null;
    this.resetFileState();
  }

  // Computes the file id and asks where to resume. Returns false while the
  // first line is still incomplete (empty or half-written file).
  async start() {
    const fileId = await this.fingerprint();
    if (fileId === null) return false;

    const { size } = await this.handle.stat();
    let resumeAt = await this.getResumeOffset(fileId);
    if (resumeAt !== null && resumeAt > size) {
      this.log.warn('stored offset is past the end of the file, reading from the start', {
        file: this.path, file_id: short(fileId), stored_offset: resumeAt, size,
      });
      resumeAt = null;
    }

    this.fileId = fileId;
    this.position = resumeAt ?? 0;
    this.checkedSize = size;
    this.log.info('reading file', {
      file: this.path, file_id: short(fileId), from_offset: this.position, size,
    });
    return true;
  }

  // Detects a file emptied or rewritten in place (same inode). Returns true
  // when reading must start over as a new file.
  async checkReplaced() {
    const { size } = await this.handle.stat();
    let reason = null;
    if (size < this.position + this.pending.length) {
      reason = 'truncated';
    } else if (size !== this.checkedSize) {
      // The file changed size. Make sure it still starts with the same line,
      // in case it was emptied and refilled between two polls.
      const fileId = await this.fingerprint();
      if (fileId !== this.fileId) reason = 'replaced';
      this.checkedSize = size;
    }
    if (!reason) return false;

    this.log.info(`file ${reason}`, { file: this.path, old_file_id: short(this.fileId), size });
    this.resetFileState();
    return true;
  }

  // sha256 of the first line, or null if it has no newline yet. A first line
  // longer than maxLineBytes is identified by its first maxLineBytes bytes.
  async fingerprint() {
    const chunks = [];
    let total = 0;
    while (total < this.maxLineBytes) {
      const want = Math.min(CHUNK_BYTES, this.maxLineBytes - total);
      const buffer = Buffer.alloc(want);
      const { bytesRead } = await this.handle.read(buffer, 0, want, total);
      if (bytesRead === 0) return null;
      const chunk = buffer.subarray(0, bytesRead);
      const newline = chunk.indexOf(NEWLINE);
      if (newline !== -1) {
        chunks.push(chunk.subarray(0, newline));
        return sha256(Buffer.concat(chunks));
      }
      chunks.push(chunk);
      total += bytesRead;
    }
    return sha256(Buffer.concat(chunks));
  }

  async readToEnd() {
    // Lines left over from a poll where onLine threw come first, even if the
    // file has not grown since.
    await this.emitLines();
    for (;;) {
      const readFrom = this.position + this.pending.length;
      const buffer = Buffer.alloc(CHUNK_BYTES);
      const { bytesRead } = await this.handle.read(buffer, 0, CHUNK_BYTES, readFrom);
      if (bytesRead === 0) return;
      this.pending = Buffer.concat([this.pending, buffer.subarray(0, bytesRead)]);
      await this.emitLines();
    }
  }

  // Hands out every complete line in `pending`. `position` only moves past a
  // line after onLine has succeeded.
  async emitLines() {
    let newline;
    while ((newline = this.pending.indexOf(NEWLINE)) !== -1) {
      if (this.discarding) {
        // End of an over-long line: drop it, carry on after it.
        this.discarding = false;
      } else if (newline > this.maxLineBytes) {
        this.malformed('line_too_long', this.position);
      } else {
        const line = this.pending.subarray(0, newline).toString('utf8');
        await this.onLine({ line, offset: this.position, fileId: this.fileId, path: this.path });
      }
      this.position += newline + 1;
      this.pending = this.pending.subarray(newline + 1);
    }

    // No newline left. If the unfinished line is already too long, report it
    // once and drop the bytes until its newline arrives, so an endless line
    // cannot fill memory.
    if (!this.discarding && this.pending.length > this.maxLineBytes) {
      this.malformed('line_too_long', this.position);
      this.discarding = true;
    }
    if (this.discarding) {
      this.position += this.pending.length;
      this.pending = Buffer.alloc(0);
    }
  }

  // A file that will not grow any more ends without a newline.
  reportUnfinishedLine() {
    if (this.pending.length > 0 && !this.discarding) {
      this.malformed('incomplete_last_line', this.position);
    }
  }

  malformed(reason, offset) {
    this.onMalformed({ reason, offset, fileId: this.fileId, path: this.path });
  }
}

// A log file plus its rotated copies in the same folder: for cowrie.json,
// files such as cowrie.json.2026-10-13. The live file is followed by one
// tailer that stays open. Each rotated copy is read once to the end and
// closed, and read again only if its size or inode changes.
class LogSource {
  // makeTailer(filePath) -> FileTailer
  constructor({ livePath, makeTailer }) {
    this.livePath = livePath;
    this.dir = path.dirname(livePath);
    this.rotatedPattern = new RegExp(`^${escapeRegExp(path.basename(livePath))}\\..+$`);
    this.makeTailer = makeTailer;
    this.live = makeTailer(livePath);
    this.rotatedDone = new Map(); // path -> "dev:ino:size" when last read
  }

  async poll() {
    await this.pollRotated();
    await this.live.poll();
  }

  async pollRotated() {
    let names;
    try {
      names = await fs.readdir(this.dir);
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
    for (const name of names.filter((n) => this.rotatedPattern.test(n)).sort()) {
      const filePath = path.join(this.dir, name);
      let stat;
      try {
        stat = await fs.stat(filePath);
      } catch (err) {
        if (err.code === 'ENOENT') continue;
        throw err;
      }
      if (!stat.isFile()) continue;
      const key = `${stat.dev}:${stat.ino}:${stat.size}`;
      if (this.rotatedDone.get(filePath) === key) continue;
      await this.makeTailer(filePath).drainOnce();
      this.rotatedDone.set(filePath, key);
    }
  }

  async close() {
    await this.live.close();
  }
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function short(fileId) {
  return fileId ? fileId.slice(0, 12) : null;
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = { FileTailer, LogSource, sha256 };
