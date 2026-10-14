'use strict';

// Finds files Dionaea stored and adds their SHA-256 to malware_samples for the
// VirusTotal enrichment. One scanner per folder:
//   dionaea/binaries/   files Dionaea downloaded itself, named by MD5
//   dionaea/ftp/root/   files attackers uploaded over FTP, under the name
//                       they chose (possibly inside folders they created)
//
// Subfolders are scanned too; symbolic links are not followed. A file is
// hashed only once its size and modification time are the same on two scans
// in a row, so a file still being written is never hashed half-way. Each
// version of a file is hashed once per parser run; a re-insert after a
// restart changes nothing in the database.

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

class BinariesScanner {
  // dir         folder to scan
  // pathPrefix  stored before the file's path inside dir in file_path, e.g.
  //             'dionaea/binaries', so the value is the same locally and in
  //             Docker
  // upsertMalware(sample) -> true when the sha256 is new
  constructor({ dir, pathPrefix, upsertMalware, onHashed = () => {}, log = {} }) {
    this.dir = dir;
    this.pathPrefix = pathPrefix;
    this.upsertMalware = upsertMalware;
    this.onHashed = onHashed;
    this.log = { info: log.info ?? (() => {}), warn: log.warn ?? (() => {}) };
    this.seen = new Map(); // relative path -> "size:mtime" at the previous scan
    this.hashed = new Map(); // relative path -> "size:mtime" when hashed and stored
    this.missingLogged = false;
  }

  async scan() {
    let files;
    try {
      files = await listFiles(this.dir);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      if (!this.missingLogged) {
        this.log.info('folder not found yet', { dir: this.dir });
        this.missingLogged = true;
      }
      return;
    }
    this.missingLogged = false;

    for (const relative of files) {
      const filePath = path.join(this.dir, relative);
      let stat;
      try {
        stat = await fsp.stat(filePath);
      } catch (err) {
        if (err.code === 'ENOENT') continue;
        throw err;
      }
      const key = `${stat.size}:${stat.mtimeMs}`;
      if (this.hashed.get(relative) === key) continue;
      if (this.seen.get(relative) !== key) {
        this.seen.set(relative, key); // changed since last scan: wait
        continue;
      }

      const sha256 = await hashFile(filePath);
      const storedPath = path.posix.join(this.pathPrefix, relative.split(path.sep).join('/'));
      const isNew = await this.upsertMalware({
        sha256,
        service: 'dionaea',
        file_path: storedPath,
        file_size: stat.size,
        first_seen: stat.mtime.toISOString(),
        first_src_ip: null,
      });
      this.hashed.set(relative, key);
      this.seen.delete(relative);
      this.onHashed({ sha256, isNew });
      this.log.info('file hashed', { file: storedPath, sha256, size: stat.size, new: isNew });
    }
  }
}

// Paths of all regular files under dir, relative to it, skipping names that
// start with a dot and symbolic links.
async function listFiles(dir, prefix = '') {
  const entries = await fsp.readdir(path.join(dir, prefix), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const relative = path.join(prefix, entry.name);
    if (entry.isFile()) {
      files.push(relative);
    } else if (entry.isDirectory()) {
      try {
        files.push(...(await listFiles(dir, relative)));
      } catch (err) {
        // A subfolder removed between listing and reading it.
        if (err.code !== 'ENOENT') throw err;
      }
    }
  }
  return files.sort();
}

// Streams the file through SHA-256, so large files are not loaded into memory.
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(filePath)
      .on('error', reject)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')));
  });
}

module.exports = { BinariesScanner, hashFile };
