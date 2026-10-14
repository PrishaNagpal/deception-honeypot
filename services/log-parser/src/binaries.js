'use strict';

// Finds files Dionaea captured (its binaries folder, files named by MD5) and
// adds their SHA-256 to malware_samples for the VirusTotal enrichment.
//
// A file is hashed only once its size and modification time are the same on
// two scans in a row, so a file still being written is never hashed half-way.
// Each file is hashed once per parser run; a re-insert after a restart changes
// nothing in the database.

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

class BinariesScanner {
  // upsertMalware(sample) -> true when the sha256 is new
  constructor({ dir, upsertMalware, onHashed = () => {}, log = {} }) {
    this.dir = dir;
    this.upsertMalware = upsertMalware;
    this.onHashed = onHashed;
    this.log = { info: log.info ?? (() => {}), warn: log.warn ?? (() => {}) };
    this.seen = new Map(); // name -> "size:mtime" at the previous scan
    this.hashed = new Map(); // name -> "size:mtime" when hashed and stored
    this.missingLogged = false;
  }

  async scan() {
    let entries;
    try {
      entries = await fsp.readdir(this.dir, { withFileTypes: true });
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      if (!this.missingLogged) {
        this.log.info('binaries folder not found yet', { dir: this.dir });
        this.missingLogged = true;
      }
      return;
    }
    this.missingLogged = false;

    for (const entry of entries) {
      if (!entry.isFile() || entry.name.startsWith('.')) continue;
      const filePath = path.join(this.dir, entry.name);
      let stat;
      try {
        stat = await fsp.stat(filePath);
      } catch (err) {
        if (err.code === 'ENOENT') continue;
        throw err;
      }
      const key = `${stat.size}:${stat.mtimeMs}`;
      if (this.hashed.get(entry.name) === key) continue;
      if (this.seen.get(entry.name) !== key) {
        this.seen.set(entry.name, key); // changed since last scan: wait
        continue;
      }

      const sha256 = await hashFile(filePath);
      const isNew = await this.upsertMalware({
        sha256,
        service: 'dionaea',
        // Relative to Dionaea's var/lib, the same locally and in Docker.
        file_path: `dionaea/binaries/${entry.name}`,
        file_size: stat.size,
        first_seen: stat.mtime.toISOString(),
        first_src_ip: null,
      });
      this.hashed.set(entry.name, key);
      this.seen.delete(entry.name);
      this.onHashed({ sha256, isNew });
      this.log.info('binary hashed', { file: entry.name, sha256, size: stat.size, new: isNew });
    }
  }
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
