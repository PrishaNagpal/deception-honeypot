'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { BinariesScanner } = require('../src/binaries');

let dir;
let stored;
let scanner;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'binaries-test-'));
  stored = [];
  scanner = new BinariesScanner({
    dir,
    upsertMalware: async (sample) => {
      stored.push(sample);
      return true;
    },
  });
});
afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

test('a file is hashed once it is unchanged on two scans in a row', async () => {
  await fs.writeFile(path.join(dir, '5d41402abc4b2a76b9719d911017c592'), 'MZ fake binary');

  await scanner.scan();
  expect(stored).toEqual([]);

  await scanner.scan();
  expect(stored).toEqual([{
    sha256: sha256('MZ fake binary'),
    service: 'dionaea',
    file_path: 'dionaea/binaries/5d41402abc4b2a76b9719d911017c592',
    file_size: 14,
    first_seen: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T.*Z$/),
    first_src_ip: null,
  }]);

  await scanner.scan();
  expect(stored).toHaveLength(1);
});

test('a file still growing is not hashed until it stops changing', async () => {
  const file = path.join(dir, 'growing');
  await fs.writeFile(file, 'part 1');
  await scanner.scan();
  await fs.appendFile(file, ' part 2');
  await scanner.scan();
  expect(stored).toEqual([]);

  await scanner.scan();
  expect(stored.map((s) => s.sha256)).toEqual([sha256('part 1 part 2')]);
});

test('hidden files and folders are ignored', async () => {
  await fs.writeFile(path.join(dir, '.gitkeep'), '');
  await fs.mkdir(path.join(dir, 'subdir'));
  await scanner.scan();
  await scanner.scan();
  expect(stored).toEqual([]);
});

test('a missing folder is not an error', async () => {
  const missing = new BinariesScanner({ dir: path.join(dir, 'nope'), upsertMalware: async () => true });
  await expect(missing.scan()).resolves.toBeUndefined();
});

test('if storing fails, the file is tried again on the next scan', async () => {
  let fail = true;
  const flaky = new BinariesScanner({
    dir,
    upsertMalware: async (sample) => {
      if (fail) {
        fail = false;
        throw new Error('database down');
      }
      stored.push(sample);
      return true;
    },
  });
  await fs.writeFile(path.join(dir, 'bin'), 'payload');
  await flaky.scan();
  await expect(flaky.scan()).rejects.toThrow('database down');
  await flaky.scan();
  expect(stored).toHaveLength(1);
});
