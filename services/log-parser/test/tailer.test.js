'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { FileTailer, LogSource, sha256 } = require('../src/tailer');

let dir;
beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'tailer-test-'));
});
afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

// A tailer that records what it hands out. resume maps file id -> offset.
function makeTailer(filePath, { resume = {}, maxLineBytes = 1024 * 1024, onLine } = {}) {
  const lines = [];
  const malformed = [];
  const tailer = new FileTailer({
    filePath,
    maxLineBytes,
    getResumeOffset: async (fileId) => resume[fileId] ?? null,
    onLine: async (info) => {
      if (onLine) await onLine(info);
      lines.push(info);
    },
    onMalformed: (info) => malformed.push(info),
  });
  return { tailer, lines, malformed };
}

const file = (name = 'app.json') => path.join(dir, name);
const texts = (lines) => lines.map((l) => l.line);

test('hands out complete lines with the byte offset where each starts', async () => {
  // "é" is two bytes in UTF-8, so byte offsets differ from character counts.
  await fs.writeFile(file(), '{"a":"é"}\n{"b":2}\n');
  const { tailer, lines } = makeTailer(file());

  await tailer.poll();

  expect(lines.map(({ line, offset }) => [line, offset])).toEqual([
    ['{"a":"é"}', 0],
    ['{"b":2}', 11],
  ]);
  expect(lines[0].fileId).toBe(sha256(Buffer.from('{"a":"é"}')));
  await tailer.close();
});

test('new lines appended later are picked up by the next poll', async () => {
  await fs.writeFile(file(), 'one\n');
  const { tailer, lines } = makeTailer(file());
  await tailer.poll();
  await fs.appendFile(file(), 'two\nthree\n');
  await tailer.poll();
  await tailer.poll();

  expect(texts(lines)).toEqual(['one', 'two', 'three']);
  expect(lines.map((l) => l.offset)).toEqual([0, 4, 8]);
  await tailer.close();
});

test('a line written in two pieces is handed out once, complete', async () => {
  await fs.writeFile(file(), 'first\n{"user":"ad');
  const { tailer, lines } = makeTailer(file());

  await tailer.poll();
  expect(texts(lines)).toEqual(['first']);

  await fs.appendFile(file(), 'min"}\n');
  await tailer.poll();
  expect(texts(lines)).toEqual(['first', '{"user":"admin"}']);
  expect(lines[1].offset).toBe(6);
  await tailer.close();
});

test('a multi-byte character split across two writes arrives intact', async () => {
  const bytes = Buffer.from('{"u":"é"}\n');
  await fs.writeFile(file(), 'x\n');
  const { tailer, lines } = makeTailer(file());
  await tailer.poll();
  await fs.appendFile(file(), bytes.subarray(0, 8)); // ends half-way through é
  await tailer.poll();
  await fs.appendFile(file(), bytes.subarray(8));
  await tailer.poll();

  expect(texts(lines)).toEqual(['x', '{"u":"é"}']);
  await tailer.close();
});

describe('empty and missing files', () => {
  test('an empty file is waited for, then read once it has a line', async () => {
    await fs.writeFile(file(), '');
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();
    expect(tailer.fileId).toBeNull();

    await fs.appendFile(file(), 'hello\n');
    await tailer.poll();
    expect(texts(lines)).toEqual(['hello']);
    await tailer.close();
  });

  test('a first line without its newline is not fingerprinted yet', async () => {
    await fs.writeFile(file(), '{"half":');
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();
    expect(tailer.fileId).toBeNull();
    expect(lines).toEqual([]);

    await fs.appendFile(file(), 'true}\n');
    await tailer.poll();
    expect(texts(lines)).toEqual(['{"half":true}']);
    await tailer.close();
  });

  test('a file that does not exist yet is waited for', async () => {
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();
    await fs.writeFile(file(), 'late\n');
    await tailer.poll();
    expect(texts(lines)).toEqual(['late']);
    await tailer.close();
  });
});

describe('resuming', () => {
  test('starts at the stored offset and re-reads that line', async () => {
    await fs.writeFile(file(), 'a\nbb\nccc\n');
    const fileId = sha256(Buffer.from('a'));
    const { tailer, lines } = makeTailer(file(), { resume: { [fileId]: 2 } });

    await tailer.poll();
    expect(lines.map((l) => [l.line, l.offset])).toEqual([['bb', 2], ['ccc', 5]]);
    await tailer.close();
  });

  test('a stored offset past the end of the file falls back to the start', async () => {
    await fs.writeFile(file(), 'a\n');
    const { tailer, lines } = makeTailer(file(), { resume: { [sha256(Buffer.from('a'))]: 999 } });
    await tailer.poll();
    expect(texts(lines)).toEqual(['a']);
    await tailer.close();
  });

  test('when onLine fails, the same line comes again on the next poll', async () => {
    await fs.writeFile(file(), 'one\ntwo\nthree\n');
    let failNext = false;
    const { tailer, lines } = makeTailer(file(), {
      onLine: async ({ line }) => {
        if (line === 'two' && failNext) {
          failNext = false;
          throw new Error('database down');
        }
      },
    });
    failNext = true;

    await expect(tailer.poll()).rejects.toThrow('database down');
    expect(texts(lines)).toEqual(['one']);
    expect(tailer.position).toBe(4);

    // The file has not grown, but the waiting lines must still come out.
    await tailer.poll();
    expect(texts(lines)).toEqual(['one', 'two', 'three']);
    await tailer.close();
  });
});

describe('rotation, truncation, deletion', () => {
  test('rotation: the old file is finished, the new one read from 0', async () => {
    await fs.writeFile(file(), 'old-1\n');
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();

    // Written to the old file just before the rename, not yet seen.
    await fs.appendFile(file(), 'old-2\n');
    await fs.rename(file(), file('app.json.2026-10-13'));
    await fs.writeFile(file(), 'new-1\n');
    await tailer.poll();

    expect(lines.map((l) => [l.line, l.offset])).toEqual([
      ['old-1', 0],
      ['old-2', 6],
      ['new-1', 0],
    ]);
    expect(lines[2].fileId).not.toBe(lines[0].fileId);
    await tailer.close();
  });

  test('truncation: the emptied file is read as a new file from 0', async () => {
    await fs.writeFile(file(), 'first-a\nfirst-b\n');
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();

    await fs.truncate(file(), 0);
    await tailer.poll();
    await fs.appendFile(file(), 'second\n');
    await tailer.poll();

    expect(lines.map((l) => [l.line, l.offset])).toEqual([
      ['first-a', 0],
      ['first-b', 8],
      ['second', 0],
    ]);
    expect(lines[2].fileId).toBe(sha256(Buffer.from('second')));
    await tailer.close();
  });

  test('rewritten in place and longer than before: detected by the changed first line', async () => {
    await fs.writeFile(file(), 'A\n');
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();

    // Same inode, bigger than before, so the size alone does not reveal it.
    const handle = await fs.open(file(), 'r+');
    await handle.truncate(0);
    await handle.write('B-new-content\nB2\n', 0);
    await handle.close();
    await tailer.poll();

    expect(texts(lines)).toEqual(['A', 'B-new-content', 'B2']);
    await tailer.close();
  });

  test('deletion and recreation: no crash, the new file is read', async () => {
    await fs.writeFile(file(), 'before\n');
    const { tailer, lines } = makeTailer(file());
    await tailer.poll();

    await fs.rm(file());
    await tailer.poll();
    await tailer.poll();
    await fs.writeFile(file(), 'after\n');
    await tailer.poll();

    expect(texts(lines)).toEqual(['before', 'after']);
    await tailer.close();
  });

  test('a rotated file ending without a newline reports an incomplete last line', async () => {
    await fs.writeFile(file(), 'ok\nhalf');
    const { tailer, lines, malformed } = makeTailer(file());
    await tailer.poll();
    await fs.rename(file(), file('app.json.1'));
    await tailer.poll();

    expect(texts(lines)).toEqual(['ok']);
    expect(malformed).toEqual([expect.objectContaining({ reason: 'incomplete_last_line', offset: 3 })]);
    await tailer.close();
  });
});

describe('the 1 MB line limit', () => {
  const ONE_MB = 1024 * 1024;

  test('a runaway line is reported once, dropped, and the next line still arrives', async () => {
    const { tailer, lines, malformed } = makeTailer(file());
    await fs.writeFile(file(), 'start\n');
    await tailer.poll();

    // Over 1 MB with no newline yet: reported and dropped without waiting.
    await fs.appendFile(file(), 'x'.repeat(ONE_MB + 10));
    await tailer.poll();
    expect(malformed).toEqual([expect.objectContaining({ reason: 'line_too_long', offset: 6 })]);
    expect(tailer.pending.length).toBe(0);

    // More of the same line, then its end, then a normal line.
    await fs.appendFile(file(), `${'x'.repeat(5000)}\n{"ok":1}\n`);
    await tailer.poll();

    expect(texts(lines)).toEqual(['start', '{"ok":1}']);
    expect(lines[1].offset).toBe(6 + ONE_MB + 10 + 5000 + 1);
    expect(malformed).toHaveLength(1);
    await tailer.close();
  });

  test('a long line that arrives complete is also refused', async () => {
    const { tailer, lines, malformed } = makeTailer(file(), { maxLineBytes: 100 });
    await fs.writeFile(file(), `short\n${'y'.repeat(150)}\nnext\n`);
    await tailer.poll();

    expect(texts(lines)).toEqual(['short', 'next']);
    expect(malformed).toEqual([expect.objectContaining({ reason: 'line_too_long', offset: 6 })]);
    await tailer.close();
  });

  test('a line of exactly the limit is accepted', async () => {
    const { tailer, lines } = makeTailer(file(), { maxLineBytes: 100 });
    await fs.writeFile(file(), `${'z'.repeat(100)}\n`);
    await tailer.poll();
    expect(lines).toHaveLength(1);
    await tailer.close();
  });
});

describe('LogSource: live file plus rotated copies', () => {
  test('reads rotated copies once and ignores unrelated files', async () => {
    await fs.writeFile(file('cowrie.json.2026-10-12'), 'day-12\n');
    await fs.writeFile(file('cowrie.json.2026-10-13'), 'day-13\n');
    await fs.writeFile(file('cowrie.json'), 'today\n');
    await fs.writeFile(file('dionaea.log'), 'not ours\n');
    await fs.writeFile(file('.gitignore'), '');

    const seen = [];
    const source = new LogSource({
      livePath: file('cowrie.json'),
      makeTailer: (filePath) => new FileTailer({
        filePath,
        maxLineBytes: 1024,
        getResumeOffset: async () => null,
        onLine: async ({ line, path: p }) => seen.push([path.basename(p), line]),
      }),
    });

    await source.poll();
    await source.poll();

    expect(seen).toEqual([
      ['cowrie.json.2026-10-12', 'day-12'],
      ['cowrie.json.2026-10-13', 'day-13'],
      ['cowrie.json', 'today'],
    ]);
    await source.close();
  });

  test('a rotated copy that fails is retried on the next poll', async () => {
    await fs.writeFile(file('cowrie.json.1'), 'r1\n');
    await fs.writeFile(file('cowrie.json'), 'live\n');
    let fail = true;
    const seen = [];
    const source = new LogSource({
      livePath: file('cowrie.json'),
      makeTailer: (filePath) => new FileTailer({
        filePath,
        maxLineBytes: 1024,
        getResumeOffset: async () => null,
        onLine: async ({ line }) => {
          if (fail) {
            fail = false;
            throw new Error('database down');
          }
          seen.push(line);
        },
      }),
    });

    await expect(source.poll()).rejects.toThrow('database down');
    await source.poll();
    expect(seen).toEqual(['r1', 'live']);
    await source.close();
  });
});
