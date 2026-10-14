'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SAMPLES_DIR = path.join(__dirname, '..', '..', '..', 'docs', 'samples');
const FIXTURES_DIR = path.join(__dirname, 'fixtures');

function readSample(name) {
  return fs.readFileSync(path.join(SAMPLES_DIR, name), 'utf8');
}

function readFixture(name) {
  return fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf8');
}

// Splits file content into complete lines with the byte offset where each one
// starts, the way the tailer will in Stage 2. Text after the last newline is
// an unfinished line and is left out.
function linesWithOffsets(content) {
  const lines = [];
  let offset = 0;
  const parts = content.split('\n');
  parts.pop();
  for (const line of parts) {
    lines.push({ line, offset });
    offset += Buffer.byteLength(line, 'utf8') + 1;
  }
  return lines;
}

// Runs every complete line of a file through a normalizer and returns all
// rows with source_offset filled in, plus the non-row results.
function normalizeContent(content, normalize) {
  const rows = [];
  const others = [];
  for (const { line, offset } of linesWithOffsets(content)) {
    const result = normalize(line);
    if (result.status === 'rows') {
      for (const row of result.rows) rows.push({ ...row, source_offset: offset });
    } else {
      others.push({ ...result, offset });
    }
  }
  return { rows, others };
}

module.exports = { readSample, readFixture, linesWithOffsets, normalizeContent };
