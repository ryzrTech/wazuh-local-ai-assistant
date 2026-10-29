const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require(process.env.ESBUILD_PATH || 'esbuild');

const source = fs.readFileSync(path.join(__dirname, '../dashboard-plugin/native/public/thinking.ts'), 'utf8');
const compiled = esbuild.transformSync(source, { loader: 'ts', format: 'cjs' }).code;
const loaded = { exports: {} };
new Function('exports', 'module', compiled)(loaded.exports, loaded);
const { splitThinkTags } = loaded.exports;

assert.deepEqual(splitThinkTags('Plain answer.'), { answer: 'Plain answer.', thinking: '', active: false });
assert.deepEqual(splitThinkTags('<think>Check first.</think>Final answer.'),
  { answer: 'Final answer.', thinking: 'Check first.', active: false });
assert.deepEqual(splitThinkTags('<think>Still working'),
  { answer: '', thinking: 'Still working', active: true });
assert.deepEqual(splitThinkTags('<thi'), { answer: '', thinking: '', active: true });
assert.deepEqual(splitThinkTags('<think>Working</thi'), { answer: '', thinking: 'Working', active: true });
console.log('thinking tag parsing: ok');
