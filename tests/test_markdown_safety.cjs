const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require(process.env.ESBUILD_PATH || 'esbuild');

const source = fs.readFileSync(path.join(__dirname, '../dashboard-plugin/native/public/markdown_safety.ts'), 'utf8');
const compiled = esbuild.transformSync(source, { loader: 'ts', format: 'cjs' }).code;
const loaded = { exports: {} };
new Function('exports', 'module', compiled)(loaded.exports, loaded);

const tree = { type: 'root', children: [
  { type: 'paragraph', children: [
    { type: 'strong', children: [{ type: 'text', value: 'important' }] },
    { type: 'html', value: '<img src="https://example.com/track">' },
    { type: 'image', url: 'https://example.com/track', alt: 'diagram' },
    { type: 'imageReference', identifier: 'remote', alt: 'chart' },
    { type: 'linkReference', identifier: 'unsafe', children: [{ type: 'text', value: 'link' }] },
  ] },
  { type: 'code', value: '<example>' },
] };
loaded.exports.stripUnsafeMarkdown()(tree);
assert.equal(tree.children[0].children[0].type, 'strong');
assert.deepEqual(tree.children[0].children.slice(1).map((node) => [node.type, node.value]), [
  ['text', '<img src="https://example.com/track">'],
  ['text', '[Image: diagram]'],
  ['text', '[Image: chart]'],
  ['text', 'link'],
]);
assert.equal(tree.children[0].children[2].url, undefined);
assert.equal(tree.children[1].value, '<example>');
console.log('Markdown safety AST checks passed');
