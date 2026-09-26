import assert from 'node:assert/strict';
import {readdir, readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const website = fileURLToPath(new URL('../', import.meta.url));
const roots = [path.resolve(website, '../docs/manual'), path.join(website, 'i18n/zh-Hans/docusaurus-plugin-content-docs/current')];
async function inventory(root, dir = '') {
  const entries = await readdir(path.join(root, dir), {withFileTypes: true});
  const files = await Promise.all(entries.map(entry => entry.isDirectory()
    ? inventory(root, path.join(dir, entry.name))
    : [path.join(dir, entry.name)]));
  return files.flat().sort();
}
const inventories = await Promise.all(roots.map(root => inventory(root)));
assert.deepEqual(inventories[0], inventories[1], 'Locale page/category inventories differ');
let pages = 0;
for (const file of inventories[0]) {
  const texts = await Promise.all(roots.map(root => readFile(path.join(root, file), 'utf8')));
  if (file.endsWith('.json')) {
    assert.equal(JSON.parse(texts[0]).position, JSON.parse(texts[1]).position, `${file}: category order differs`);
    continue;
  }
  if (!file.endsWith('.md')) continue;
  pages++;
  for (const field of ['id', 'slug', 'sidebar_position']) {
    const values = texts.map(text => text.match(new RegExp(`^${field}: (.*)$`, 'm'))?.[1]);
    assert.equal(values[0], values[1], `${file}: ${field} differs`);
  }
  const code = text => [...text.matchAll(/^```[^\n]*\n([\s\S]*?)^```/gm)].map(match => match[1]);
  assert.deepEqual(code(texts[0]), code(texts[1]), `${file}: command/example blocks differ`);
  const links = text => [...text.matchAll(/\]\(([^)]+)\)/g)].map(match => match[1]).filter(link => !/^https?:/.test(link)).sort();
  assert.deepEqual(links(texts[0]), links(texts[1]), `${file}: internal links differ`);
  const warnings = text => [...text.matchAll(/^:::(warning|danger|caution|note|tip)/gm)].map(match => match[1]);
  assert.deepEqual(warnings(texts[0]), warnings(texts[1]), `${file}: admonitions differ`);
  const headings = text => [...text.matchAll(/^(#{2,6}) /gm)].map(match => match[1]);
  assert.deepEqual(headings(texts[0]), headings(texts[1]), `${file}: section structure differs`);
  const identifiers = text => [...new Set(text.match(/AGE_PLUGIN_PHONE_[A-Z_]+|--[a-z][a-z-]+/g) ?? [])].sort();
  assert.deepEqual(identifiers(texts[0]), identifiers(texts[1]), `${file}: options/environment variables differ`);
}
console.log(`Locale parity passed: ${pages} pages per locale. Semantic translation review is still required.`);
