/**
 * Build script: assembles loadable-unpacked extension directories.
 *
 * TypeScript is compiled first (tsc -p tsconfig.json with outDir to a
 * temp staging tree); this script then copies each browser's manifest,
 * compiled scripts, shared styles, and icons into dist/<browser>/.
 *
 * Usage: node build.mjs chromium|firefox
 */

import { cp, mkdir, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = path.dirname(new URL(import.meta.url).pathname);
const browser = process.argv[2];

if (browser !== 'chromium' && browser !== 'firefox') {
  console.error('usage: node build.mjs chromium|firefox');
  process.exit(2);
}

const srcDir = path.join(root, browser);
const sharedDir = path.join(root, 'shared');
const buildDir = path.join(root, 'build', browser);
const distDir = path.join(root, 'dist', browser);

async function copyTree(from, to) {
  if (!existsSync(from)) {
    throw new Error(`missing source: ${from}`);
  }
  const entries = await readdir(from, { withFileTypes: true });
  for (const entry of entries) {
    const src = path.join(from, entry.name);
    const dest = path.join(to, entry.name);
    if (entry.isDirectory()) {
      await mkdir(dest, { recursive: true });
      await copyTree(src, dest);
    } else {
      await cp(src, dest);
    }
  }
}

// build/<browser>/ holds the tsc output (mirroring the source tree).
const staging = path.join(root, 'build', 'ts');
if (!existsSync(staging)) {
  console.error('no compiled output; run `tsc -p tsconfig.json` first');
  process.exit(1);
}

await mkdir(path.join(distDir, 'src'), { recursive: true });

// Manifest.
await cp(path.join(srcDir, 'manifest.json'), path.join(distDir, 'manifest.json'));

// Compiled scripts: staged tree contains shared/ and <browser>/.
const stagedBrowser = path.join(staging, browser, 'src');
await copyTree(stagedBrowser, path.join(distDir, 'src'));

// Shared styles and icons.
await mkdir(path.join(distDir, 'shared'), { recursive: true });
await copyTree(path.join(sharedDir, 'styles'), path.join(distDir, 'shared', 'styles'));
await mkdir(path.join(distDir, 'shared', 'icons'), { recursive: true });
await copyTree(path.join(sharedDir, 'icons'), path.join(distDir, 'shared', 'icons'));

// HTML pages (popup/options) are generated inline by the pages' scripts
// at runtime is NOT acceptable for manifests, so we ship minimal pages.
await mkdir(path.join(distDir, 'src'), { recursive: true });
for (const page of ['popup.html', 'options.html']) {
  const dest = path.join(distDir, 'src', page);
  if (!existsSync(dest)) {
    const kind = page.replace('.html', '');
    const { writeFile } = await import('node:fs/promises');
    await writeFile(
      dest,
      `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>ezcap ${kind}</title>
  <link rel="stylesheet" href="../shared/styles/common.css">
</head>
<body>
  <div id="ezcap-root"></div>
  <form id="options-form">
    <label><input type="checkbox" id="auto-start"> Connect automatically</label>
    <label>Stored event limit
      <select id="event-limit">
        <option value="100">100</option>
        <option value="500">500</option>
        <option value="1000">1000</option>
      </select>
    </label>
    <button type="button" id="save">Save</button>
    <p id="status"></p>
  </form>
  <script type="module" src="${kind}.js"></script>
</body>
</html>
`,
    );
  }
}

console.log(`built ${distDir}`);
