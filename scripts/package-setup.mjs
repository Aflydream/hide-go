#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith('--')) continue;
    const name = key.slice(2);
    const val = argv[i + 1];
    if (!val || val.startsWith('--')) {
      throw new Error(`Missing value for flag --${name}`);
    }
    args[name] = val;
    i += 1;
  }
  return args;
}

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function collectReferencedAssets(distDir, htmlFileName) {
  const assetsDir = path.join(distDir, 'assets');
  const allAssetNames = fs
    .readdirSync(assetsDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);

  const visited = new Set();
  const queue = [];

  const htmlText = fs.readFileSync(path.join(distDir, htmlFileName), 'utf8');
  for (const name of allAssetNames) {
    if (htmlText.includes(name) && !visited.has(name)) {
      visited.add(name);
      queue.push(name);
    }
  }

  while (queue.length > 0) {
    const cur = queue.shift();
    if (!/\.(js|mjs|css)$/i.test(cur)) continue;
    const content = fs.readFileSync(path.join(assetsDir, cur), 'utf8');
    for (const candidate of allAssetNames) {
      if (!visited.has(candidate) && content.includes(candidate)) {
        visited.add(candidate);
        queue.push(candidate);
      }
    }
  }

  return Array.from(visited).sort();
}

function createUstarHeader(entryPath, size, mode) {
  const header = Buffer.alloc(512, 0);
  const cleanPath = entryPath.replace(/\\/g, '/').replace(/^\/+/, '');
  let name = cleanPath;
  let prefix = '';

  if (Buffer.byteLength(cleanPath) > 100) {
    const slash = cleanPath.lastIndexOf('/');
    if (slash <= 0) {
      throw new Error(`Tar entry name exceeds 100 bytes: ${cleanPath}`);
    }
    prefix = cleanPath.slice(0, slash);
    name = cleanPath.slice(slash + 1);
    if (Buffer.byteLength(name) > 100 || Buffer.byteLength(prefix) > 155) {
      throw new Error(`Tar entry path exceeds ustar limits: ${cleanPath}`);
    }
  }

  const writeOctal = (offset, length, value) => {
    const oct = value.toString(8).padStart(length - 1, '0');
    header.write(`${oct}\0`, offset, length, 'ascii');
  };

  header.write(name, 0, Math.min(Buffer.byteLength(name), 100), 'utf8');
  writeOctal(100, 8, mode);
  writeOctal(108, 8, 0);
  writeOctal(116, 8, 0);
  if (size > 0o77777777777) {
    throw new Error(`File too large for ustar entry: ${cleanPath}`);
  }
  const sizeStr = size.toString(8).padStart(11, '0');
  header.write(`${sizeStr}\0`, 124, 12, 'ascii');
  header.write(`${(0).toString(8).padStart(11, '0')}\0`, 136, 12, 'ascii');
  header.fill(0x20, 148, 156);
  header.write('0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  if (prefix) {
    header.write(prefix, 345, Math.min(Buffer.byteLength(prefix), 155), 'utf8');
  }

  let sum = 0;
  for (let i = 0; i < 512; i += 1) {
    sum += header[i];
  }
  const cksum = sum.toString(8).padStart(6, '0');
  header.write(`${cksum}\0 `, 148, 8, 'ascii');
  return header;
}

function buildDeterministicTarGz(entries) {
  const sorted = [...entries].sort((a, b) => a.tarPath.localeCompare(b.tarPath));
  const chunks = [];
  for (const entry of sorted) {
    const data = entry.data;
    chunks.push(createUstarHeader(entry.tarPath, data.length, entry.mode));
    chunks.push(data);
    const rem = data.length % 512;
    if (rem !== 0) {
      chunks.push(Buffer.alloc(512 - rem, 0));
    }
  }
  chunks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(chunks), { level: 9 });
}

function platformSpec(targetOs) {
  if (targetOs === 'windows') {
    return {
      desktopBin: 'hide-go-desktop.exe',
      daemonBin: 'hide-go-daemon.exe',
      setupBin: 'hide-go-setup.exe',
      setupEntry: 'Hide-Go-Setup.exe',
      engineLib: 'hide_engine.dll',
      chromeLib: 'hide_chrome.dll',
    };
  }
  if (targetOs === 'macos') {
    return {
      desktopBin: 'hide-go-desktop',
      daemonBin: 'hide-go-daemon',
      setupBin: 'hide-go-setup',
      setupEntry: 'Hide-Go-Setup',
      engineLib: 'libhide_engine.dylib',
      chromeLib: 'libhide_chrome.dylib',
    };
  }
  return {
    desktopBin: 'hide-go-desktop',
    daemonBin: 'hide-go-daemon',
    setupBin: 'hide-go-setup',
    setupEntry: 'Hide-Go-Setup',
    engineLib: 'libhide_engine.so',
    chromeLib: 'libhide_chrome.so',
  };
}

function resolveReleaseDir(args) {
  if (args['build-dir']) {
    return path.resolve(repoRoot, args['build-dir']);
  }
  if (args.target) {
    return path.join(repoRoot, 'target', args.target, 'release');
  }
  return path.join(repoRoot, 'target', 'release');
}

function stagePayloadArchive(targetOs, releaseDir, outPath) {
  const spec = platformSpec(targetOs);
  const distDir = path.join(repoRoot, 'dist');
  const localesDir = path.join(repoRoot, 'src', 'locales');
  const iconsDir = path.join(repoRoot, 'desktop', 'icons');

  for (const reqFile of [
    path.join(releaseDir, spec.desktopBin),
    path.join(releaseDir, spec.daemonBin),
    path.join(releaseDir, spec.engineLib),
    path.join(releaseDir, spec.chromeLib),
    path.join(distDir, 'index.html'),
  ]) {
    if (!fs.existsSync(reqFile)) {
      throw new Error(`Required build artifact missing: ${reqFile}`);
    }
  }

  const uiAssets = collectReferencedAssets(distDir, 'index.html');
  const entries = [
    {
      tarPath: spec.desktopBin,
      data: fs.readFileSync(path.join(releaseDir, spec.desktopBin)),
      mode: 0o755,
    },
    {
      tarPath: spec.daemonBin,
      data: fs.readFileSync(path.join(releaseDir, spec.daemonBin)),
      mode: 0o755,
    },
    {
      tarPath: spec.engineLib,
      data: fs.readFileSync(path.join(releaseDir, spec.engineLib)),
      mode: 0o755,
    },
    {
      tarPath: spec.chromeLib,
      data: fs.readFileSync(path.join(releaseDir, spec.chromeLib)),
      mode: 0o755,
    },
    {
      tarPath: 'resources/ui/index.html',
      data: fs.readFileSync(path.join(distDir, 'index.html')),
      mode: 0o644,
    },
    ...uiAssets.map((name) => ({
      tarPath: `resources/ui/assets/${name}`,
      data: fs.readFileSync(path.join(distDir, 'assets', name)),
      mode: 0o644,
    })),
    ...['zh-CN.json', 'en.json'].map((locFile) => ({
      tarPath: `resources/locales/${locFile}`,
      data: fs.readFileSync(path.join(localesDir, locFile)),
      mode: 0o644,
    })),
    ...['icon.ico', 'icon.png', '32x32.png', '128x128.png'].map((iconFile) => ({
      tarPath: `resources/icons/${iconFile}`,
      data: fs.readFileSync(path.join(iconsDir, iconFile)),
      mode: 0o644,
    })),
  ];

  const tarGz = buildDeterministicTarGz(entries);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, tarGz);
  const digest = sha256Hex(tarGz);
  console.log(`Staged ${outPath} (${tarGz.length} bytes, sha256=${digest})`);
}

function packageReleaseSetup(targetOs, releaseDir, outPath, format) {
  const spec = platformSpec(targetOs);
  const setupSrc = path.join(releaseDir, spec.setupBin);
  if (!fs.existsSync(setupSrc)) {
    throw new Error(`Required setup executable missing: ${setupSrc}`);
  }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.rmSync(outPath, { force: true });
  fs.rmSync(`${outPath}.sha256`, { force: true });

  if (format === 'exe') {
    fs.copyFileSync(setupSrc, outPath);
  } else if (format === 'tar.gz') {
    const setupData = fs.readFileSync(setupSrc);
    const tarGz = buildDeterministicTarGz([
      {
        tarPath: spec.setupEntry,
        data: setupData,
        mode: 0o755,
      },
    ]);
    fs.writeFileSync(outPath, tarGz);
  } else {
    throw new Error(`--format must be exe|tar.gz (got: ${format})`);
  }

  const outBytes = fs.readFileSync(outPath);
  const digest = sha256Hex(outBytes);
  fs.writeFileSync(`${outPath}.sha256`, `${digest}  ${path.basename(outPath)}\n`);
  console.log(`Packaged ${outPath} (${outBytes.length} bytes, sha256=${digest})`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const mode = args.mode;
  if (!['stage-payload', 'release-setup'].includes(mode)) {
    throw new Error(`--mode must be one of stage-payload|release-setup (got: ${mode ?? ''})`);
  }

  const targetOs = args.os;
  if (!['windows', 'macos', 'linux'].includes(targetOs)) {
    throw new Error(`--os must be one of windows|macos|linux (got: ${targetOs ?? ''})`);
  }

  const releaseDir = resolveReleaseDir(args);
  if (mode === 'stage-payload') {
    const outPath = path.resolve(repoRoot, args.out ?? `target/pkg/app-${targetOs}.tar.gz`);
    stagePayloadArchive(targetOs, releaseDir, outPath);
    return;
  }

  const defaultFormat = targetOs === 'windows' ? 'exe' : 'tar.gz';
  const format = args.format ?? defaultFormat;
  const defaultOut = targetOs === 'windows' ? 'Hide-Go-Setup-windows-x64.exe' : `Hide-Go-Setup-${targetOs}.tar.gz`;
  const outPath = path.resolve(repoRoot, args.out ?? defaultOut);
  packageReleaseSetup(targetOs, releaseDir, outPath, format);
}

main();
