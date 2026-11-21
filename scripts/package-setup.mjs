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

function readWorkspaceVersion() {
  const cargoToml = fs.readFileSync(path.join(repoRoot, 'Cargo.toml'), 'utf8');
  const match = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error('Could not find workspace version in Cargo.toml');
  }
  return match[1];
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

function copyFileEnsuringDir(src, dst, mode = null) {
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
  if (mode !== null && process.platform !== 'win32') {
    fs.chmodSync(dst, mode);
  }
}

function writeFileEnsuringDir(dst, data, mode = null) {
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.writeFileSync(dst, data);
  if (mode !== null && process.platform !== 'win32') {
    fs.chmodSync(dst, mode);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const targetOs = args.os;
  if (!['windows', 'macos', 'linux'].includes(targetOs)) {
    throw new Error(`--os must be one of windows|macos|linux (got: ${targetOs ?? ''})`);
  }
  const format = args.format ?? (targetOs === 'windows' ? 'zip' : 'tar.gz');
  if (!['zip', 'tar.gz'].includes(format)) {
    throw new Error(`--format must be zip|tar.gz (got: ${format})`);
  }

  const releaseDir = args['build-dir']
    ? path.resolve(repoRoot, args['build-dir'])
    : args.target
      ? path.join(repoRoot, 'target', args.target, 'release')
      : path.join(repoRoot, 'target', 'release');

  const pkgDir = path.resolve(repoRoot, args['package-dir'] ?? `Hide-Go-Setup-${targetOs}`);
  const archivePath = path.resolve(
    repoRoot,
    args.archive ?? `${pkgDir}.${format === 'zip' ? 'zip' : 'tar.gz'}`,
  );

  const spec =
    targetOs === 'windows'
      ? {
          desktopBin: 'hide-go-desktop.exe',
          daemonBin: 'hide-go-daemon.exe',
          setupBin: 'hide-go-setup.exe',
          setupEntry: 'Hide-Go-Setup.exe',
          engineLib: 'hide_engine.dll',
          chromeLib: 'hide_chrome.dll',
        }
      : targetOs === 'macos'
        ? {
            desktopBin: 'hide-go-desktop',
            daemonBin: 'hide-go-daemon',
            setupBin: 'hide-go-setup',
            setupEntry: 'Hide-Go-Setup',
            engineLib: 'libhide_engine.dylib',
            chromeLib: 'libhide_chrome.dylib',
          }
        : {
            desktopBin: 'hide-go-desktop',
            daemonBin: 'hide-go-daemon',
            setupBin: 'hide-go-setup',
            setupEntry: 'Hide-Go-Setup',
            engineLib: 'libhide_engine.so',
            chromeLib: 'libhide_chrome.so',
          };

  const version = readWorkspaceVersion();
  const distDir = path.join(repoRoot, 'dist');
  const localesDir = path.join(repoRoot, 'src', 'locales');
  const iconsDir = path.join(repoRoot, 'desktop', 'icons');

  for (const reqFile of [
    path.join(releaseDir, spec.setupBin),
    path.join(releaseDir, spec.desktopBin),
    path.join(releaseDir, spec.daemonBin),
    path.join(releaseDir, spec.engineLib),
    path.join(releaseDir, spec.chromeLib),
    path.join(distDir, 'index.html'),
    path.join(distDir, 'setup.html'),
  ]) {
    if (!fs.existsSync(reqFile)) {
      throw new Error(`Required build artifact missing: ${reqFile}`);
    }
  }

  fs.rmSync(pkgDir, { recursive: true, force: true });
  fs.rmSync(archivePath, { force: true });
  fs.rmSync(`${archivePath}.sha256`, { force: true });
  fs.mkdirSync(pkgDir, { recursive: true });

  // 1. Setup entry launcher + shared runtime DLLs
  copyFileEnsuringDir(path.join(releaseDir, spec.setupBin), path.join(pkgDir, spec.setupEntry), 0o755);
  copyFileEnsuringDir(path.join(releaseDir, spec.engineLib), path.join(pkgDir, spec.engineLib), 0o755);
  copyFileEnsuringDir(path.join(releaseDir, spec.chromeLib), path.join(pkgDir, spec.chromeLib), 0o755);

  // 2. Setup runtime resources (setup HTML/assets, locales, icons)
  copyFileEnsuringDir(path.join(distDir, 'setup.html'), path.join(pkgDir, 'resources/setup/setup.html'), 0o644);
  const setupAssets = collectReferencedAssets(distDir, 'setup.html');
  for (const name of setupAssets) {
    copyFileEnsuringDir(
      path.join(distDir, 'assets', name),
      path.join(pkgDir, 'resources/setup/assets', name),
      0o644,
    );
  }
  for (const locFile of ['zh-CN.json', 'en.json']) {
    copyFileEnsuringDir(
      path.join(localesDir, locFile),
      path.join(pkgDir, 'resources/locales', locFile),
      0o644,
    );
  }
  for (const iconFile of ['icon.ico', 'icon.png', '32x32.png', '128x128.png']) {
    copyFileEnsuringDir(
      path.join(iconsDir, iconFile),
      path.join(pkgDir, 'resources/icons', iconFile),
      0o644,
    );
  }

  // 3. Compressed data/app.tar.gz holding desktop & daemon launchers + desktop UI resources
  const uiAssets = collectReferencedAssets(distDir, 'index.html');
  const appEntries = [
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
      tarPath: 'resources/ui/index.html',
      data: fs.readFileSync(path.join(distDir, 'index.html')),
      mode: 0o644,
    },
    ...uiAssets.map((name) => ({
      tarPath: `resources/ui/assets/${name}`,
      data: fs.readFileSync(path.join(distDir, 'assets', name)),
      mode: 0o644,
    })),
  ];
  const appTarGz = buildDeterministicTarGz(appEntries);
  writeFileEnsuringDir(path.join(pkgDir, 'data/app.tar.gz'), appTarGz, 0o644);

  // 4. Write data/payload-manifest.json covering all verified package files
  const manifestFiles = {};
  const walkPackage = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkPackage(full);
      } else if (entry.isFile()) {
        const rel = path.relative(pkgDir, full).replace(/\\/g, '/');
        if (rel === spec.setupEntry || rel === 'data/payload-manifest.json') continue;
        manifestFiles[rel] = sha256Hex(fs.readFileSync(full));
      }
    }
  };
  walkPackage(pkgDir);

  const sortedFiles = {};
  for (const key of Object.keys(manifestFiles).sort()) {
    sortedFiles[key] = manifestFiles[key];
  }
  writeFileEnsuringDir(
    path.join(pkgDir, 'data/payload-manifest.json'),
    `${JSON.stringify({ version, files: sortedFiles }, null, 2)}\n`,
    0o644,
  );

  // 5. Pack archive & write .sha256
  fs.mkdirSync(path.dirname(archivePath), { recursive: true });
  if (format === 'zip') {
    if (process.platform === 'win32') {
      execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          'Compress-Archive -Path $env:HIDE_GO_PKG_DIR -DestinationPath $env:HIDE_GO_ZIP_OUT -CompressionLevel Optimal -Force',
        ],
        {
          stdio: 'inherit',
          env: {
            ...process.env,
            HIDE_GO_PKG_DIR: pkgDir,
            HIDE_GO_ZIP_OUT: archivePath,
          },
        },
      );
    } else {
      execFileSync('zip', ['-r', '-q', archivePath, path.basename(pkgDir)], {
        cwd: path.dirname(pkgDir),
        stdio: 'inherit',
      });
    }
  } else {
    execFileSync('tar', ['-czf', archivePath, '-C', path.dirname(pkgDir), path.basename(pkgDir)], {
      stdio: 'inherit',
      env: { ...process.env, COPYFILE_DISABLE: '1' },
    });
  }

  const archiveHash = sha256Hex(fs.readFileSync(archivePath));
  fs.writeFileSync(`${archivePath}.sha256`, `${archiveHash}  ${path.basename(archivePath)}\n`);
  console.log(`Packaged ${archivePath} (${fs.statSync(archivePath).size} bytes)`);
}

main();
