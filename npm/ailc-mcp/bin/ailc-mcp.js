#!/usr/bin/env node
'use strict';

// Кроссплатформенная обёртка ailc для запуска через npx. При первом запуске скачивает
// готовый бинарь нужной платформы из релиза GitHub (версия совпадает с версией пакета),
// кэширует его и запускает. Без аргументов запускает MCP-сервер (ailc serve), поэтому в
// .mcp.json достаточно строки { "command": "npx", "args": ["-y", "ailc-mcp"] }.
// Зависимостей нет: распаковка через системный tar (есть на macOS, Linux и Windows 10+).

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawnSync, execFileSync } = require('child_process');

const REPO = 'pro-deploy/ailc';
const VERSION = require('../package.json').version;

function fail(msg) {
  process.stderr.write('ailc-mcp: ' + msg + '\n');
  process.exit(1);
}

function platformTarget() {
  const p = process.platform;
  const a = process.arch;
  const cpu = a === 'arm64' ? 'aarch64' : a === 'x64' ? 'x86_64' : null;
  if (!cpu) fail('неподдерживаемая архитектура: ' + a);
  if (p === 'darwin') return { triple: cpu + '-apple-darwin', ext: 'tar.gz', exe: 'ailc' };
  if (p === 'linux') return { triple: cpu + '-unknown-linux-gnu', ext: 'tar.gz', exe: 'ailc' };
  if (p === 'win32') return { triple: 'x86_64-pc-windows-msvc', ext: 'zip', exe: 'ailc.exe' };
  return fail('неподдерживаемая ОС: ' + p);
}

function download(url, dest, cb, redirects) {
  redirects = redirects || 0;
  if (redirects > 8) return cb(new Error('слишком много перенаправлений'));
  https
    .get(url, { headers: { 'User-Agent': 'ailc-mcp' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return download(res.headers.location, dest, cb, redirects + 1);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return cb(new Error('HTTP ' + res.statusCode + ' для ' + url));
      }
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => file.close(() => cb(null)));
      file.on('error', cb);
    })
    .on('error', cb);
}

function run(bin, args) {
  const r = spawnSync(bin, args, { stdio: 'inherit' });
  if (r.error) fail(r.error.message);
  process.exit(r.status === null ? 1 : r.status);
}

function main() {
  const t = platformTarget();
  const cacheDir = path.join(os.homedir(), '.ailc', 'bin', 'v' + VERSION);
  const binPath = path.join(cacheDir, t.exe);
  const passed = process.argv.slice(2);
  const args = passed.length ? passed : ['serve'];

  if (fs.existsSync(binPath)) return run(binPath, args);

  fs.mkdirSync(cacheDir, { recursive: true });
  const asset = 'ailc-' + t.triple + '.' + t.ext;
  const url = 'https://github.com/' + REPO + '/releases/download/v' + VERSION + '/' + asset;
  const archive = path.join(cacheDir, asset);

  process.stderr.write('ailc-mcp: скачиваю ' + asset + ' (однократно)...\n');
  download(url, archive, (err) => {
    if (err) fail('не удалось скачать бинарь: ' + err.message);
    try {
      const flag = t.ext === 'tar.gz' ? '-xzf' : '-xf';
      execFileSync('tar', [flag, archive, '-C', cacheDir], { stdio: 'inherit' });
    } catch (e) {
      fail('не удалось распаковать архив: ' + e.message);
    }
    try {
      fs.unlinkSync(archive);
    } catch (e) {
      /* не критично */
    }
    if (!fs.existsSync(binPath)) fail('бинарь не найден после распаковки');
    if (process.platform !== 'win32') fs.chmodSync(binPath, 0o755);
    run(binPath, args);
  });
}

main();
