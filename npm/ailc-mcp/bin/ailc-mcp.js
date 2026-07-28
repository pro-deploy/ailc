#!/usr/bin/env node
'use strict';

// Кроссплатформенная обёртка ailc для запуска через npx. При первом запуске скачивает
// готовый бинарь нужной платформы из релиза GitHub (версия совпадает с версией пакета),
// сверяет контрольную сумму SHA-256, кэширует его и запускает. Без аргументов запускает
// MCP-сервер (ailc serve), поэтому в .mcp.json достаточно строки
// { "command": "npx", "args": ["-y", "ailc-mcp"] }.
// Зависимостей нет: распаковка через системный tar (есть на macOS, Linux и Windows 10+).
//
// Установка атомарна: загрузка, проверка суммы и распаковка выполняются во временном
// каталоге, и только полностью готовый каталог переносится на место переименованием.
// Поэтому прерванная загрузка не оставляет частично распакованный бинарь, который
// следующий запуск принял бы за готовый.
//
// Переменные окружения:
//   AILC_INSECURE_SKIP_CHECKSUM=1  продолжить, если файл контрольной суммы недоступен
//                                  (по умолчанию это ошибка)

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawnSync, execFileSync } = require('child_process');

const REPO = 'pro-deploy/ailc';
const VERSION = require('../package.json').version;

// Узлы, на которые допускается перенаправление при загрузке. Артефакты релиза GitHub
// отдаются через github.com и поддомены githubusercontent.com; перенаправление на любой
// иной узел считается признаком подмены и прерывает загрузку.
const ALLOWED_HOSTS = ['github.com', 'githubusercontent.com'];

function fail(msg) {
  process.stderr.write('ailc-mcp: ' + msg + '\n');
  process.exit(1);
}

function hostAllowed(u) {
  let host;
  try {
    const parsed = new URL(u);
    if (parsed.protocol !== 'https:') return false;
    host = parsed.hostname.toLowerCase();
  } catch (e) {
    return false;
  }
  return ALLOWED_HOSTS.some((d) => host === d || host.endsWith('.' + d));
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
  if (!hostAllowed(url)) return cb(new Error('недопустимый адрес загрузки: ' + url));
  https
    .get(url, { headers: { 'User-Agent': 'ailc-mcp' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        return download(next, dest, cb, redirects + 1);
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

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    /* каталога могло не быть */
  }
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

  const asset = 'ailc-' + t.triple + '.' + t.ext;
  const base = 'https://github.com/' + REPO + '/releases/download/v' + VERSION;
  const stageDir = cacheDir + '.tmp-' + process.pid;
  rmrf(stageDir);
  fs.mkdirSync(stageDir, { recursive: true });
  const archive = path.join(stageDir, asset);
  const shaFile = archive + '.sha256';

  const abort = (msg) => {
    rmrf(stageDir);
    fail(msg);
  };

  process.stderr.write('ailc-mcp: скачиваю ' + asset + ' (однократно)...\n');
  download(base + '/' + asset, archive, (err) => {
    if (err) abort('не удалось скачать бинарь: ' + err.message);

    download(base + '/' + asset + '.sha256', shaFile, (shaErr) => {
      // Контрольная сумма обязательна: без неё нельзя отличить подлинный артефакт от
      // подменённого. Обход возможен только явной переменной окружения.
      if (shaErr) {
        if (process.env.AILC_INSECURE_SKIP_CHECKSUM !== '1') {
          abort(
            'контрольная сумма недоступна (' +
              shaErr.message +
              '), установка прервана. Осознанный обход: AILC_INSECURE_SKIP_CHECKSUM=1'
          );
        }
        process.stderr.write(
          'ailc-mcp: ВНИМАНИЕ, проверка контрольной суммы отключена явно.\n'
        );
      } else {
        const expected = String(fs.readFileSync(shaFile, 'utf8')).trim().split(/\s+/)[0].toLowerCase();
        const actual = sha256(archive);
        if (!expected) abort('файл контрольной суммы пуст, установка прервана');
        if (expected !== actual) {
          abort(
            'контрольная сумма не совпала (ожидалось ' +
              expected +
              ', получено ' +
              actual +
              '), установка прервана'
          );
        }
      }

      try {
        const flag = t.ext === 'tar.gz' ? '-xzf' : '-xf';
        execFileSync('tar', [flag, archive, '-C', stageDir], { stdio: 'inherit' });
      } catch (e) {
        abort('не удалось распаковать архив: ' + e.message);
      }

      const staged = path.join(stageDir, t.exe);
      if (!fs.existsSync(staged)) abort('бинарь не найден после распаковки');
      if (process.platform !== 'win32') fs.chmodSync(staged, 0o755);
      try {
        fs.unlinkSync(archive);
        fs.unlinkSync(shaFile);
      } catch (e) {
        /* не критично */
      }

      // Атомарная установка. Если параллельный запуск успел перенести свой каталог,
      // переименование не удастся: тогда пользуемся уже готовым результатом.
      fs.mkdirSync(path.dirname(cacheDir), { recursive: true });
      try {
        fs.renameSync(stageDir, cacheDir);
      } catch (e) {
        rmrf(stageDir);
        if (!fs.existsSync(binPath)) fail('не удалось установить бинарь: ' + e.message);
      }
      run(binPath, args);
    });
  });
}

main();
