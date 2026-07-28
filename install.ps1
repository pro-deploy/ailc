# Установщик ailc для Windows. Скачивает готовый бинарь из релиза, сверяет контрольную
# сумму, кладёт его в каталог пользователя и печатает сниппет для подключения в IDE.
#
# Использование (PowerShell):
#   irm https://raw.githubusercontent.com/pro-deploy/ailc/main/install.ps1 | iex
#
# Переменные окружения (необязательно):
#   AILC_VERSION  версия (тег) релиза, по умолчанию latest
#   AILC_BINDIR   каталог установки, по умолчанию %LOCALAPPDATA%\ailc\bin
#   AILC_INSECURE_SKIP_CHECKSUM=1  продолжить установку, если файл контрольной суммы
#                 недоступен (по умолчанию это ошибка)
#   AILC_REQUIRE_SIGNATURE=1  требовать проверку подписи (по умолчанию она выполняется,
#                 только когда в системе есть cosign)

#Requires -Version 5
$ErrorActionPreference = 'Stop'

$Repo    = 'pro-deploy/ailc'
$Version = if ($env:AILC_VERSION) { $env:AILC_VERSION } else { 'latest' }
$BinDir  = if ($env:AILC_BINDIR)  { $env:AILC_BINDIR }  else { Join-Path $env:LOCALAPPDATA 'ailc\bin' }

# Для Windows публикуется бинарь x86_64; на ARM64 он работает через эмуляцию x64.
$target = 'x86_64-pc-windows-msvc'
$asset  = "ailc-$target.zip"
$base   = if ($Version -eq 'latest') {
  "https://github.com/$Repo/releases/latest/download"
} else {
  "https://github.com/$Repo/releases/download/$Version"
}

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$zip = Join-Path $env:TEMP $asset

Write-Host "Платформа: $target"
Write-Host "Скачиваю $asset ..."
Invoke-WebRequest -Uri "$base/$asset" -OutFile $zip

# Проверка целостности. ВАЖНО: загрузка файла контрольной суммы и сравнение сумм разделены.
# Если сравнение выполнить внутри try, то `throw` при несовпадении перехватит собственный
# catch, и подменённый архив будет установлен молча. Поэтому в try остаётся только сетевой
# вызов, а решение принимается снаружи.
$shaFile  = Join-Path $env:TEMP "$asset.sha256"
$expected = $null
try {
  Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $shaFile
  $expected = ((Get-Content $shaFile) -split '\s+')[0].ToLower()
} catch {
  $expected = $null
}

if (-not $expected) {
  if ($env:AILC_INSECURE_SKIP_CHECKSUM -eq '1') {
    Write-Host 'ВНИМАНИЕ: контрольная сумма недоступна, проверка отключена явно (AILC_INSECURE_SKIP_CHECKSUM=1).'
  } else {
    Remove-Item -Force -ErrorAction SilentlyContinue $zip
    throw 'ailc-install: контрольная сумма недоступна, установка прервана. Осознанный обход: AILC_INSECURE_SKIP_CHECKSUM=1'
  }
} else {
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) {
    Remove-Item -Force -ErrorAction SilentlyContinue $zip
    throw "ailc-install: контрольная сумма не совпала (ожидалось $expected, получено $actual), установка прервана"
  }
  Write-Host 'Контрольная сумма проверена.'
}

# Подпись артефакта: подтверждает ПОДЛИННОСТЬ источника, тогда как контрольная сумма
# подтверждает лишь целостность загрузки. Проверка требует cosign; при его отсутствии
# установка продолжается с предупреждением, строгий режим включается переменной
# AILC_REQUIRE_SIGNATURE=1.
$cosign = Get-Command cosign -ErrorAction SilentlyContinue
if ($cosign) {
  $sig = Join-Path $env:TEMP "$asset.sig"
  $pem = Join-Path $env:TEMP "$asset.pem"
  $haveSig = $true
  try {
    Invoke-WebRequest -Uri "$base/$asset.sig" -OutFile $sig
    Invoke-WebRequest -Uri "$base/$asset.pem" -OutFile $pem
  } catch {
    $haveSig = $false
  }
  if ($haveSig) {
    $identity = "^https://github.com/$Repo/\.github/workflows/release\.yml@refs/tags/"
    & cosign verify-blob --certificate $pem --signature $sig `
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
      --certificate-identity-regexp $identity $zip | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Remove-Item -Force -ErrorAction SilentlyContinue $zip
      throw 'ailc-install: подпись не прошла проверку, установка прервана'
    }
    Write-Host "Подпись проверена: артефакт выпущен рабочим процессом $Repo."
  } elseif ($env:AILC_REQUIRE_SIGNATURE -eq '1') {
    throw 'ailc-install: подпись недоступна, а строгий режим включён (AILC_REQUIRE_SIGNATURE=1)'
  } else {
    Write-Host 'Подпись недоступна для этого выпуска, проверена только контрольная сумма.'
  }
} elseif ($env:AILC_REQUIRE_SIGNATURE -eq '1') {
  throw 'ailc-install: не найден cosign, а строгий режим включён (AILC_REQUIRE_SIGNATURE=1)'
} else {
  Write-Host 'cosign не установлен: проверена только контрольная сумма. Для проверки'
  Write-Host 'подлинности источника установите cosign (https://docs.sigstore.dev).'
}

Expand-Archive -Path $zip -DestinationPath $BinDir -Force
$exe = Join-Path $BinDir 'ailc.exe'
Write-Host "Установлено: $exe"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$BinDir*") {
  Write-Host "Внимание: каталог $BinDir не в PATH. Команда для добавления:"
  Write-Host "  setx PATH `"$BinDir;`$env:PATH`""
}

$cmd = ($exe -replace '\\', '\\')
Write-Host ''
Write-Host 'Подключение в среду разработки. Добавьте в .mcp.json (Claude Code) или в .cursor\mcp.json (Cursor):'
Write-Host "{ `"mcpServers`": { `"ailc`": { `"command`": `"$cmd`", `"args`": [`"serve`"] } } }"
Write-Host ''
Write-Host "Проверка: `"$exe`" dod ."
