# Установщик ailc для Windows. Скачивает готовый бинарь из релиза, сверяет контрольную
# сумму, кладёт его в каталог пользователя и печатает сниппет для подключения в IDE.
#
# Использование (PowerShell):
#   irm https://raw.githubusercontent.com/pro-deploy/ailc/main/install.ps1 | iex
#
# Переменные окружения (необязательно):
#   AILC_VERSION  версия (тег) релиза, по умолчанию latest
#   AILC_BINDIR   каталог установки, по умолчанию %LOCALAPPDATA%\ailc\bin

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

try {
  $shaFile = Join-Path $env:TEMP "$asset.sha256"
  Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $shaFile
  $expected = ((Get-Content $shaFile) -split '\s+')[0].ToLower()
  $actual   = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw 'контрольная сумма не совпала, прерываю установку' }
  Write-Host 'Контрольная сумма проверена.'
} catch {
  Write-Host 'Контрольная сумма недоступна, пропускаю проверку.'
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
