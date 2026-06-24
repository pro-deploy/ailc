#!/bin/sh
# Установщик ailc для macOS и Linux. Определяет операционную систему и архитектуру,
# скачивает готовый бинарь нужной платформы из релиза, сверяет контрольную сумму,
# кладёт его в каталог пользователя и печатает готовый сниппет для подключения в IDE.
#
# Использование:
#   curl -fsSL https://raw.githubusercontent.com/pro-deploy/ailc/main/install.sh | sh
#
# Переменные окружения (необязательно):
#   AILC_VERSION  версия (тег) релиза, по умолчанию latest
#   AILC_BINDIR   каталог установки, по умолчанию $HOME/.local/bin

set -eu

REPO="pro-deploy/ailc"
VERSION="${AILC_VERSION:-latest}"
BINDIR="${AILC_BINDIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
err() { printf 'ailc-install: %s\n' "$*" >&2; exit 1; }

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  plat="unknown-linux-gnu" ;;
  Darwin) plat="apple-darwin" ;;
  *) err "неподдерживаемая ОС: $os (для Windows используйте install.ps1)" ;;
esac

case "$arch" in
  x86_64|amd64)  cpu="x86_64" ;;
  arm64|aarch64) cpu="aarch64" ;;
  *) err "неподдерживаемая архитектура: $arch" ;;
esac

target="${cpu}-${plat}"
asset="ailc-${target}.tar.gz"

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

command -v curl >/dev/null 2>&1 || err "нужен curl"
command -v tar  >/dev/null 2>&1 || err "нужен tar"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Платформа: $target"
say "Скачиваю $asset ..."
curl -fsSL "$base/$asset" -o "$tmp/$asset" || err "не удалось скачать $base/$asset"

if curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256" 2>/dev/null; then
  expected="$(awk '{print $1}' "$tmp/$asset.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
  fi
  [ "$expected" = "$actual" ] || err "контрольная сумма не совпала, прерываю установку"
  say "Контрольная сумма проверена."
else
  say "Контрольная сумма недоступна, пропускаю проверку."
fi

mkdir -p "$BINDIR"
tar -xzf "$tmp/$asset" -C "$tmp"
mv "$tmp/ailc" "$BINDIR/ailc"
chmod +x "$BINDIR/ailc"
say "Установлено: $BINDIR/ailc"

case ":$PATH:" in
  *":$BINDIR:"*) : ;;
  *) say "Внимание: каталог $BINDIR не в PATH. Добавьте строку в профиль оболочки: export PATH=\"$BINDIR:\$PATH\"" ;;
esac

say ""
say "Подключение в среду разработки. Добавьте в .mcp.json (Claude Code) или в ~/.cursor/mcp.json (Cursor):"
say "{ \"mcpServers\": { \"ailc\": { \"command\": \"$BINDIR/ailc\", \"args\": [\"serve\"] } } }"
say ""
say "Проверка: $BINDIR/ailc dod ."
