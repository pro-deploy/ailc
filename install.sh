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
#   AILC_INSECURE_SKIP_CHECKSUM=1  продолжить установку, если файл контрольной суммы
#                 недоступен (по умолчанию это ошибка)
#   AILC_REQUIRE_SIGNATURE=1  требовать проверку подписи (по умолчанию она выполняется,
#                 только когда в системе есть cosign, иначе установка продолжается)

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

# Проверка целостности обязательна: недоступность контрольной суммы трактуется как ошибка,
# иначе активному посреднику достаточно ответить 404 на запрос суммы, чтобы проверку обойти.
# Осознанный обход возможен только явной переменной окружения.
if curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256" 2>/dev/null; then
  expected="$(awk '{print $1}' "$tmp/$asset.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
  fi
  [ -n "$expected" ] || err "файл контрольной суммы пуст, прерываю установку"
  [ "$expected" = "$actual" ] || err "контрольная сумма не совпала (ожидалось $expected, получено $actual), прерываю установку"
  say "Контрольная сумма проверена."
elif [ "${AILC_INSECURE_SKIP_CHECKSUM:-0}" = "1" ]; then
  say "ВНИМАНИЕ: контрольная сумма недоступна, проверка отключена явно (AILC_INSECURE_SKIP_CHECKSUM=1)."
else
  err "контрольная сумма недоступна, прерываю установку. Осознанный обход: AILC_INSECURE_SKIP_CHECKSUM=1"
fi

# Подпись артефакта: подтверждает ПОДЛИННОСТЬ источника, тогда как контрольная сумма
# подтверждает лишь целостность загрузки (она публикуется рядом с архивом, поэтому
# компрометация страницы выпуска компрометирует и её). Подпись сделана без ключей: в ней
# удостоверена личность рабочего процесса выпуска, а запись лежит в публичном журнале
# прозрачности. Проверка требует cosign; при его отсутствии установка продолжается с
# явным предупреждением, а строгий режим включается переменной AILC_REQUIRE_SIGNATURE=1.
if command -v cosign >/dev/null 2>&1; then
  if curl -fsSL "$base/$asset.sig" -o "$tmp/$asset.sig" 2>/dev/null &&
     curl -fsSL "$base/$asset.pem" -o "$tmp/$asset.pem" 2>/dev/null; then
    if cosign verify-blob \
        --certificate "$tmp/$asset.pem" \
        --signature "$tmp/$asset.sig" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        --certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@refs/tags/" \
        "$tmp/$asset" >/dev/null 2>&1; then
      say "Подпись проверена: артефакт выпущен рабочим процессом $REPO."
    else
      err "подпись не прошла проверку, прерываю установку"
    fi
  elif [ "${AILC_REQUIRE_SIGNATURE:-0}" = "1" ]; then
    err "подпись недоступна, а строгий режим включён (AILC_REQUIRE_SIGNATURE=1)"
  else
    say "Подпись недоступна для этого выпуска, проверена только контрольная сумма."
  fi
elif [ "${AILC_REQUIRE_SIGNATURE:-0}" = "1" ]; then
  err "не найден cosign, а строгий режим включён (AILC_REQUIRE_SIGNATURE=1)"
else
  say "cosign не установлен: проверена только контрольная сумма. Для проверки подлинности"
  say "источника установите cosign (https://docs.sigstore.dev) и повторите установку."
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
