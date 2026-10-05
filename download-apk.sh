#!/bin/sh
set -eu

REPO="filippxda26/parental-control"
API_URL="https://api.github.com/repos/$REPO/releases/latest"
DEST_DIR="${1:-.}"

if command -v wget >/dev/null 2>&1; then
    FETCH_CMD="wget"
elif command -v curl >/dev/null 2>&1; then
    FETCH_CMD="curl"
else
    printf '%s\n' "Ошибка: нужен wget или curl." >&2
    exit 1
fi

if ! command -v apk >/dev/null 2>&1; then
    printf '%s\n' "Ошибка: команда apk не найдена. Этот скрипт предназначен для OpenWrt с apk." >&2
    exit 1
fi

fetch_stdout() {
    if [ "$FETCH_CMD" = "wget" ]; then
        wget -qO- "$1"
    else
        curl -fsSL "$1"
    fi
}

download_file() {
    if [ "$FETCH_CMD" = "wget" ]; then
        wget -O "$2" "$1"
    else
        curl -fL "$1" -o "$2"
    fi
}

RELEASE_JSON="$(fetch_stdout "$API_URL")" || {
    printf '%s\n' "Ошибка: не удалось получить информацию о последнем Release." >&2
    exit 1
}

ASSET_URLS="$(printf '%s' "$RELEASE_JSON" | tr ',' '\n' | sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)".*/\1/p')"
APK_URL="$(printf '%s\n' "$ASSET_URLS" | grep '/parental-control-[^/]*\.apk$' | head -n 1 || true)"
KEY_URL="$(printf '%s\n' "$ASSET_URLS" | grep '/parental-control-signing-public-key\.pem$' | head -n 1 || true)"

if [ -z "$APK_URL" ]; then
    printf '%s\n' "Ошибка: APK не найден в последнем GitHub Release." >&2
    exit 1
fi

if [ -z "$KEY_URL" ]; then
    printf '%s\n' "Ошибка: в последнем Release нет публичного ключа подписи." >&2
    printf '%s\n' "Пересоберите Release текущим GitHub Actions workflow, затем повторите команду." >&2
    exit 1
fi

APK_NAME="${APK_URL##*/}"
mkdir -p "$DEST_DIR"
TMP_FILE="$DEST_DIR/.${APK_NAME}.tmp.$$"
OUT_FILE="$DEST_DIR/$APK_NAME"
KEY_FILE="$DEST_DIR/.parental-control-signing-public-key.$$"
KEY_DIR="$DEST_DIR/.parental-control-apk-keys.$$"

cleanup() {
    rm -f "$TMP_FILE" "$KEY_FILE"
    rm -rf "$KEY_DIR"
}
trap cleanup EXIT HUP INT TERM

printf 'Скачивание %s...\n' "$APK_NAME"
download_file "$APK_URL" "$TMP_FILE"
mv "$TMP_FILE" "$OUT_FILE"

printf '%s\n' "Скачивание публичного ключа подписи..."
download_file "$KEY_URL" "$KEY_FILE"

mkdir -p "$KEY_DIR"
if [ -d /etc/apk/keys ]; then
    for key in /etc/apk/keys/*; do
        [ -f "$key" ] && cp "$key" "$KEY_DIR/"
    done
fi
cp "$KEY_FILE" "$KEY_DIR/parental-control.pem"

printf '%s\n' "Проверка подписи APK..."
if ! apk --keys-dir "$KEY_DIR" verify "$OUT_FILE"; then
    printf 'Ошибка: подпись APK не прошла проверку. APK сохранён: %s\n' "$OUT_FILE" >&2
    exit 1
fi

printf 'Установка %s...\n' "$OUT_FILE"
if apk --keys-dir "$KEY_DIR" add "$OUT_FILE"; then
    printf 'Готово: %s проверен и установлен.\n' "$APK_NAME"
else
    printf 'Ошибка установки. APK сохранён: %s\n' "$OUT_FILE" >&2
    exit 1
fi
