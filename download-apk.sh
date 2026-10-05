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

if [ "$FETCH_CMD" = "wget" ]; then
    RELEASE_JSON="$(wget -qO- "$API_URL")" || {
        printf '%s\n' "Ошибка: не удалось получить информацию о последнем Release." >&2
        exit 1
    }
else
    RELEASE_JSON="$(curl -fsSL "$API_URL")" || {
        printf '%s\n' "Ошибка: не удалось получить информацию о последнем Release." >&2
        exit 1
    }
fi

APK_URL="$(printf '%s\n' "$RELEASE_JSON" | sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*parental-control-[^"]*\.apk\)".*/\1/p' | head -n 1)"

if [ -z "$APK_URL" ]; then
    printf '%s\n' "Ошибка: APK не найден в последнем GitHub Release." >&2
    exit 1
fi

APK_NAME="${APK_URL##*/}"
mkdir -p "$DEST_DIR"
TMP_FILE="$DEST_DIR/.${APK_NAME}.tmp.$$"
OUT_FILE="$DEST_DIR/$APK_NAME"
trap 'rm -f "$TMP_FILE"' EXIT HUP INT TERM

printf 'Скачивание %s...\n' "$APK_NAME"
if [ "$FETCH_CMD" = "wget" ]; then
    wget -O "$TMP_FILE" "$APK_URL"
else
    curl -fL "$APK_URL" -o "$TMP_FILE"
fi

mv "$TMP_FILE" "$OUT_FILE"
trap - EXIT HUP INT TERM
printf 'Готово: %s\n' "$OUT_FILE"
