#!/usr/bin/env bash
# Fetch the vendored typefaces for the CGE-P PDF build kit.
#
# The font binaries are not committed. This script downloads the exact
# upstream releases they came from and verifies them twice: the archive
# against its SHA-256, and each extracted file against its own SHA-256.
#
# The two layers are deliberate, and they are the same distinction Lab 2.2
# draws between a version constraint and a lock file. The pinned release
# tag says what we intend; the per-file hash records what we actually got.
# A re-tagged or re-uploaded release would pass the first check and fail
# the second.
#
# Usage:  ./fetch-fonts.sh [--check]
#   --check   verify what is already on disk; download nothing

set -euo pipefail
cd "$(dirname "$0")"

INTER_VERSION="4.1"
INTER_URL="https://github.com/rsms/inter/releases/download/v${INTER_VERSION}/Inter-${INTER_VERSION}.zip"
INTER_ZIP_SHA="9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e"

JBM_VERSION="2.304"
JBM_URL="https://github.com/JetBrains/JetBrainsMono/releases/download/v${JBM_VERSION}/JetBrainsMono-${JBM_VERSION}.zip"
JBM_ZIP_SHA="6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf"

# filename -> sha256 of the exact bytes that produced the published PDFs
declare -A SHA=(
  [Inter-Regular.otf]="d4f2b9e148059a15f014cb0f0b8fea8cd11bfa447dd483bedf1b0adc0e2ba799"
  [Inter-Italic.otf]="3bdf49f72ad2f2959a2619ceef700784504f6d17f502e2e2bc6edce5d43ca631"
  [Inter-SemiBold.otf]="0a4d30778fa2dc239368d90fd854b88b27e7ede737450da72686a90eca66f02c"
  [Inter-Bold.otf]="9fc6261e817d0b1b2bf1953d8799bb1c837d11aeebbf83ae352e7b4d6de6425d"
  [JetBrainsMonoNL-Regular.ttf]="fb3b2575d7b0657359707993288f12a7360344d39387bb26050e276d61f6bd2a"
  [JetBrainsMonoNL-Bold.ttf]="0198e841824025f8876e5c297f0b9b497ee8d6eb9969710a3328e1303f996ec3"
)

verify_all() {
  local fail=0
  for f in "${!SHA[@]}"; do
    if [[ ! -f "$f" ]]; then
      printf '  MISSING  %s\n' "$f"; fail=1; continue
    fi
    local got; got=$(sha256sum "$f" | cut -d' ' -f1)
    if [[ "$got" == "${SHA[$f]}" ]]; then
      printf '  OK       %s\n' "$f"
    else
      printf '  MISMATCH %s\n            expected %s\n            got      %s\n' "$f" "${SHA[$f]}" "$got"
      fail=1
    fi
  done
  return $fail
}

if [[ "${1:-}" == "--check" ]]; then
  echo "Verifying fonts already on disk:"
  verify_all && { echo "All 6 fonts verified."; exit 0; } || { echo "Verification FAILED." >&2; exit 1; }
fi

if verify_all >/dev/null 2>&1; then
  echo "All 6 fonts already present and verified. Nothing to do."
  exit 0
fi

for tool in curl unzip sha256sum; do
  command -v "$tool" >/dev/null || { echo "need $tool on PATH" >&2; exit 2; }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() {  # url  expected_sha  dest
  echo "Downloading $(basename "$3") ..."
  curl -fsSL "$1" -o "$3"
  local got; got=$(sha256sum "$3" | cut -d' ' -f1)
  if [[ "$got" != "$2" ]]; then
    echo "ARCHIVE CHECKSUM MISMATCH for $(basename "$3")" >&2
    echo "  expected $2" >&2
    echo "  got      $got" >&2
    echo "Refusing to extract. The upstream release may have been re-uploaded." >&2
    exit 1
  fi
}

fetch "$INTER_URL" "$INTER_ZIP_SHA" "$TMP/inter.zip"
fetch "$JBM_URL"   "$JBM_ZIP_SHA"   "$TMP/jbm.zip"

echo "Extracting ..."
unzip -qo "$TMP/inter.zip" \
  'extras/otf/Inter-Regular.otf' 'extras/otf/Inter-Italic.otf' \
  'extras/otf/Inter-SemiBold.otf' 'extras/otf/Inter-Bold.otf' -d "$TMP/i"
mv "$TMP"/i/extras/otf/*.otf .

unzip -qo "$TMP/jbm.zip" \
  'fonts/ttf/JetBrainsMonoNL-Regular.ttf' 'fonts/ttf/JetBrainsMonoNL-Bold.ttf' -d "$TMP/j"
mv "$TMP"/j/fonts/ttf/*.ttf .

echo "Verifying extracted files:"
verify_all || { echo "Verification FAILED after extraction." >&2; exit 1; }
echo "All 6 fonts fetched and verified. You can now run ../build.py"
