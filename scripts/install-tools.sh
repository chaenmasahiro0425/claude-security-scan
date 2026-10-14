#!/usr/bin/env bash
# gitleaks と osv-scanner を公式GitHubリリースから bin/ に取得し、SHA256 を検証する。
# Homebrew 等で既に入っていれば不要（PATH 上のものを使う）。
set -euo pipefail
GITLEAKS_VERSION="8.30.1"
OSV_VERSION="2.7.0"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
mkdir -p "$BIN"
TMP="$(mktemp -d)"
trap 'rm -r "$TMP"' EXIT

os="$(uname -s | tr '[:upper:]' '[:lower:]')"   # darwin / linux
arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) gl_arch=arm64; osv_arch=arm64 ;;
  x86_64|amd64)  gl_arch=x64;   osv_arch=amd64 ;;
  *) echo "未対応のCPU: $arch" >&2; exit 1 ;;
esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
verify() {  # verify <file> <checksums file>
  local name expected actual
  name="$(basename "$1")"
  expected="$(awk -v n="$name" '$2==n || $2=="*"n {print $1}' "$2")"
  actual="$(sha256 "$1")"
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "チェックサム不一致: $name" >&2; exit 1
  fi
  echo "  ✓ $name の SHA256 を確認"
}

echo "gitleaks v$GITLEAKS_VERSION ($os/$gl_arch)"
gl="gitleaks_${GITLEAKS_VERSION}_${os}_${gl_arch}.tar.gz"
base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
curl -fsSL -o "$TMP/$gl" "$base/$gl"
curl -fsSL -o "$TMP/gl_sums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
verify "$TMP/$gl" "$TMP/gl_sums.txt"
tar -xzf "$TMP/$gl" -C "$TMP" gitleaks
install -m 755 "$TMP/gitleaks" "$BIN/gitleaks"

echo "osv-scanner v$OSV_VERSION ($os/$osv_arch)"
osv="osv-scanner_${os}_${osv_arch}"
base="https://github.com/google/osv-scanner/releases/download/v$OSV_VERSION"
curl -fsSL -o "$TMP/$osv" "$base/$osv"
curl -fsSL -o "$TMP/osv_sums.txt" "$base/osv-scanner_SHA256SUMS"
verify "$TMP/$osv" "$TMP/osv_sums.txt"
install -m 755 "$TMP/$osv" "$BIN/osv-scanner"

if [ "$os" = darwin ]; then xattr -d com.apple.quarantine "$BIN/gitleaks" "$BIN/osv-scanner" 2>/dev/null || true; fi
"$BIN/gitleaks" version
"$BIN/osv-scanner" --version | head -1
echo "完了: $BIN"
