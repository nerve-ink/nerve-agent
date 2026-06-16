#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
DIST_DIR="$ROOT/dist"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

build_one() {
  local goos="$1"
  local goarch="$2"
  local name="nerve-agent-${goos}-${goarch}"

  echo "building ${name}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o "${DIST_DIR}/${name}" \
      .
}

build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64

(
  cd "$DIST_DIR"
  shasum -a 256 nerve-agent-* > checksums.txt
)

echo
echo "release artifacts:"
ls -lh "$DIST_DIR"
