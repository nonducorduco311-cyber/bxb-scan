#!/usr/bin/env bash
# Build the ByTE X Bit Posture Scanner (stdlib only, no deps).
# Bump VERSION for each release; filenames and the in-app version follow it,
# which also sidesteps CDN/browser download caching (every release = new URL).
set -e
VERSION="0.1.0"

mkdir -p dist
LDFLAGS="-s -w -X main.version=${VERSION}"

echo "Building v${VERSION} ..."
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "dist/bxb-scan-${VERSION}"     .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "dist/bxb-scan-${VERSION}.exe" .

( cd dist && sha256sum "bxb-scan-${VERSION}" "bxb-scan-${VERSION}.exe" | tee "SHA256SUMS-${VERSION}.txt" )

echo
echo "Done. Release files in ./dist/ :"
echo "  bxb-scan-${VERSION}        (Linux)"
echo "  bxb-scan-${VERSION}.exe    (Windows)"
echo "  SHA256SUMS-${VERSION}.txt"
