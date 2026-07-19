#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=${TMPDIR:-/tmp}/leftovers-strict-vm-launcher.$$
OUT=$WORK/strict-vm-launcher
mkdir -m 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

CLANG_MODULE_CACHE_PATH=$WORK/clang-cache \
SWIFT_MODULE_CACHE_PATH=$WORK/swift-cache \
/usr/bin/swiftc \
    -target arm64-apple-macos26.0 \
    -O \
    -framework CryptoKit \
    -framework Virtualization \
    "$HERE/strict_vm_launcher.swift" \
    -o "$OUT"
/usr/bin/codesign \
    --force \
    --sign - \
    --entitlements "$HERE/strict-vm.entitlements.plist" \
    "$OUT"
/usr/bin/codesign --verify --strict "$OUT"
echo "strict VM launcher compiled and ad-hoc entitlement signature verified"
