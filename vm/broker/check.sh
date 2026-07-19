#!/bin/sh
# Compile and exercise only the native adapter's rejection path.  This script
# never installs a daemon, registers/binds a Mach service, or creates XPC work.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=${TMPDIR:-/tmp}/leftovers-native-broker-check.$$
OUT=$WORK/NativeBrokerTrustAdapter
mkdir -m 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

/usr/bin/clang \
    -target arm64-apple-macos26.0 \
    -std=c11 \
    -Werror \
    -fsyntax-only \
    "$HERE/SecurityFlagValues.c"

CLANG_MODULE_CACHE_PATH=$WORK/clang-cache \
SWIFT_MODULE_CACHE_PATH=$WORK/swift-cache \
/usr/bin/swiftc \
    -target arm64-apple-macos26.0 \
    -framework Security \
    "$HERE/NativeBrokerTrustAdapter.swift" \
    -o "$OUT"

set +e
"$OUT" --self-check >"$WORK/stdout" 2>"$WORK/stderr"
status=$?
set -e
test "$status" -eq 78
test ! -s "$WORK/stdout"
grep -Fqx 'source_disabled: native broker trust adapter rejects before manifest, account, Security, or XPC access' "$WORK/stderr"

# Keep the source's negative guarantees reviewable and deterministic.
! grep -Eq 'xpc_connection_create_mach_service|xpc_main\(|launchctl|SMAppService|AuthorizationExecuteWithPrivileges' \
    "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'SecCodeCreateWithXPCMessage' "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'SecCodeCopySelf' "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'SecCodeCopySigningInformation' "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'SecRequirementCopyData' "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'openat(directory, manifestFilename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)' \
    "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'try descriptor.withOpenDescriptor' "$HERE/NativeBrokerTrustAdapter.swift"
grep -Fq 'try closeAllChecked(&directories)' "$HERE/NativeBrokerTrustAdapter.swift"

echo 'native broker trust adapter compiled; rejection-only self-check passed'
