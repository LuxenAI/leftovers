#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUPERVISOR=$HERE/package/leftovers-guest-supervisor/src/guest_supervisor.c
EARLY_INIT=$HERE/package/leftovers-guest-supervisor/src/early_init.c
DEFCONFIG=$HERE/configs/leftovers_strict_vm_defconfig

test -f "$HERE/SOURCES.lock.json"
python3 "$HERE/verify-sources.py"
python3 "$HERE/release.py" validate-locks
test -f "$SUPERVISOR"
test -f "$EARLY_INIT"
test -f "$DEFCONFIG"
grep -q 'BR2_LINUX_KERNEL_CUSTOM_REPO_VERSION="669dc96e243e422e7404bb98be00d527bafc0a96"' "$DEFCONFIG"
grep -q 'CONFIG_NET=n' "$HERE/board/leftovers/linux.fragment"
grep -q 'CONFIG_SECURITY_LANDLOCK=y' "$HERE/board/leftovers/linux.fragment"
grep -q 'SYS_pivot_root' "$EARLY_INIT"
grep -q 'mount("/dev/vda", "/newroot", "ext4", MS_RDONLY' "$EARLY_INIT"
grep -q 'PR_SET_NO_NEW_PRIVS' "$SUPERVISOR"
grep -q 'SECCOMP_MODE_FILTER' "$SUPERVISOR"
grep -q 'SYS_landlock_restrict_self' "$SUPERVISOR"
grep -q 'memory.max' "$SUPERVISOR"
grep -q 'pids.max' "$SUPERVISOR"
grep -q 'cpu.max' "$SUPERVISOR"
grep -q 'cgroup.subtree_control' "$SUPERVISOR"
grep -q 'leftovers.request=/dev/vdc' "$SUPERVISOR"
grep -q 'leftovers.scratch=/dev/vdb' "$SUPERVISOR"
grep -q 'There is intentionally no LFRQ parser and no LFRS writer here' "$SUPERVISOR"
! grep -q 'LFR_HEADER_BYTES' "$SUPERVISOR"
! grep -q 'emit_lfrs' "$SUPERVISOR"
! grep -Eq '\b(system|popen|execlp|execvp)\s*\(' "$SUPERVISOR"
echo 'strict guest static policy checks passed'
