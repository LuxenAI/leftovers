#!/bin/busybox sh
# Minimal initramfs-only guest used solely for a live Virtualization.framework smoke.
set -eu

export PATH=/usr/bin:/usr/sbin:/bin:/sbin
BB=/bin/busybox
$BB mount -t proc proc /proc || true
$BB mount -t sysfs sysfs /sys || true
$BB mount -t devtmpfs devtmpfs /dev || true

# Alpine's virt kernel keeps the block driver modular. Load only the fixed block
# transport needed for the two launcher-declared disks, then bound device discovery.
/usr/sbin/modprobe virtio_blk
$BB mdev -s
attempts=0
while [ "$attempts" -lt 50 ]; do
    if [ -r /sys/block/vda/ro ] && [ -r /sys/block/vdb/ro ] && [ -b /dev/vdb ]; then
        break
    fi
    $BB sleep 0.1
    attempts=$((attempts + 1))
done
test -r /sys/block/vda/ro
test -r /sys/block/vdb/ro
test -b /dev/vdb

network_interfaces="$($BB ls -1 /sys/class/net 2>/dev/null | $BB tr '\n' ',' | $BB sed 's/,$//')"
virtio_devices="$($BB ls -1 /sys/bus/virtio/devices 2>/dev/null | $BB tr '\n' ',' | $BB sed 's/,$//')"
root_read_only="$($BB cat /sys/block/vda/ro)"
scratch_read_only="$($BB cat /sys/block/vdb/ro)"

{
    printf 'LEFTOVERS_STRICT_VM_SMOKE_V1\n'
    printf 'network_interfaces=%s\n' "$network_interfaces"
    printf 'virtio_devices=%s\n' "$virtio_devices"
    printf 'root_read_only=%s\n' "$root_read_only"
    printf 'scratch_read_only=%s\n' "$scratch_read_only"
    printf 'request_device_present=%s\n' "$(test -e /sys/block/vdc && printf yes || printf no)"
    printf 'guest_pid=%s\n' "$$"
    printf 'complete=true\n'
} >/run/leftovers-smoke-receipt

$BB dd if=/run/leftovers-smoke-receipt of=/dev/vdb bs=4096 count=1 conv=sync
$BB sync
$BB poweroff -f

# A failed shutdown must remain visibly live until the host wall-time guard stops the VM.
while :; do
    $BB sleep 60
done
