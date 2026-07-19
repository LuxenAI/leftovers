/* Minimal static early PID 1: mount only vda read-only, pivot, then exec. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static bool make_directory(const char *path, mode_t mode) {
    return mkdir(path, mode) == 0 || errno == EEXIST;
}

static void power_off(void) {
    sync();
    (void)reboot(LINUX_REBOOT_CMD_POWER_OFF);
    for (;;) {
        pause();
    }
}

int main(void) {
    char *const argv[] = {"/sbin/leftovers-guest-supervisor", NULL};
    char *const environment[] = {NULL};
    unsigned int attempt;
    if (getpid() != 1 || !make_directory("/dev", 0755) || !make_directory("/newroot", 0755) ||
        mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") != 0) {
        power_off();
    }
    for (attempt = 0U; attempt < 5U; ++attempt) {
        if (mount("/dev/vda", "/newroot", "ext4", MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) == 0) {
            break;
        }
        sleep(1U);
    }
    if (attempt == 5U || !make_directory("/newroot/.oldroot", 0700) || chdir("/newroot") != 0 ||
        syscall(SYS_pivot_root, ".", ".oldroot") != 0 || chdir("/") != 0 ||
        umount2("/.oldroot", MNT_DETACH) != 0 || rmdir("/.oldroot") != 0) {
        power_off();
    }
    execve(argv[0], argv, environment);
    power_off();
}
