/*
 * Rejection-only PID 1 supervisor for the future Leftovers strict-VM guest.
 *
 * This production-reachable supervisor intentionally invokes no request
 * parser, archive extractor, model client, check runner, or result writer.
 * The separately compiled interpreter is source-only and statically
 * unreachable until its complete scratch/result contract is live-attested.
 * Returning without the real LFRS footer makes host extraction fail closed.
 * Do not add a private wire format: the controller-owned format is defined
 * only in src/leftovers/vm_bundle.py.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/reboot.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Compiled for static coverage only. The call-site is deliberately impossible
 * in this release; enabling it requires the separately reviewed scratch-image
 * preparation/result-extraction contract and live VM adversarial evidence. */
#include "guest_interpreter.c"

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_restrict_self 446
#endif

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION 1U
#endif

#define WORKER_UID 65534U
#define WORKER_GID 65534U
#define WORKER_NOFILE_LIMIT 32U
#define WORKER_FILE_LIMIT_BYTES (8U * 1024U * 1024U)
#define WORKER_CPU_LIMIT_SECONDS 120U
#define WORKER_WALL_LIMIT_SECONDS 150U

static bool close_all_inherited_descriptors(void) {
    return syscall(SYS_close_range, 0U, ~0U, 0U) == 0;
}

static bool descriptor_table_is_empty(void) {
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int own_descriptor;
    if (directory == NULL) {
        return false;
    }
    own_descriptor = dirfd(directory);
    for (;;) {
        char *end = NULL;
        long descriptor;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)closedir(directory);
                return false;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        errno = 0;
        descriptor = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' || descriptor < 0L ||
            descriptor > INT_MAX || (int)descriptor != own_descriptor) {
            (void)closedir(directory);
            return false;
        }
    }
    return closedir(directory) == 0;
}

static bool set_exact_resource_limit(int resource, rlim_t value) {
    struct rlimit requested = {.rlim_cur = value, .rlim_max = value};
    struct rlimit observed;
    return setrlimit(resource, &requested) == 0 && getrlimit(resource, &observed) == 0 &&
           observed.rlim_cur == value && observed.rlim_max == value;
}

static bool configure_worker_resource_limits(void) {
    return set_exact_resource_limit(RLIMIT_NOFILE, (rlim_t)WORKER_NOFILE_LIMIT) &&
           set_exact_resource_limit(RLIMIT_FSIZE, (rlim_t)WORKER_FILE_LIMIT_BYTES) &&
           set_exact_resource_limit(RLIMIT_CORE, (rlim_t)0U) &&
           set_exact_resource_limit(RLIMIT_CPU, (rlim_t)WORKER_CPU_LIMIT_SECONDS);
}

static bool arm_worker_wall_timer(void) {
    struct sigaction action;
    struct itimerval timer;
    sigset_t unblocked;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGALRM, &action, NULL) != 0 ||
        sigemptyset(&unblocked) != 0 || sigaddset(&unblocked, SIGALRM) != 0 ||
        sigprocmask(SIG_UNBLOCK, &unblocked, NULL) != 0) {
        return false;
    }
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_sec = (time_t)WORKER_WALL_LIMIT_SECONDS;
    return setitimer(ITIMER_REAL, &timer, NULL) == 0;
}

static bool write_all(int fd, const void *buffer, size_t length) {
    const uint8_t *bytes = buffer;
    while (length > 0U) {
        const ssize_t written = write(fd, bytes, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            return false;
        }
        bytes += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

static bool write_text_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    bool ok;
    if (fd < 0) {
        return false;
    }
    ok = write_all(fd, value, strlen(value));
    if (close(fd) != 0) {
        ok = false;
    }
    return ok;
}

static bool read_exact_text_file(const char *path, const char *expected) {
    char actual[128];
    const size_t expected_length = strlen(expected);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t read_count;
    if (fd < 0 || expected_length >= sizeof(actual)) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return false;
    }
    do {
        read_count = read(fd, actual, sizeof(actual));
    } while (read_count < 0 && errno == EINTR);
    if (close(fd) != 0) {
        return false;
    }
    return read_count == (ssize_t)expected_length &&
           memcmp(actual, expected, expected_length) == 0;
}

static bool make_directory(const char *path, mode_t mode) {
    return mkdir(path, mode) == 0 || errno == EEXIST;
}

static bool root_is_read_only(void) {
    struct statvfs filesystem;
    return statvfs("/", &filesystem) == 0 && (filesystem.f_flag & ST_RDONLY) != 0;
}

static bool mount_boundary_filesystems(void) {
    if (!root_is_read_only() || !make_directory("/proc", 0555) || !make_directory("/sys", 0555) ||
        !make_directory("/dev", 0755) || !make_directory("/run", 0755) ||
        !make_directory("/tmp", 01777) || !make_directory("/sys/fs", 0555) ||
        !make_directory("/sys/fs/cgroup", 0755)) {
        return false;
    }
    return mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0 &&
           mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0 &&
           mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") == 0 &&
           mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0 &&
           mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                 "mode=0755,size=8m,nr_inodes=1024") == 0 &&
           mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                 "mode=1777,size=16m,nr_inodes=2048") == 0;
}

static bool cgroup_controllers_enabled(void) {
    return write_text_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpu +memory +pids\n") &&
           read_exact_text_file("/sys/fs/cgroup/cgroup.subtree_control", "cpu memory pids\n");
}

static bool configure_cgroup(void) {
    const char *base = "/sys/fs/cgroup/leftovers";
    if (!cgroup_controllers_enabled() || !make_directory(base, 0755)) {
        return false;
    }
    return write_text_file("/sys/fs/cgroup/leftovers/memory.max", "402653184\n") &&
           write_text_file("/sys/fs/cgroup/leftovers/memory.swap.max", "0\n") &&
           write_text_file("/sys/fs/cgroup/leftovers/pids.max", "64\n") &&
           write_text_file("/sys/fs/cgroup/leftovers/cpu.max", "50000 100000\n") &&
           read_exact_text_file("/sys/fs/cgroup/leftovers/memory.max", "402653184\n") &&
           read_exact_text_file("/sys/fs/cgroup/leftovers/memory.swap.max", "0\n") &&
           read_exact_text_file("/sys/fs/cgroup/leftovers/pids.max", "64\n") &&
           read_exact_text_file("/sys/fs/cgroup/leftovers/cpu.max", "50000 100000\n");
}

static bool place_self_in_cgroup(void) {
    char pid[32];
    const int count = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
    return count > 0 && (size_t)count < sizeof(pid) &&
           write_text_file("/sys/fs/cgroup/leftovers/cgroup.procs", pid);
}

static bool cmdline_devices_are_exact(void) {
    char command_line[2048];
    char *token;
    FILE *stream = fopen("/proc/cmdline", "re");
    size_t read_count;
    unsigned int request_count = 0U;
    unsigned int scratch_count = 0U;
    if (stream == NULL) {
        return false;
    }
    read_count = fread(command_line, 1U, sizeof(command_line) - 1U, stream);
    if (ferror(stream) != 0 || fclose(stream) != 0) {
        return false;
    }
    command_line[read_count] = '\0';
    for (token = strtok(command_line, " "); token != NULL; token = strtok(NULL, " ")) {
        if (strncmp(token, "leftovers.request=", 19U) == 0) {
            if (++request_count != 1U || strcmp(token, "leftovers.request=/dev/vdc") != 0) {
                return false;
            }
        } else if (strncmp(token, "leftovers.scratch=", 19U) == 0) {
            if (++scratch_count != 1U || strcmp(token, "leftovers.scratch=/dev/vdb") != 0) {
                return false;
            }
        } else if (strncmp(token, "leftovers.", 10U) == 0) {
            return false;
        }
    }
    return request_count == 1U && scratch_count == 1U;
}

static bool block_device_inventory_is_exact(void) {
    DIR *directory = opendir("/sys/class/block");
    struct dirent *entry;
    bool root_seen = false;
    bool scratch_seen = false;
    bool request_seen = false;
    if (directory == NULL) {
        return false;
    }
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)closedir(directory);
                return false;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, "vda") == 0 && !root_seen) {
            root_seen = true;
        } else if (strcmp(entry->d_name, "vdb") == 0 && !scratch_seen) {
            scratch_seen = true;
        } else if (strcmp(entry->d_name, "vdc") == 0 && !request_seen) {
            request_seen = true;
        } else {
            (void)closedir(directory);
            return false;
        }
    }
    return closedir(directory) == 0 && root_seen && scratch_seen && request_seen;
}

static bool inspect_block_device(
    const char *path,
    bool expected_read_only,
    struct stat *identity
) {
    int descriptor;
    int read_only = -1;
    struct stat before;
    struct stat after;
    bool ok;
    if (lstat(path, &before) != 0 || !S_ISBLK(before.st_mode) || before.st_nlink != 1) {
        return false;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        return false;
    }
    ok = fstat(descriptor, &after) == 0 && after.st_dev == before.st_dev &&
         after.st_ino == before.st_ino && after.st_rdev == before.st_rdev &&
         S_ISBLK(after.st_mode) && ioctl(descriptor, BLKROGET, &read_only) == 0 &&
         (read_only != 0) == expected_read_only;
    if (close(descriptor) != 0) {
        ok = false;
    }
    if (!ok) {
        return false;
    }
    *identity = after;
    return true;
}

static bool device_node_policy_is_exact(
    const char *path,
    uid_t expected_uid,
    gid_t expected_gid,
    mode_t expected_mode,
    dev_t expected_device
) {
    struct stat status;
    return lstat(path, &status) == 0 && S_ISBLK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == expected_uid && status.st_gid == expected_gid &&
           (status.st_mode & 07777) == expected_mode && status.st_rdev == expected_device;
}

static bool limited_device_node_inventory_is_exact(void) {
    DIR *directory = opendir("/dev");
    struct dirent *entry;
    bool scratch_seen = false;
    bool request_seen = false;
    if (directory == NULL) {
        return false;
    }
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)closedir(directory);
                return false;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, "vdb") == 0 && !scratch_seen) {
            scratch_seen = true;
        } else if (strcmp(entry->d_name, "vdc") == 0 && !request_seen) {
            request_seen = true;
        } else {
            (void)closedir(directory);
            return false;
        }
    }
    return closedir(directory) == 0 && scratch_seen && request_seen;
}

static bool make_limited_block_node(
    const char *path,
    dev_t device,
    mode_t mode,
    uid_t owner,
    gid_t group
) {
    return mknod(path, (mode_t)(S_IFBLK | mode), device) == 0 &&
           chown(path, owner, group) == 0 && chmod(path, mode) == 0 &&
           device_node_policy_is_exact(path, owner, group, mode, device);
}

static bool required_devices_are_exact_and_minimal(void) {
    struct stat root_device;
    struct stat scratch_device;
    struct stat request_device;
    struct stat limited_scratch;
    struct stat limited_request;
    if (!block_device_inventory_is_exact() ||
        !inspect_block_device("/dev/vda", true, &root_device) ||
        !inspect_block_device("/dev/vdb", false, &scratch_device) ||
        !inspect_block_device("/dev/vdc", true, &request_device) ||
        root_device.st_rdev == scratch_device.st_rdev ||
        root_device.st_rdev == request_device.st_rdev ||
        scratch_device.st_rdev == request_device.st_rdev) {
        return false;
    }
    /* Hide the broad devtmpfs mount beneath a tiny tmpfs. MS_NODEV is
     * deliberately absent because the only two visible entries are the
     * validated request and scratch block nodes created below. The root node
     * and every character device remain unreachable after capability drop. */
    if (mount(
            "tmpfs",
            "/dev",
            "tmpfs",
            MS_NOSUID | MS_NOEXEC,
            "mode=0755,size=64k,nr_inodes=8"
        ) != 0 ||
        !make_limited_block_node(
            "/dev/vdb",
            scratch_device.st_rdev,
            0600,
            (uid_t)WORKER_UID,
            (gid_t)WORKER_GID
        ) ||
        !make_limited_block_node(
            "/dev/vdc",
            request_device.st_rdev,
            0400,
            (uid_t)WORKER_UID,
            (gid_t)WORKER_GID
        ) ||
        !limited_device_node_inventory_is_exact() ||
        !inspect_block_device("/dev/vdb", false, &limited_scratch) ||
        !inspect_block_device("/dev/vdc", true, &limited_request)) {
        return false;
    }
    return limited_scratch.st_rdev == scratch_device.st_rdev &&
           limited_request.st_rdev == request_device.st_rdev;
}

static bool drop_capability_bounding_set_while_privileged(void) {
    unsigned int capability;
    for (capability = 0U; capability < 64U; ++capability) {
        if (prctl(PR_CAPBSET_DROP, (unsigned long)capability, 0UL, 0UL, 0UL) != 0 && errno != EINVAL) {
            return false;
        }
    }
    return prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) == 0;
}

static bool capability_line_is_zero(const char *line_name) {
    char status[4096];
    FILE *stream = fopen("/proc/self/status", "re");
    char *line;
    size_t read_count;
    if (stream == NULL) {
        return false;
    }
    read_count = fread(status, 1U, sizeof(status) - 1U, stream);
    if (ferror(stream) != 0 || fclose(stream) != 0) {
        return false;
    }
    status[read_count] = '\0';
    for (line = strtok(status, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        size_t prefix = strlen(line_name);
        char *value;
        if (strncmp(line, line_name, prefix) != 0 || line[prefix] != ':') {
            continue;
        }
        value = line + prefix + 1U;
        while (*value == ' ' || *value == '\t') {
            ++value;
        }
        if (*value == '\0') {
            return false;
        }
        while (*value != '\0') {
            if (*value != '0') {
                return false;
            }
            ++value;
        }
        return true;
    }
    return false;
}

static bool worker_identity_and_capabilities_are_safe(void) {
    return getuid() == (uid_t)WORKER_UID && geteuid() == (uid_t)WORKER_UID &&
           getgid() == (gid_t)WORKER_GID && getegid() == (gid_t)WORKER_GID &&
           capability_line_is_zero("CapInh") && capability_line_is_zero("CapPrm") &&
           capability_line_is_zero("CapEff") && capability_line_is_zero("CapBnd");
}

static bool install_network_denial_seccomp(void) {
    const struct sock_filter filters[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    const struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filters) / sizeof(filters[0])),
        .filter = (struct sock_filter *)filters,
    };
    return prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) == 0 &&
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

static bool landlock_restrict_worker(void) {
    const uint64_t access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                            LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                            LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
                            LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr ruleset_attr = {.handled_access_fs = access};
    const int abi =
        (int)syscall(SYS_landlock_create_ruleset, NULL, 0U, LANDLOCK_CREATE_RULESET_VERSION);
    int ruleset_fd;
    if (abi < 3) {
        return false;
    }
    ruleset_fd =
        (int)syscall(SYS_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        return false;
    }
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
        (void)close(ruleset_fd);
        return false;
    }
    return close(ruleset_fd) == 0;
}

static int rejection_only_worker(void) {
    if (!descriptor_table_is_empty() || !configure_worker_resource_limits() ||
        !arm_worker_wall_timer() || !place_self_in_cgroup() ||
        !drop_capability_bounding_set_while_privileged() ||
        setgroups(0U, NULL) != 0 || setgid((gid_t)WORKER_GID) != 0 ||
        setuid((uid_t)WORKER_UID) != 0 || !worker_identity_and_capabilities_are_safe() ||
        !install_network_denial_seccomp() || !landlock_restrict_worker()) {
        return 2;
    }
    /* The production worker deliberately invokes neither the compiled LFRQ
     * interpreter nor an LFRS completion writer. */
    return 1;
}

static void power_off(void) {
    sync();
    (void)reboot(LINUX_REBOOT_CMD_POWER_OFF);
    for (;;) {
        pause();
    }
}

int main(void) {
    pid_t worker;
    int status = 0;
    if (getpid() != 1 || !close_all_inherited_descriptors() || !mount_boundary_filesystems() ||
        !descriptor_table_is_empty() || !configure_cgroup() || !cmdline_devices_are_exact() ||
        !required_devices_are_exact_and_minimal()) {
        power_off();
    }
    if (false) {
        (void)leftovers_guest_interpret(-1, -1, -1);
    }
    worker = fork();
    if (worker == 0) {
        _exit(rejection_only_worker());
    }
    if (worker > 0) {
        while (waitpid(worker, &status, 0) < 0 && errno == EINTR) {
        }
    }
    (void)status;
    power_off();
}
