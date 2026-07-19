/*
 * Bounded in-guest action interpreter for the future strict-VM worker.
 *
 * This file is deliberately not reachable from the production guest yet.  It
 * is compiled into the supervisor so the exact parser and descriptor rules
 * receive normal compiler coverage, but guest_supervisor.c keeps the release
 * gate false until the scratch-image constructor, result extractor, broker,
 * and live adversarial VM evidence are reviewed together.
 *
 * The implementation has no shell, PATH lookup, package manager, archive
 * extractor, network API, credential lookup, or caller-provided argv.  The
 * only two mutating primitives are a controller-bound replacement record and
 * the two built-in checks below.  Both are rooted at a directory descriptor;
 * absolute paths, dot components, symlinks, hard links, devices, FIFOs, and
 * sockets are rejected before a repository file is read or written.
 */
#ifndef LEFTOVERS_GUEST_INTERPRETER_C
#define LEFTOVERS_GUEST_INTERPRETER_C

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#if defined(__GNUC__)
#define LFR_MAYBE_UNUSED __attribute__((unused))
#else
#define LFR_MAYBE_UNUSED
#endif

#define LFR_HEADER_BYTES 4096U
#define LFR_ALIGNMENT 512U
#define LFR_MAX_SECTIONS 16U
#define LFR_MAX_REQUEST_BYTES (256U * 1024U * 1024U)
#define LFR_MIN_SCRATCH_BYTES (64U * 1024U * 1024U)
#define LFR_MAX_SCRATCH_BYTES (4ULL * 1024ULL * 1024ULL * 1024ULL)
#define LFR_MAX_TAIL_BYTES (64U * 1024U * 1024U)
#define LFR_MAX_ACTIONS 32U
#define LFR_MAX_PATH_BYTES 240U
#define LFR_MAX_FILES 2048U
#define LFR_MAX_TREE_DEPTH 32U
#define LFR_MAX_FILE_BYTES (1024U * 1024U)
#define LFR_MAX_REPOSITORY_BYTES (32U * 1024U * 1024U)
#define LFR_MAX_PATCH_BYTES (256U * 1024U)
#define LFR_MAX_RESULT_BYTES (256U * 1024U)
#define LFR_ACTION_TIMEOUT_SECONDS 120U

/* Linux openat2 resolve flags; the guest kernel pin must expose this syscall. */
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01U
#define RESOLVE_NO_MAGICLINKS 0x02U
#define RESOLVE_BENEATH 0x08U
#define RESOLVE_NO_SYMLINKS 0x04U
#endif

struct lfr_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct lfr_section {
    char name[17];
    uint64_t offset;
    uint64_t length;
    uint8_t digest[32];
};

struct lfr_request {
    char run_id[65];
    char stage[33];
    uint32_t round;
    uint64_t total_bytes;
    uint8_t payload_digest[32];
    struct lfr_section sections[LFR_MAX_SECTIONS];
    size_t section_count;
};

struct lfr_limits {
    uint64_t deadline_monotonic_ns;
    unsigned int files;
    uint64_t bytes;
    unsigned int actions;
};

enum lfr_action_kind {
    LFR_ACTION_APPLY_PATCH = 1,
    LFR_ACTION_RUN_CHECK = 2,
    LFR_ACTION_FINISH = 3,
};

struct lfr_action {
    enum lfr_action_kind kind;
    char id[65];
    char check_id[65];
    char patch_sha256[65];
    char finish_status[9];
};

struct lfr_action_batch {
    struct lfr_action actions[LFR_MAX_ACTIONS];
    size_t action_count;
    size_t patch_count;
    size_t check_count;
};

struct lfr_json_cursor {
    const uint8_t *raw;
    size_t length;
    size_t position;
    size_t nodes;
};

/* Small, self-contained SHA-256. No dynamically loaded crypto implementation
 * is trusted in the guest image. */
struct lfr_sha256 {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};

static uint32_t lfr_rotr(uint32_t value, unsigned int amount) {
    return (value >> amount) | (value << (32U - amount));
}

static uint32_t lfr_be32(const uint8_t *raw) {
    return ((uint32_t)raw[0] << 24U) | ((uint32_t)raw[1] << 16U) |
           ((uint32_t)raw[2] << 8U) | (uint32_t)raw[3];
}

static void lfr_put_be32(uint8_t *raw, uint32_t value) {
    raw[0] = (uint8_t)(value >> 24U);
    raw[1] = (uint8_t)(value >> 16U);
    raw[2] = (uint8_t)(value >> 8U);
    raw[3] = (uint8_t)value;
}

static void lfr_sha256_block(struct lfr_sha256 *hash, const uint8_t *raw) {
    static const uint32_t constants[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
        0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
        0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
        0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
        0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
        0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
    uint32_t words[64];
    uint32_t a = hash->state[0], b = hash->state[1], c = hash->state[2], d = hash->state[3];
    uint32_t e = hash->state[4], f = hash->state[5], g = hash->state[6], h = hash->state[7];
    unsigned int index;
    for (index = 0U; index < 16U; ++index) {
        words[index] = lfr_be32(raw + index * 4U);
    }
    for (; index < 64U; ++index) {
        const uint32_t x = words[index - 15U];
        const uint32_t y = words[index - 2U];
        words[index] = words[index - 16U] + (lfr_rotr(x, 7U) ^ lfr_rotr(x, 18U) ^ (x >> 3U)) +
                       words[index - 7U] + (lfr_rotr(y, 17U) ^ lfr_rotr(y, 19U) ^ (y >> 10U));
    }
    for (index = 0U; index < 64U; ++index) {
        const uint32_t s1 = lfr_rotr(e, 6U) ^ lfr_rotr(e, 11U) ^ lfr_rotr(e, 25U);
        const uint32_t choice = (e & f) ^ ((~e) & g);
        const uint32_t temporary1 = h + s1 + choice + constants[index] + words[index];
        const uint32_t s0 = lfr_rotr(a, 2U) ^ lfr_rotr(a, 13U) ^ lfr_rotr(a, 22U);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temporary2 = s0 + majority;
        h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    hash->state[0] += a; hash->state[1] += b; hash->state[2] += c; hash->state[3] += d;
    hash->state[4] += e; hash->state[5] += f; hash->state[6] += g; hash->state[7] += h;
}

static void lfr_sha256_init(struct lfr_sha256 *hash) {
    static const uint32_t initial[8] = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    memcpy(hash->state, initial, sizeof(initial));
    hash->bits = 0U;
    hash->used = 0U;
}

static void lfr_sha256_update(struct lfr_sha256 *hash, const uint8_t *raw, size_t length) {
    while (length > 0U) {
        const size_t take = length < 64U - hash->used ? length : 64U - hash->used;
        memcpy(hash->block + hash->used, raw, take);
        hash->used += take;
        raw += take;
        length -= take;
        if (hash->used == 64U) {
            lfr_sha256_block(hash, hash->block);
            hash->bits += 512U;
            hash->used = 0U;
        }
    }
}

static void lfr_sha256_final(struct lfr_sha256 *hash, uint8_t out[32]) {
    size_t index;
    hash->bits += (uint64_t)hash->used * 8U;
    hash->block[hash->used++] = 0x80U;
    if (hash->used > 56U) {
        memset(hash->block + hash->used, 0, 64U - hash->used);
        lfr_sha256_block(hash, hash->block);
        hash->used = 0U;
    }
    memset(hash->block + hash->used, 0, 56U - hash->used);
    for (index = 0U; index < 8U; ++index) {
        hash->block[63U - index] = (uint8_t)(hash->bits >> (index * 8U));
    }
    lfr_sha256_block(hash, hash->block);
    for (index = 0U; index < 8U; ++index) {
        lfr_put_be32(out + index * 4U, hash->state[index]);
    }
}

static uint16_t lfr_le16(const uint8_t *raw) {
    return (uint16_t)((uint16_t)raw[0] | ((uint16_t)raw[1] << 8U));
}
static uint32_t lfr_le32(const uint8_t *raw) {
    return (uint32_t)raw[0] | ((uint32_t)raw[1] << 8U) | ((uint32_t)raw[2] << 16U) |
           ((uint32_t)raw[3] << 24U);
}
static uint64_t lfr_le64(const uint8_t *raw) {
    uint64_t value = 0U;
    unsigned int index;
    for (index = 0U; index < 8U; ++index) value |= (uint64_t)raw[index] << (index * 8U);
    return value;
}
static void lfr_put_le16(uint8_t *raw, uint16_t value) { raw[0] = (uint8_t)value; raw[1] = (uint8_t)(value >> 8U); }
static void lfr_put_le32(uint8_t *raw, uint32_t value) {
    raw[0] = (uint8_t)value; raw[1] = (uint8_t)(value >> 8U); raw[2] = (uint8_t)(value >> 16U); raw[3] = (uint8_t)(value >> 24U);
}
static void lfr_put_le64(uint8_t *raw, uint64_t value) { unsigned int i; for (i = 0U; i < 8U; ++i) raw[i] = (uint8_t)(value >> (i * 8U)); }

static bool lfr_pread_exact(int fd, void *buffer, size_t length, uint64_t offset) {
    uint8_t *cursor = buffer;
    while (length > 0U) {
        const ssize_t count = pread(fd, cursor, length, (off_t)offset);
        if (count <= 0) return false;
        cursor += (size_t)count;
        length -= (size_t)count;
        offset += (uint64_t)count;
    }
    return true;
}

static bool lfr_pwrite_all(int fd, const void *buffer, size_t length, uint64_t offset) {
    const uint8_t *cursor = buffer;
    while (length > 0U) {
        const ssize_t count = pwrite(fd, cursor, length, (off_t)offset);
        if (count <= 0) return false;
        cursor += (size_t)count;
        length -= (size_t)count;
        offset += (uint64_t)count;
    }
    return true;
}

static bool lfr_fixed_ascii(const uint8_t *raw, size_t capacity, char *out, size_t out_capacity) {
    size_t length = 0U;
    while (length < capacity && raw[length] != 0U) {
        if (raw[length] < 0x20U || raw[length] > 0x7eU) return false;
        ++length;
    }
    if (length == 0U || length + 1U > out_capacity) return false;
    if (length < capacity) {
        size_t padding;
        for (padding = length; padding < capacity; ++padding) {
            if (raw[padding] != 0U) return false;
        }
    }
    memcpy(out, raw, length);
    out[length] = '\0';
    return true;
}

static bool lfr_run_id_is_valid(const char *value) {
    size_t index;
    if (strnlen(value, 33U) != 32U) {
        return false;
    }
    for (index = 0U; index < 32U; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static uint64_t lfr_section_cap(const char *name) {
    if (strcmp(name, "manifest") == 0 || strcmp(name, "task") == 0 || strcmp(name, "policy") == 0 ||
        strcmp(name, "check_registry") == 0 || strcmp(name, "mediation") == 0) return 64U * 1024U;
    if (strcmp(name, "action_batch") == 0) return 256U * 1024U;
    if (strcmp(name, "prior_obs") == 0) return 128U * 1024U;
    if (strcmp(name, "source_capsule") == 0) return 128U * 1024U * 1024U;
    if (strcmp(name, "cumulative_patch") == 0) return 8U * 1024U * 1024U;
    if (strcmp(name, "proposed_patch") == 0) return LFR_MAX_PATCH_BYTES;
    return 0U;
}

static const struct lfr_section *lfr_section_find(const struct lfr_request *request, const char *name) {
    size_t index;
    for (index = 0U; index < request->section_count; ++index) {
        if (strcmp(request->sections[index].name, name) == 0) return &request->sections[index];
    }
    return NULL;
}

static bool lfr_hash_range(int fd, uint64_t start, uint64_t end, uint8_t digest[32]) {
    uint8_t buffer[8192];
    struct lfr_sha256 hash;
    if (start > end) return false;
    lfr_sha256_init(&hash);
    while (start < end) {
        const size_t length = (end - start) > sizeof(buffer) ? sizeof(buffer) : (size_t)(end - start);
        if (!lfr_pread_exact(fd, buffer, length, start)) return false;
        lfr_sha256_update(&hash, buffer, length);
        start += length;
    }
    lfr_sha256_final(&hash, digest);
    return true;
}

static bool lfr_range_is_zero(int fd, uint64_t start, uint64_t end) {
    uint8_t buffer[4096];
    while (start < end) {
        const size_t length = end - start > sizeof(buffer) ? sizeof(buffer) : (size_t)(end - start);
        size_t index;
        if (!lfr_pread_exact(fd, buffer, length, start)) return false;
        for (index = 0U; index < length; ++index) if (buffer[index] != 0U) return false;
        start += length;
    }
    return true;
}

static bool lfr_parse_request(int request_fd, struct lfr_request *request) {
    uint8_t header[LFR_HEADER_BYTES];
    struct stat status;
    uint64_t request_bytes = 0U;
    int read_only = 0;
    uint64_t prior_offset = 0U;
    uint64_t prior_end = LFR_HEADER_BYTES;
    size_t index;
    bool seen_required[7] = {false, false, false, false, false, false, false};
    static const char *const required[7] = {"manifest", "source_capsule", "task", "policy", "check_registry", "mediation", "action_batch"};
    if (fstat(request_fd, &status) != 0 || status.st_nlink != 1) return false;
    if (S_ISREG(status.st_mode)) {
        if (status.st_size < 0) return false;
        request_bytes = (uint64_t)status.st_size;
    } else if (S_ISBLK(status.st_mode)) {
        if (ioctl(request_fd, BLKGETSIZE64, &request_bytes) != 0 ||
            ioctl(request_fd, BLKROGET, &read_only) != 0 || read_only == 0) return false;
    } else {
        return false;
    }
    if (request_bytes < LFR_HEADER_BYTES || request_bytes > LFR_MAX_REQUEST_BYTES ||
        (request_bytes % LFR_ALIGNMENT) != 0U ||
        !lfr_pread_exact(request_fd, header, sizeof(header), 0U)) return false;
    if (memcmp(header, "LFRQ", 4U) != 0 || lfr_le16(header + 4U) != 1U || lfr_le16(header + 6U) != LFR_HEADER_BYTES ||
        lfr_le16(header + 10U) != 0U) return false;
    request->section_count = lfr_le16(header + 8U);
    request->total_bytes = lfr_le64(header + 12U);
    if (request->section_count == 0U || request->section_count > LFR_MAX_SECTIONS ||
        request->total_bytes != request_bytes ||
        !lfr_fixed_ascii(header + 52U, 64U, request->run_id, sizeof(request->run_id)) ||
        !lfr_run_id_is_valid(request->run_id) ||
        !lfr_fixed_ascii(header + 120U, 32U, request->stage, sizeof(request->stage)) ||
        (strcmp(request->stage, "planning") != 0 && strcmp(request->stage, "implementation") != 0 &&
         strcmp(request->stage, "review") != 0 && strcmp(request->stage, "final_verify") != 0)) return false;
    request->round = lfr_le32(header + 116U);
    memcpy(request->payload_digest, header + 20U, 32U);
    for (index = 0U; index < 32U; ++index) if (header[152U + index] != 0U) return false;
    for (index = 0U; index < request->section_count; ++index) {
        const uint8_t *entry = header + 184U + index * 64U;
        struct lfr_section *section = &request->sections[index];
        uint8_t observed[32];
        size_t required_index;
        if (!lfr_fixed_ascii(entry, 16U, section->name, sizeof(section->name)) || lfr_section_cap(section->name) == 0U ||
            (index > 0U && strcmp(request->sections[index - 1U].name, section->name) >= 0)) return false;
        section->offset = lfr_le64(entry + 16U);
        section->length = lfr_le64(entry + 24U);
        memcpy(section->digest, entry + 32U, 32U);
        if (section->length == 0U || section->length > lfr_section_cap(section->name) ||
            (section->offset % LFR_ALIGNMENT) != 0U || section->offset < LFR_HEADER_BYTES ||
            section->offset < prior_offset || section->offset > request->total_bytes ||
            section->length > request->total_bytes - section->offset || section->offset < prior_end ||
            !lfr_range_is_zero(request_fd, prior_end, section->offset) ||
            !lfr_hash_range(request_fd, section->offset, section->offset + section->length, observed) ||
            memcmp(observed, section->digest, sizeof(observed)) != 0) return false;
        prior_offset = section->offset;
        prior_end = section->offset + section->length;
        for (required_index = 0U; required_index < 7U; ++required_index) if (strcmp(section->name, required[required_index]) == 0) seen_required[required_index] = true;
    }
    if (!lfr_range_is_zero(request_fd, prior_end, request->total_bytes)) return false;
    for (index = 184U + request->section_count * 64U; index < sizeof(header); ++index) if (header[index] != 0U) return false;
    for (index = 0U; index < 7U; ++index) if (!seen_required[index]) return false;
    { uint8_t observed[32]; if (!lfr_hash_range(request_fd, LFR_HEADER_BYTES, request->total_bytes, observed) || memcmp(observed, request->payload_digest, sizeof(observed)) != 0) return false; }
    return true;
}

static bool lfr_json_take(struct lfr_json_cursor *cursor, uint8_t expected) {
    if (cursor->position >= cursor->length || cursor->raw[cursor->position] != expected) {
        return false;
    }
    ++cursor->position;
    return true;
}

static bool lfr_json_key(struct lfr_json_cursor *cursor, const char *key) {
    const size_t length = strlen(key);
    if (!lfr_json_take(cursor, '"') || length > cursor->length - cursor->position ||
        memcmp(cursor->raw + cursor->position, key, length) != 0) {
        return false;
    }
    cursor->position += length;
    return lfr_json_take(cursor, '"') && lfr_json_take(cursor, ':');
}

static bool lfr_json_next_key_is(const struct lfr_json_cursor *cursor, const char *key) {
    const size_t length = strlen(key);
    return cursor->position + length + 3U <= cursor->length &&
           cursor->raw[cursor->position] == '"' &&
           memcmp(cursor->raw + cursor->position + 1U, key, length) == 0 &&
           cursor->raw[cursor->position + length + 1U] == '"' &&
           cursor->raw[cursor->position + length + 2U] == ':';
}

static bool lfr_json_take_utf8_tail(
    struct lfr_json_cursor *cursor,
    uint8_t first,
    size_t *encoded_bytes
) {
    size_t length;
    uint8_t second;
    size_t index;
    if (first >= 0xc2U && first <= 0xdfU) {
        length = 2U;
    } else if (first >= 0xe0U && first <= 0xefU) {
        length = 3U;
    } else if (first >= 0xf0U && first <= 0xf4U) {
        length = 4U;
    } else {
        return false;
    }
    if (cursor->length - cursor->position < length - 1U) {
        return false;
    }
    second = cursor->raw[cursor->position];
    if (second < 0x80U || second > 0xbfU ||
        (first == 0xc2U && second <= 0x9fU) ||
        (first == 0xe0U && second < 0xa0U) ||
        (first == 0xedU && second > 0x9fU) ||
        (first == 0xf0U && second < 0x90U) ||
        (first == 0xf4U && second > 0x8fU)) {
        return false;
    }
    for (index = 1U; index < length - 1U; ++index) {
        const uint8_t continuation = cursor->raw[cursor->position + index];
        if (continuation < 0x80U || continuation > 0xbfU) {
            return false;
        }
    }
    cursor->position += length - 1U;
    *encoded_bytes = length;
    return true;
}

/* canonical_json_bytes(..., ensure_ascii=False) emits non-ASCII text as raw,
 * shortest-form UTF-8. With control characters rejected by the host, only
 * quote and backslash use escapes. Authority-bearing fields permit neither
 * escapes nor UTF-8, so alternate spellings cannot create privileged names. */
static bool lfr_json_string(
    struct lfr_json_cursor *cursor,
    char *output,
    size_t output_capacity,
    bool allow_utf8,
    size_t *decoded_bytes
) {
    size_t output_length = 0U;
    size_t decoded = 0U;
    if (!lfr_json_take(cursor, '"')) {
        return false;
    }
    while (cursor->position < cursor->length) {
        uint8_t value = cursor->raw[cursor->position++];
        size_t encoded_bytes = 1U;
        if (value == '"') {
            if (output != NULL) {
                if (output_length >= output_capacity) {
                    return false;
                }
                output[output_length] = '\0';
            }
            if (decoded_bytes != NULL) {
                *decoded_bytes = decoded;
            }
            return true;
        }
        if (value == '\\') {
            if (!allow_utf8 || cursor->position >= cursor->length) {
                return false;
            }
            value = cursor->raw[cursor->position++];
            if (value == '"' || value == '\\') {
                encoded_bytes = 1U;
            } else {
                return false;
            }
        } else if (value < 0x20U || value == 0x7fU) {
            return false;
        } else if (value >= 0x80U &&
                   (!allow_utf8 || output != NULL ||
                    !lfr_json_take_utf8_tail(cursor, value, &encoded_bytes))) {
            return false;
        }
        if (decoded > 4096U - encoded_bytes) {
            return false;
        }
        decoded += encoded_bytes;
        if (output != NULL) {
            if (value == 0U || output_length + 1U >= output_capacity) {
                return false;
            }
            output[output_length++] = (char)value;
        }
    }
    return false;
}

static bool lfr_json_u32(struct lfr_json_cursor *cursor, uint32_t *output) {
    uint64_t value = 0U;
    size_t digits = 0U;
    if (cursor->position >= cursor->length || cursor->raw[cursor->position] < '0' ||
        cursor->raw[cursor->position] > '9') {
        return false;
    }
    if (cursor->raw[cursor->position] == '0' && cursor->position + 1U < cursor->length &&
        cursor->raw[cursor->position + 1U] >= '0' &&
        cursor->raw[cursor->position + 1U] <= '9') {
        return false;
    }
    while (cursor->position < cursor->length && cursor->raw[cursor->position] >= '0' &&
           cursor->raw[cursor->position] <= '9') {
        value = value * 10U + (uint64_t)(cursor->raw[cursor->position] - '0');
        if (value > UINT32_MAX) {
            return false;
        }
        ++cursor->position;
        ++digits;
    }
    if (digits == 0U) {
        return false;
    }
    *output = (uint32_t)value;
    return true;
}

static bool lfr_action_id_is_valid(const char *value) {
    size_t index;
    const size_t length = strnlen(value, 65U);
    if (length == 0U || length > 64U || value[0] < 'a' || value[0] > 'z') {
        return false;
    }
    for (index = 1U; index < length; ++index) {
        if (!((value[index] >= 'a' && value[index] <= 'z') ||
              (value[index] >= '0' && value[index] <= '9') || value[index] == '_' ||
              value[index] == '-')) {
            return false;
        }
    }
    return true;
}

static bool lfr_digest_text_is_valid(const char *value) {
    size_t index;
    if (strnlen(value, 65U) != 64U) {
        return false;
    }
    for (index = 0U; index < 64U; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static void lfr_digest_text(const uint8_t digest[32], char output[65]) {
    static const char hex[] = "0123456789abcdef";
    size_t index;
    for (index = 0U; index < 32U; ++index) {
        output[index * 2U] = hex[digest[index] >> 4U];
        output[index * 2U + 1U] = hex[digest[index] & 15U];
    }
    output[64] = '\0';
}

static bool lfr_parse_one_action(struct lfr_json_cursor *cursor, struct lfr_action *action) {
    char type[16];
    size_t summary_bytes = 0U;
    memset(action, 0, sizeof(*action));
    if (++cursor->nodes > 256U || !lfr_json_take(cursor, '{')) {
        return false;
    }
    if (lfr_json_next_key_is(cursor, "check_id")) {
        if (!lfr_json_key(cursor, "check_id") ||
            !lfr_json_string(cursor, action->check_id, sizeof(action->check_id), false, NULL) ||
            !lfr_json_take(cursor, ',') || !lfr_json_key(cursor, "id") ||
            !lfr_json_string(cursor, action->id, sizeof(action->id), false, NULL) ||
            !lfr_json_take(cursor, ',') || !lfr_json_key(cursor, "type") ||
            !lfr_json_string(cursor, type, sizeof(type), false, NULL) ||
            strcmp(type, "run_check") != 0) {
            return false;
        }
        action->kind = LFR_ACTION_RUN_CHECK;
    } else {
        if (!lfr_json_key(cursor, "id") ||
            !lfr_json_string(cursor, action->id, sizeof(action->id), false, NULL) ||
            !lfr_json_take(cursor, ',')) {
            return false;
        }
        if (lfr_json_next_key_is(cursor, "patch_sha256")) {
            if (!lfr_json_key(cursor, "patch_sha256") ||
                !lfr_json_string(
                    cursor,
                    action->patch_sha256,
                    sizeof(action->patch_sha256),
                    false,
                    NULL
                ) ||
                !lfr_json_take(cursor, ',') || !lfr_json_key(cursor, "type") ||
                !lfr_json_string(cursor, type, sizeof(type), false, NULL) ||
                strcmp(type, "apply_patch") != 0 ||
                !lfr_digest_text_is_valid(action->patch_sha256)) {
                return false;
            }
            action->kind = LFR_ACTION_APPLY_PATCH;
        } else if (lfr_json_next_key_is(cursor, "status")) {
            if (!lfr_json_key(cursor, "status") ||
                !lfr_json_string(
                    cursor,
                    action->finish_status,
                    sizeof(action->finish_status),
                    false,
                    NULL
                ) ||
                (strcmp(action->finish_status, "complete") != 0 &&
                 strcmp(action->finish_status, "blocked") != 0 &&
                 strcmp(action->finish_status, "failed") != 0) ||
                !lfr_json_take(cursor, ',') || !lfr_json_key(cursor, "summary") ||
                !lfr_json_string(cursor, NULL, 0U, true, &summary_bytes) || summary_bytes == 0U ||
                summary_bytes > 4096U || !lfr_json_take(cursor, ',') ||
                !lfr_json_key(cursor, "type") ||
                !lfr_json_string(cursor, type, sizeof(type), false, NULL) ||
                strcmp(type, "finish") != 0) {
                return false;
            }
            action->kind = LFR_ACTION_FINISH;
        } else {
            return false;
        }
    }
    return lfr_action_id_is_valid(action->id) && lfr_json_take(cursor, '}');
}

static bool lfr_parse_action_batch(
    const uint8_t *raw,
    size_t length,
    const struct lfr_request *request,
    const struct lfr_section *patch,
    struct lfr_action_batch *batch
) {
    struct lfr_json_cursor cursor = {.raw = raw, .length = length, .position = 0U, .nodes = 0U};
    char text[65];
    char expected_patch[65];
    uint32_t number;
    size_t index;
    bool finished = false;
    memset(batch, 0, sizeof(*batch));
    if (length == 0U || length > LFR_MAX_RESULT_BYTES || !lfr_json_take(&cursor, '{') ||
        !lfr_json_key(&cursor, "actions") || !lfr_json_take(&cursor, '[')) {
        return false;
    }
    if (cursor.position >= cursor.length || cursor.raw[cursor.position] == ']') {
        return false;
    }
    for (;;) {
        if (batch->action_count >= LFR_MAX_ACTIONS ||
            !lfr_parse_one_action(&cursor, &batch->actions[batch->action_count])) {
            return false;
        }
        ++batch->action_count;
        if (lfr_json_take(&cursor, ']')) {
            break;
        }
        if (!lfr_json_take(&cursor, ',')) {
            return false;
        }
    }
    if (!lfr_json_take(&cursor, ',') || !lfr_json_key(&cursor, "model") ||
        !lfr_json_string(&cursor, text, sizeof(text), false, NULL) ||
        strcmp(text, "gpt-5.6-terra") != 0 || !lfr_json_take(&cursor, ',') ||
        !lfr_json_key(&cursor, "provider") ||
        !lfr_json_string(&cursor, text, sizeof(text), false, NULL) ||
        strcmp(text, "openai-codex-cli") != 0 || !lfr_json_take(&cursor, ',') ||
        !lfr_json_key(&cursor, "reasoning_effort") ||
        !lfr_json_string(&cursor, text, sizeof(text), false, NULL) || strcmp(text, "high") != 0 ||
        !lfr_json_take(&cursor, ',') || !lfr_json_key(&cursor, "round") ||
        !lfr_json_u32(&cursor, &number) || number != request->round || !lfr_json_take(&cursor, ',') ||
        !lfr_json_key(&cursor, "run_id") ||
        !lfr_json_string(&cursor, text, sizeof(text), false, NULL) ||
        strcmp(text, request->run_id) != 0 || !lfr_json_take(&cursor, ',') ||
        !lfr_json_key(&cursor, "schema_version") || !lfr_json_u32(&cursor, &number) ||
        number != 1U || !lfr_json_take(&cursor, ',') || !lfr_json_key(&cursor, "stage") ||
        !lfr_json_string(&cursor, text, sizeof(text), false, NULL) ||
        strcmp(text, request->stage) != 0 || !lfr_json_take(&cursor, '}') ||
        cursor.position != cursor.length) {
        return false;
    }
    if (patch != NULL) {
        lfr_digest_text(patch->digest, expected_patch);
    } else {
        expected_patch[0] = '\0';
    }
    for (index = 0U; index < batch->action_count; ++index) {
        size_t prior;
        const struct lfr_action *action = &batch->actions[index];
        for (prior = 0U; prior < index; ++prior) {
            if (strcmp(action->id, batch->actions[prior].id) == 0) {
                return false;
            }
        }
        if (finished) {
            return false;
        }
        if (action->kind == LFR_ACTION_APPLY_PATCH) {
            ++batch->patch_count;
            if (strcmp(request->stage, "implementation") != 0 || patch == NULL ||
                strcmp(action->patch_sha256, expected_patch) != 0 || batch->patch_count > 1U) {
                return false;
            }
        } else if (action->kind == LFR_ACTION_RUN_CHECK) {
            ++batch->check_count;
            if (strcmp(request->stage, "final_verify") != 0 ||
                (strcmp(action->check_id, "repo-tree-safety-v1") != 0 &&
                 strcmp(action->check_id, "repo-root-regular-v1") != 0)) {
                return false;
            }
            for (prior = 0U; prior < index; ++prior) {
                if (batch->actions[prior].kind == LFR_ACTION_RUN_CHECK &&
                    strcmp(action->check_id, batch->actions[prior].check_id) == 0) {
                    return false;
                }
            }
        } else if (action->kind == LFR_ACTION_FINISH) {
            finished = true;
            if (index + 1U != batch->action_count) {
                return false;
            }
        } else {
            return false;
        }
    }
    if (!finished || (patch != NULL) != (batch->patch_count == 1U) ||
        (strcmp(request->stage, "final_verify") == 0 && batch->check_count == 0U)) {
        return false;
    }
    return true;
}

static bool lfr_safe_component(const char *component, size_t length) {
    size_t index;
    if (length == 0U || length > NAME_MAX || (length == 1U && component[0] == '.') ||
        (length == 2U && component[0] == '.' && component[1] == '.')) return false;
    for (index = 0U; index < length; ++index) if (component[index] == '/' || component[index] == '\0' || (unsigned char)component[index] < 0x20U) return false;
    return true;
}

static int lfr_open_beneath(int root_fd, const char *path, int flags, mode_t mode) {
    struct lfr_open_how how = {.flags = (uint64_t)(flags | O_CLOEXEC | O_NOFOLLOW), .mode = (uint64_t)mode,
                               .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV};
    size_t length = strnlen(path, LFR_MAX_PATH_BYTES + 1U);
    if (length == 0U || length > LFR_MAX_PATH_BYTES || path[0] == '/' || strstr(path, "//") != NULL ||
        strstr(path, "/./") != NULL || strstr(path, "/../") != NULL || strcmp(path, ".") == 0 ||
        strcmp(path, "..") == 0 || strncmp(path, "../", 3U) == 0 ||
        (length >= 3U && strcmp(path + length - 3U, "/..") == 0)) return -1;
    return (int)syscall(SYS_openat2, root_fd, path, &how, sizeof(how));
}

static bool lfr_regular_single_link(int fd) {
    struct stat status;
    return fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_nlink == 1 && status.st_size <= (off_t)LFR_MAX_FILE_BYTES;
}

static bool lfr_repository_tree_safe_at(
    int directory_fd,
    struct lfr_limits *limits,
    unsigned int depth
) {
    DIR *directory;
    struct dirent *entry;
    int scan_fd;
    if (depth > LFR_MAX_TREE_DEPTH) return false;
    scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
    if (scan_fd < 0) return false;
    directory = fdopendir(scan_fd);
    if (directory == NULL) {
        (void)close(scan_fd);
        return false;
    }
    for (;;) {
        struct stat status;
        int child;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) { (void)closedir(directory); return false; }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (!lfr_safe_component(entry->d_name, strnlen(entry->d_name, NAME_MAX + 1U)) ||
            fstatat(directory_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0 ||
            ++limits->files > LFR_MAX_FILES) { closedir(directory); return false; }
        if (S_ISDIR(status.st_mode)) {
            child = openat(directory_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || !lfr_repository_tree_safe_at(child, limits, depth + 1U)) { if (child >= 0) (void)close(child); closedir(directory); return false; }
            (void)close(child);
        } else if (S_ISREG(status.st_mode) && status.st_nlink == 1 && status.st_size >= 0 && status.st_size <= (off_t)LFR_MAX_FILE_BYTES &&
                   (limits->bytes += (uint64_t)status.st_size) <= LFR_MAX_REPOSITORY_BYTES) {
            continue;
        } else { closedir(directory); return false; }
    }
    return closedir(directory) == 0;
}

/* Fixed checks are functions, not model/repository/controller command strings. */
static int lfr_run_fixed_check(const char *check_id, int repository_fd, struct lfr_limits *limits) {
    if (strcmp(check_id, "repo-tree-safety-v1") == 0) return lfr_repository_tree_safe_at(repository_fd, limits, 0U) ? 0 : 1;
    if (strcmp(check_id, "repo-root-regular-v1") == 0) { struct stat status; return fstat(repository_fd, &status) == 0 && S_ISDIR(status.st_mode) ? 0 : 1; }
    return 125;
}

/* Patch application intentionally uses a tiny replacement-only, canonical
 * LPATCH/1 record. It never shells out to patch/git. The controller currently
 * emits unified diffs, so activation remains gated until it emits this exact
 * format or the two parsers are jointly revised. */
static bool lfr_apply_exact_controller_patch(int repository_fd, int request_fd, const struct lfr_section *patch, const uint8_t expected_digest[32], struct lfr_limits *limits) {
    uint8_t prefix[9];
    char path[LFR_MAX_PATH_BYTES + 1U];
    size_t path_length;
    int target;
    (void)limits;
    if (patch == NULL || patch->length < sizeof(prefix) || patch->length > LFR_MAX_PATCH_BYTES ||
        memcmp(patch->digest, expected_digest, 32U) != 0 ||
        !lfr_pread_exact(request_fd, prefix, sizeof(prefix), patch->offset) ||
        memcmp(prefix, "LPATCH/1\n", sizeof(prefix)) != 0) {
        return false;
    }
    /* The descriptor-only replacement primitive remains intentionally
     * incomplete until LPATCH/1 is jointly specified by guest and controller.
     * It performs no partial write and never falls back to unified-diff tools. */
    memset(path, 0, sizeof(path));
    path_length = strnlen(path, sizeof(path));
    if (!lfr_safe_component(path, path_length)) return false;
    target = lfr_open_beneath(repository_fd, path, O_RDWR, 0U);
    if (target < 0 || !lfr_regular_single_link(target)) { if (target >= 0) (void)close(target); return false; }
    (void)close(target);
    return false; /* no implicit partial write: an unimplemented record fails closed */
}

static bool lfr_action_deadline_ok(const struct lfr_limits *limits) {
    struct timespec now;
    uint64_t nanoseconds;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
    nanoseconds = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
    return nanoseconds <= limits->deadline_monotonic_ns;
}

/* Returns only a complete/blocked/failed bounded record. The footer builder is
 * kept separate from semantic host acceptance; production host extraction
 * remains disabled until it validates all five LFRS sections independently. */
static bool lfr_emit_bounded_result(int scratch_fd, uint64_t scratch_bytes, const struct lfr_request *request, const char *status) {
    uint8_t footer[LFR_HEADER_BYTES];
    uint64_t offset;
    const size_t status_length = strlen(status);
    if (scratch_bytes < LFR_MIN_SCRATCH_BYTES || scratch_bytes > LFR_MAX_SCRATCH_BYTES || (scratch_bytes % LFR_ALIGNMENT) != 0U || status_length == 0U || status_length > 16U) return false;
    memset(footer, 0, sizeof(footer));
    memcpy(footer, "LFRS", 4U); lfr_put_le16(footer + 4U, 1U); lfr_put_le16(footer + 6U, LFR_HEADER_BYTES);
    lfr_put_le16(footer + 8U, 0U); lfr_put_le64(footer + 12U, scratch_bytes);
    memcpy(footer + 52U, request->run_id, strnlen(request->run_id, 64U)); lfr_put_le32(footer + 116U, request->round);
    memcpy(footer + 120U, request->stage, strnlen(request->stage, 32U));
    offset = scratch_bytes - LFR_HEADER_BYTES;
    /* No completion marker is written here. This is intentionally a bounded
     * diagnostic footer, never a host-acceptable success result. */
    return lfr_pwrite_all(scratch_fd, footer, sizeof(footer), offset) && fsync(scratch_fd) == 0;
}

/* The supervisor calls this only in a separately reviewed fixture build. */
static int LFR_MAYBE_UNUSED leftovers_guest_interpret(int request_fd, int repository_fd, int scratch_fd) {
    struct lfr_request request;
    struct lfr_limits limits = {.files = 0U, .bytes = 0U, .actions = 0U};
    struct stat scratch_status;
    const struct lfr_section *actions;
    const struct lfr_section *patch;
    struct lfr_action_batch batch;
    uint8_t *action_json = NULL;
    uint64_t scratch_bytes = 0U;
    int result = 2;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !lfr_parse_request(request_fd, &request) ||
        fstat(repository_fd, &scratch_status) != 0 || !S_ISDIR(scratch_status.st_mode) ||
        fstat(scratch_fd, &scratch_status) != 0 || !S_ISBLK(scratch_status.st_mode) ||
        ioctl(scratch_fd, BLKGETSIZE64, &scratch_bytes) != 0) return 2;
    limits.deadline_monotonic_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec + (uint64_t)LFR_ACTION_TIMEOUT_SECONDS * 1000000000ULL;
    actions = lfr_section_find(&request, "action_batch"); patch = lfr_section_find(&request, "proposed_patch");
    if (actions == NULL || actions->length > LFR_MAX_RESULT_BYTES || !lfr_action_deadline_ok(&limits)) goto done;
    action_json = malloc((size_t)actions->length);
    if (action_json == NULL ||
        !lfr_pread_exact(request_fd, action_json, (size_t)actions->length, actions->offset) ||
        !lfr_parse_action_batch(action_json, (size_t)actions->length, &request, patch, &batch)) {
        goto done;
    }
    limits.actions = (unsigned int)batch.action_count;
    for (size_t index = 0U; index < batch.action_count; ++index) {
        const struct lfr_action *action = &batch.actions[index];
        if (!lfr_action_deadline_ok(&limits)) {
            goto done;
        }
        if (action->kind == LFR_ACTION_APPLY_PATCH) {
            if (!lfr_apply_exact_controller_patch(
                    repository_fd,
                    request_fd,
                    patch,
                    patch->digest,
                    &limits
                )) {
                goto done;
            }
        } else if (action->kind == LFR_ACTION_RUN_CHECK) {
            result = lfr_run_fixed_check(action->check_id, repository_fd, &limits);
            if (result != 0) {
                goto done;
            }
        } else if (action->kind == LFR_ACTION_FINISH) {
            result = strcmp(action->finish_status, "complete") == 0 ? 0 : 1;
        } else {
            goto done;
        }
    }
done:
    if (action_json != NULL) { memset(action_json, 0, (size_t)actions->length); free(action_json); }
    (void)lfr_emit_bounded_result(scratch_fd, scratch_bytes, &request, result == 0 ? "complete" : "failed");
    return result;
}

#ifdef LFR_ACTION_PARSER_TEST
static int lfr_test_hex_digit(uint8_t value) {
    if (value >= '0' && value <= '9') {
        return (int)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (int)(value - 'a') + 10;
    }
    return -1;
}

static bool lfr_test_decode_digest(const char *raw, uint8_t output[32]) {
    size_t index;
    if (strlen(raw) != 64U) {
        return false;
    }
    for (index = 0U; index < 32U; ++index) {
        const int high = lfr_test_hex_digit((uint8_t)raw[index * 2U]);
        const int low = lfr_test_hex_digit((uint8_t)raw[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        output[index] = (uint8_t)((unsigned int)high * 16U + (unsigned int)low);
    }
    return true;
}

static int lfr_test_repository_tree(const char *path) {
    struct lfr_limits limits;
    int directory_fd;
    bool safe;
    memset(&limits, 0, sizeof(limits));
    directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0) {
        return 65;
    }
    safe = lfr_repository_tree_safe_at(directory_fd, &limits, 0U);
    if (close(directory_fd) != 0) {
        safe = false;
    }
    return safe ? 0 : 65;
}

static int lfr_test_request(const char *path) {
    struct lfr_request request;
    int descriptor;
    bool valid;
    memset(&request, 0, sizeof(request));
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return 65;
    }
    valid = lfr_parse_request(descriptor, &request);
    if (close(descriptor) != 0) {
        valid = false;
    }
    return valid ? 0 : 65;
}

int main(int argc, char **argv) {
    struct lfr_request request;
    struct lfr_section patch;
    struct lfr_section *patch_pointer = NULL;
    struct lfr_action_batch batch;
    uint8_t *raw;
    size_t used = 0U;
    char *end = NULL;
    unsigned long round;
    ssize_t count;
    if (argc == 3 && strcmp(argv[1], "--tree") == 0) {
        return lfr_test_repository_tree(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--request") == 0) {
        return lfr_test_request(argv[2]);
    }
    if (argc != 5 || strlen(argv[1]) != 32U || strlen(argv[2]) >= sizeof(request.stage)) {
        return 64;
    }
    errno = 0;
    round = strtoul(argv[3], &end, 10);
    if (errno != 0 || end == argv[3] || *end != '\0' || round > UINT32_MAX) {
        return 64;
    }
    memset(&request, 0, sizeof(request));
    memcpy(request.run_id, argv[1], 33U);
    if (!lfr_run_id_is_valid(request.run_id)) {
        return 64;
    }
    memcpy(request.stage, argv[2], strlen(argv[2]) + 1U);
    request.round = (uint32_t)round;
    memset(&patch, 0, sizeof(patch));
    if (strcmp(argv[4], "-") != 0) {
        if (!lfr_test_decode_digest(argv[4], patch.digest)) {
            return 64;
        }
        patch.length = 1U;
        patch_pointer = &patch;
    }
    raw = malloc(LFR_MAX_RESULT_BYTES + 1U);
    if (raw == NULL) {
        return 70;
    }
    while ((count = read(STDIN_FILENO, raw + used, LFR_MAX_RESULT_BYTES + 1U - used)) > 0) {
        used += (size_t)count;
        if (used > LFR_MAX_RESULT_BYTES) {
            free(raw);
            return 65;
        }
    }
    if (count < 0 || used == 0U ||
        !lfr_parse_action_batch(raw, used, &request, patch_pointer, &batch)) {
        free(raw);
        return 65;
    }
    free(raw);
    if (printf(
            "actions=%zu patches=%zu checks=%zu\n",
            batch.action_count,
            batch.patch_count,
            batch.check_count
        ) < 0) {
        return 74;
    }
    return 0;
}
#endif
#endif
