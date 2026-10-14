/* Standalone early-exec FD service wire format. No runtime pointers or DR
 * private types are part of this interface. All fields use the native byte
 * order of the same-ISA exec family; the version and ELF class are validated. */
#ifndef DR_EXEC_RESOURCES_H
#define DR_EXEC_RESOURCES_H

#include <stdint.h>

#define DR_EXEC_RESOURCE_MAGIC UINT64_C(0x3152435352584544)
#define DR_EXEC_RESOURCE_VERSION 1
/* Includes runtime, private dependencies, target and proc root. Plus the
 * manifest/reply descriptors this remains below Linux SCM_MAX_FD (253). */
#define DR_EXEC_RESOURCE_LIMIT 128
#define DR_EXEC_MANIFEST_LIMIT (1024 * 1024)
/* One initial bootstrap and bounded self-relocations before the client HELLO. */
#define DR_EXEC_RESOURCE_GET_LIMIT 4

enum {
    DR_EXEC_RESOURCE_REGISTER = 1,
    DR_EXEC_RESOURCE_GET = 2,
};
enum {
    DR_EXEC_RESOURCE_OK = 0,
    DR_EXEC_RESOURCE_INVALID = 1,
    DR_EXEC_RESOURCE_UNAVAILABLE = 2,
};
enum {
    DR_EXEC_RESOURCE_RUNTIME = 1,
    DR_EXEC_RESOURCE_PRIVATE = 2,
    DR_EXEC_RESOURCE_TARGET = 3,
    DR_EXEC_RESOURCE_PROCFS = 4,
};

typedef struct {
    uint64_t magic;
    uint32_t version, operation;
    uint64_t exec_nonce;
    uint32_t resource_count, reserved;
    uint64_t manifest_size;
} dr_exec_resource_request_t;

typedef struct {
    uint64_t magic;
    uint32_t version, status;
    uint64_t exec_nonce;
    uint32_t resource_count, reserved;
    uint64_t manifest_size;
} dr_exec_resource_reply_t;

typedef struct {
    uint64_t magic;
    uint32_t version, resource_count;
    uint64_t total_size, records_offset, strings_offset, reserved;
} dr_exec_manifest_t;

/* Each record refers to the descriptor at the same position in SCM_RIGHTS.
 * Strings include a terminating NUL, within the manifest's string pool. The
 * digest covers ELF headers and file-backed PT_LOAD bytes, not relocated
 * process memory. Directory records have zero ELF fields and digest. */
typedef struct {
    uint32_t role, reserved;
    uint64_t path_offset, path_size, soname_offset, soname_size;
    uint64_t file_size, device, inode;
    int64_t modified_seconds;
    uint64_t modified_nanoseconds;
    uint16_t elf_machine;
    uint8_t elf_class, elf_data;
    uint32_t reserved2;
    unsigned char load_digest[16];
} dr_exec_resource_record_t;

#endif /* DR_EXEC_RESOURCES_H */
