/* FD-only early-exec resource handoff. The service owns descriptor references,
 * not copies of library bytes. This file can run before DR's heap/TLS init. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <elf.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <errno.h>
#include <stdlib.h>
#include "../globals.h"
#include "../module_shared.h"
#include "../utils.h"
#include "os_private.h"
#include "include/syscall.h"
#include "exec_resources.h"

#ifndef O_PATH
#    define O_PATH 010000000
#endif
#ifndef F_ADD_SEALS
#    define F_ADD_SEALS 1033
#    define F_GET_SEALS 1034
#    define F_SEAL_SEAL 0x0001
#    define F_SEAL_SHRINK 0x0002
#    define F_SEAL_GROW 0x0004
#    define F_SEAL_WRITE 0x0008
#endif

#if defined(LINUX) && defined(X86) && defined(X64)
/* Written before the image starts executing, then read-only until teardown. */
static file_t service_file = INVALID_FILE;
static file_t initial_runtime = INVALID_FILE;
static byte *bootstrap_manifest;
static size_t bootstrap_size;
static uint bootstrap_count;
static file_t bootstrap_files[DR_EXEC_RESOURCE_LIMIT];

/* These are owned runtime resources, not application descriptors. Before the
 * protected-FD table exists, retain them outside 0/1/2 so a closed application
 * standard stream stays closed. Later loader adoption adds normal protection. */
static file_t
resource_outside_stdio(file_t owned)
{
    if (owned < 0 || owned > 2)
        return owned;
    ptr_int_t duplicate;
    do {
        duplicate = dynamorio_syscall(SYS_fcntl, 3, owned, F_DUPFD_CLOEXEC, 3);
    } while (duplicate == -EINTR);
    os_close(owned);
    return duplicate < 0 ? INVALID_FILE : (file_t)duplicate;
}

static bool
read_at(file_t file, void *data, size_t size, uint64 offset)
{
    byte *cursor = data;
    if (offset > INT64_MAX || size > INT64_MAX - offset)
        return false;
    while (size != 0) {
        ptr_int_t count = dynamorio_syscall(SYS_pread64, 4, file, cursor, size, offset);
        if (count == -EINTR)
            continue;
        if (count <= 0)
            return false;
        cursor += count;
        size -= count;
        offset += count;
    }
    return true;
}

static bool
resource_identity(file_t file, dr_exec_resource_record_t *record)
{
    struct stat info;
    if (dynamorio_syscall(SYS_fstat, 2, file, &info) != 0 || info.st_size < 0)
        return false;
    record->file_size = info.st_size;
    record->device = info.st_dev;
    record->inode = info.st_ino;
    record->modified_seconds = info.st_mtim.tv_sec;
    record->modified_nanoseconds = info.st_mtim.tv_nsec;
    if (record->role == DR_EXEC_RESOURCE_PROCFS) {
        struct statfs fs;
        return S_ISDIR(info.st_mode) &&
            dynamorio_syscall(SYS_fstatfs, 2, file, &fs) == 0 &&
            fs.f_type == PROC_SUPER_MAGIC;
    }
    if (!S_ISREG(info.st_mode))
        return false;
    Elf64_Ehdr header;
    if (!read_at(file, &header, sizeof(header), 0) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_ident[EI_VERSION] != EV_CURRENT || header.e_machine != EM_X86_64 ||
        header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Elf64_Phdr) ||
        header.e_phnum == 0 || header.e_phnum == PN_XNUM ||
        header.e_phoff > record->file_size ||
        header.e_phnum > (record->file_size - header.e_phoff) / sizeof(Elf64_Phdr))
        return false;
    record->elf_machine = header.e_machine;
    record->elf_class = header.e_ident[EI_CLASS];
    record->elf_data = header.e_ident[EI_DATA];
    struct MD5Context digest;
    d_r_md5_init(&digest);
    d_r_md5_update(&digest, (byte *)&header, sizeof(header));
    /* Header order is part of the public digest definition. Reading one header
     * at a time avoids allocating an attacker-controlled table before the heap. */
    for (uint i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr segment;
        if (!read_at(file, &segment, sizeof(segment),
                     header.e_phoff + i * sizeof(segment)))
            return false;
        d_r_md5_update(&digest, (byte *)&segment, sizeof(segment));
    }
    bool loaded = false;
    byte buffer[4096];
    for (uint i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr segment;
        if (!read_at(file, &segment, sizeof(segment),
                     header.e_phoff + i * sizeof(segment)))
            return false;
        if (segment.p_type != PT_LOAD)
            continue;
        if (segment.p_filesz > segment.p_memsz || segment.p_offset > record->file_size ||
            segment.p_filesz > record->file_size - segment.p_offset)
            return false;
        loaded = true;
        for (uint64 offset = 0; offset < segment.p_filesz;) {
            size_t size = MIN(sizeof(buffer), segment.p_filesz - offset);
            if (!read_at(file, buffer, size, segment.p_offset + offset))
                return false;
            d_r_md5_update(&digest, buffer, size);
            offset += size;
        }
    }
    d_r_md5_final(record->load_digest, &digest);
    struct stat after;
    return loaded && dynamorio_syscall(SYS_fstat, 2, file, &after) == 0 &&
        after.st_size == info.st_size && after.st_dev == info.st_dev &&
        after.st_ino == info.st_ino && after.st_mtim.tv_sec == info.st_mtim.tv_sec &&
        after.st_mtim.tv_nsec == info.st_mtim.tv_nsec;
}

static bool
valid_string(const dr_exec_manifest_t *header, uint64 offset, uint64 size)
{
    if (size == 0 || offset < header->strings_offset || offset > header->total_size ||
        size > header->total_size - offset)
        return false;
    const byte *text = (const byte *)header + offset;
    for (uint64 i = 0; i < size; ++i) {
        if (text[i] == 0)
            return i == size - 1;
    }
    return false;
}

static bool
validate_manifest(byte *data, size_t size, file_t *files, uint count)
{
    if (size < sizeof(dr_exec_manifest_t))
        return false;
    dr_exec_manifest_t *header = (dr_exec_manifest_t *)data;
    if (header->magic != DR_EXEC_RESOURCE_MAGIC ||
        header->version != DR_EXEC_RESOURCE_VERSION || header->reserved != 0 ||
        header->resource_count != count || header->total_size != size ||
        header->records_offset != sizeof(*header) ||
        header->strings_offset !=
            sizeof(*header) + count * sizeof(dr_exec_resource_record_t) ||
        header->strings_offset > size)
        return false;
    dr_exec_resource_record_t *records = (void *)(data + header->records_offset);
    uint runtime = 0, target = 0, procfs = 0;
    for (uint i = 0; i < count; ++i) {
        dr_exec_resource_record_t expected = records[i], actual = { 0 };
        if (expected.reserved != 0 || expected.reserved2 != 0 ||
            !valid_string(header, expected.path_offset, expected.path_size) ||
            expected.path_size < 2 ||
            !valid_string(header, expected.soname_offset, expected.soname_size))
            return false;
        if (expected.role == DR_EXEC_RESOURCE_RUNTIME)
            ++runtime;
        else if (expected.role == DR_EXEC_RESOURCE_TARGET)
            ++target;
        else if (expected.role == DR_EXEC_RESOURCE_PROCFS)
            ++procfs;
        else if (expected.role != DR_EXEC_RESOURCE_PRIVATE)
            return false;
        ptr_int_t flags = dynamorio_syscall(SYS_fcntl, 3, files[i], F_GETFL, 0);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || TESTANY(O_PATH, flags))
            return false;
        actual.role = expected.role;
        if (!resource_identity(files[i], &actual))
            return false;
        actual.path_offset = expected.path_offset;
        actual.path_size = expected.path_size;
        actual.soname_offset = expected.soname_offset;
        actual.soname_size = expected.soname_size;
        if (memcmp(&actual, &expected, sizeof(actual)) != 0)
            return false;
    }
    return runtime == 1 && target == 1 && procfs == 1;
}

/* Each caller has its own reply socket: inherited broker endpoints never have
 * a shared response queue, even when several descendants exec concurrently. */
static bool
exchange(const dr_exec_resource_request_t *request, const file_t *send_files,
         uint send_count, dr_exec_resource_reply_t *reply, file_t *received,
         uint *received_count)
{
    int sockets[2];
    *received_count = 0;
    if (send_count > DR_EXEC_RESOURCE_LIMIT + 1 ||
        (send_count != 0 && send_files == NULL))
        return false;
    if (dynamorio_syscall(SYS_socketpair, 4, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                          sockets) != 0)
        return false;
    union {
        struct cmsghdr alignment;
        byte data[CMSG_SPACE((DR_EXEC_RESOURCE_LIMIT + 2) * sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec payload = { (void *)request, sizeof(*request) };
    struct msghdr message = { 0 };
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control.data;
    message.msg_controllen = CMSG_SPACE((send_count + 1) * sizeof(int));
    struct cmsghdr *rights = CMSG_FIRSTHDR(&message);
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN((send_count + 1) * sizeof(int));
    int *fds = (int *)CMSG_DATA(rights);
    fds[0] = sockets[1];
    for (uint i = 0; i < send_count; ++i)
        fds[i + 1] = send_files[i];
    ptr_int_t result;
    do {
        result = dynamorio_syscall(SYS_sendmsg, 3, service_file, &message, MSG_NOSIGNAL);
    } while (result == -EINTR);
    os_close(sockets[1]);
    bool valid = result == sizeof(*request);
    *received_count = 0;
    if (valid) {
        payload.iov_base = reply;
        payload.iov_len = sizeof(*reply);
        message.msg_controllen = sizeof(control);
        memset(&control, 0, sizeof(control));
        do {
            result =
                dynamorio_syscall(SYS_recvmsg, 3, sockets[0], &message, MSG_CMSG_CLOEXEC);
        } while (result == -EINTR);
        valid = result == sizeof(*reply) &&
            !TESTANY(MSG_TRUNC | MSG_CTRUNC, message.msg_flags);
        size_t control_size = message.msg_controllen;
        if (control_size > sizeof(control.data)) {
            control_size = sizeof(control.data);
            valid = false;
        }
        /* CMSG_NXTHDR can call glibc's __cmsg_nxthdr in an unoptimized build.
         * Walk bounded offsets instead: this path also runs before DR's heap
         * and private loader are initialized. */
        for (size_t offset = 0; offset < control_size;) {
            size_t remaining = control_size - offset;
            struct cmsghdr part;
            if (remaining < sizeof(part)) {
                valid = false;
                break;
            }
            memcpy(&part, control.data + offset, sizeof(part));
            if (part.cmsg_len < CMSG_LEN(0) || part.cmsg_len > remaining) {
                valid = false;
                break;
            }
            if (part.cmsg_level != SOL_SOCKET || part.cmsg_type != SCM_RIGHTS) {
                valid = false;
            } else {
                size_t length = part.cmsg_len - CMSG_LEN(0);
                for (size_t i = 0; i < length / sizeof(int); ++i) {
                    int descriptor;
                    memcpy(&descriptor,
                           control.data + offset + CMSG_LEN(0) + i * sizeof(int),
                           sizeof(descriptor));
                    if (*received_count < DR_EXEC_RESOURCE_LIMIT + 1)
                        received[(*received_count)++] = descriptor;
                    else {
                        os_close(descriptor);
                        valid = false;
                    }
                }
                if (length % sizeof(int) != 0)
                    valid = false;
            }
            size_t stride = CMSG_ALIGN(part.cmsg_len);
            if (stride < part.cmsg_len) {
                valid = false;
                break;
            }
            /* A final cmsg need not include all of its alignment padding. */
            if (stride > remaining)
                break;
            offset += stride;
        }
        valid = valid && reply->magic == DR_EXEC_RESOURCE_MAGIC &&
            reply->version == DR_EXEC_RESOURCE_VERSION && reply->reserved == 0 &&
            reply->exec_nonce == request->exec_nonce &&
            reply->status == DR_EXEC_RESOURCE_OK;
    }
    os_close(sockets[0]);
    if (!valid) {
        for (uint i = 0; i < *received_count; ++i)
            os_close(received[i]);
        *received_count = 0;
    }
    return valid;
}

bool
os_exec_resources_bootstrap(void)
{
    const char *value = getenv(DYNAMORIO_VAR_EXEC_SERVICE);
    uint64 nonce;
    int broker;
    char trailing;
    if (value == NULL)
        return true;
    if (sscanf(value, "%d:" UINT64_FORMAT_STRING "%c", &broker, &nonce, &trailing) != 2 ||
        broker < 3 || nonce == 0)
        return false;
    service_file = broker;
    dr_exec_resource_request_t request = { DR_EXEC_RESOURCE_MAGIC,
                                           DR_EXEC_RESOURCE_VERSION,
                                           DR_EXEC_RESOURCE_GET,
                                           nonce,
                                           0,
                                           0,
                                           0 };
    dr_exec_resource_reply_t reply;
    file_t received[DR_EXEC_RESOURCE_LIMIT + 1];
    uint count;
    if (!exchange(&request, NULL, 0, &reply, received, &count))
        return false;
    bool valid = reply.resource_count > 0 &&
        reply.resource_count <= DR_EXEC_RESOURCE_LIMIT &&
        count == reply.resource_count + 1 &&
        reply.manifest_size >= sizeof(dr_exec_manifest_t) &&
        reply.manifest_size <= DR_EXEC_MANIFEST_LIMIT;
    for (uint i = 0; i < count; ++i) {
        received[i] = resource_outside_stdio(received[i]);
        valid &= received[i] != INVALID_FILE;
    }
    struct stat status;
    if (valid) {
        ptr_int_t seals = dynamorio_syscall(SYS_fcntl, 3, received[0], F_GET_SEALS, 0);
        uint required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        valid = seals >= 0 && (seals & required) == required &&
            dynamorio_syscall(SYS_fstat, 2, received[0], &status) == 0 &&
            S_ISREG(status.st_mode) && status.st_size == reply.manifest_size;
    }
    byte *mapping = NULL;
    size_t size = reply.manifest_size;
    if (valid) {
        mapping = os_map_file(received[0], &size, 0, NULL, MEMPROT_READ, 0);
        valid = mapping != NULL && size == reply.manifest_size &&
            validate_manifest(mapping, size, received + 1, reply.resource_count);
    }
    if (!valid) {
        if (mapping != NULL)
            os_unmap_file(mapping, size);
        for (uint i = 0; i < count; ++i)
            if (received[i] != INVALID_FILE)
                os_close(received[i]);
        return false;
    }
    os_close(received[0]);
    bootstrap_manifest = mapping;
    bootstrap_size = size;
    bootstrap_count = reply.resource_count;
    for (uint i = 0; i < bootstrap_count; ++i)
        bootstrap_files[i] = received[i + 1];
    return true;
}

void
os_exec_resources_release_bootstrap(void)
{
    for (uint i = 0; i < bootstrap_count; ++i) {
        if (bootstrap_files[i] != INVALID_FILE)
            os_close(bootstrap_files[i]);
    }
    if (bootstrap_manifest != NULL)
        os_unmap_file(bootstrap_manifest, bootstrap_size);
    bootstrap_manifest = NULL;
    bootstrap_count = 0;
    if (initial_runtime != INVALID_FILE)
        os_close(initial_runtime);
    initial_runtime = INVALID_FILE;
}

file_t
os_exec_resource_file(uint role)
{
    dr_exec_resource_record_t *records = bootstrap_manifest == NULL
        ? NULL
        : (void *)(bootstrap_manifest + sizeof(dr_exec_manifest_t));
    for (uint i = 0; i < bootstrap_count; ++i) {
        if (records[i].role == role)
            return bootstrap_files[i];
    }
    if (role == DR_EXEC_RESOURCE_RUNTIME) {
        if (dynamo_heap_initialized) {
            acquire_recursive_lock(&privload_lock);
            privmod_t *runtime = privload_lookup_by_base(get_dynamorio_dll_start());
            file_t file = runtime == NULL ? INVALID_FILE : runtime->backing_file;
            release_recursive_lock(&privload_lock);
            if (file != INVALID_FILE)
                return file;
        }
        if (initial_runtime == INVALID_FILE)
            initial_runtime = resource_outside_stdio(os_open_procfs("self/exe", false));
        return initial_runtime;
    }
    return INVALID_FILE;
}

file_t
os_exec_resource_take(uint role)
{
    dr_exec_resource_record_t *records = bootstrap_manifest == NULL
        ? NULL
        : (void *)(bootstrap_manifest + sizeof(dr_exec_manifest_t));
    for (uint i = 0; i < bootstrap_count; ++i) {
        if (records[i].role == role) {
            file_t file = bootstrap_files[i];
            bootstrap_files[i] = INVALID_FILE;
            return file;
        }
    }
    if (role == DR_EXEC_RESOURCE_RUNTIME) {
        file_t file = os_exec_resource_file(role);
        initial_runtime = INVALID_FILE;
        return file;
    }
    return INVALID_FILE;
}

file_t
os_exec_resource_lookup(const char *name, const char **path)
{
    dr_exec_resource_record_t *records = bootstrap_manifest == NULL
        ? NULL
        : (void *)(bootstrap_manifest + sizeof(dr_exec_manifest_t));
    for (uint i = 0; i < bootstrap_count; ++i) {
        const char *logical = (char *)bootstrap_manifest + records[i].path_offset;
        const char *soname = (char *)bootstrap_manifest + records[i].soname_offset;
        /* DT_SONAME is optional. privmod's existing fallback can include the
         * leading slash, while DT_NEEDED normally contains only the basename. */
        const char *base = strrchr(logical, '/');
        base = base == NULL ? logical : base + 1;
        if (records[i].role == DR_EXEC_RESOURCE_PRIVATE &&
            (strcmp(name, logical) == 0 ||
             (name[0] != '/' &&
              (strcmp(name, soname) == 0 ||
               ((soname[0] == 0 || soname[0] == '/') && strcmp(name, base) == 0))))) {
            if (path != NULL)
                *path = logical;
            return bootstrap_files[i];
        }
    }
    return INVALID_FILE;
}

bool
os_exec_resources_set_service(file_t broker)
{
    int type;
    socklen_t size = sizeof(type);
    ptr_int_t flags = dynamorio_syscall(SYS_fcntl, 3, broker, F_GETFD, 0);
    if (broker < 3 || flags < 0 || TESTANY(FD_CLOEXEC, flags) ||
        !DYNAMO_OPTION(early_inject) ||
        (service_file != INVALID_FILE && service_file != broker) ||
        dynamorio_syscall(SYS_getsockopt, 5, broker, SOL_SOCKET, SO_TYPE, &type, &size) !=
            0 ||
        type != SOCK_SEQPACKET)
        return false;
    service_file = broker;
    return true;
}

file_t
os_exec_resources_service(void)
{
    return service_file;
}

bool
os_exec_resources_register(uint64 nonce, file_t target, const char *path,
                           file_t proc_root)
{
    if (service_file == INVALID_FILE || nonce == 0)
        return false;
    file_t files[DR_EXEC_RESOURCE_LIMIT + 1];
    const char *paths[DR_EXEC_RESOURCE_LIMIT], *names[DR_EXEC_RESOURCE_LIMIT];
    uint roles[DR_EXEC_RESOURCE_LIMIT];
    uint count = 0;
    size_t strings_size = 0;
    bool valid = true;
    acquire_recursive_lock(&privload_lock);
    for (privmod_t *mod = privload_first_module(); mod != NULL; mod = mod->next) {
        if (mod->backing_file == INVALID_FILE)
            continue;
        if (count == DR_EXEC_RESOURCE_LIMIT - 2) {
            valid = false;
            break;
        }
        files[count + 1] = mod->backing_file;
        paths[count] = mod->path;
        names[count] = mod->name == NULL ? "" : mod->name;
        roles[count] = mod->base == get_dynamorio_dll_start() ? DR_EXEC_RESOURCE_RUNTIME
                                                              : DR_EXEC_RESOURCE_PRIVATE;
        ++count;
    }
    files[count + 1] = target;
    paths[count] = path;
    names[count] = "";
    roles[count++] = DR_EXEC_RESOURCE_TARGET;
    files[count + 1] = proc_root;
    paths[count] = "/proc";
    names[count] = "";
    roles[count++] = DR_EXEC_RESOURCE_PROCFS;
    for (uint i = 0; i < count; ++i)
        strings_size += strlen(paths[i]) + strlen(names[i]) + 2;
    size_t size = sizeof(dr_exec_manifest_t) + count * sizeof(dr_exec_resource_record_t) +
        strings_size;
    byte *mapping = NULL;
    file_t manifest = INVALID_FILE;
    if (valid && size <= DR_EXEC_MANIFEST_LIMIT) {
        manifest = dynamorio_syscall(SYS_memfd_create, 2, "dr-exec-resources",
                                     MFD_CLOEXEC | MFD_ALLOW_SEALING);
        valid = manifest >= 0 && dynamorio_syscall(SYS_ftruncate, 2, manifest, size) == 0;
        if (valid) {
            mapping =
                os_map_file(manifest, &size, 0, NULL, MEMPROT_READ | MEMPROT_WRITE, 0);
            valid = mapping != NULL;
        }
    } else
        valid = false;
    if (valid) {
        memset(mapping, 0, size);
        dr_exec_manifest_t *header = (void *)mapping;
        header->magic = DR_EXEC_RESOURCE_MAGIC;
        header->version = DR_EXEC_RESOURCE_VERSION;
        header->resource_count = count;
        header->total_size = size;
        header->records_offset = sizeof(*header);
        header->strings_offset =
            sizeof(*header) + count * sizeof(dr_exec_resource_record_t);
        dr_exec_resource_record_t *records = (void *)(mapping + header->records_offset);
        size_t offset = header->strings_offset;
        for (uint i = 0; i < count; ++i) {
            records[i].role = roles[i];
            records[i].path_offset = offset;
            records[i].path_size = strlen(paths[i]) + 1;
            memcpy(mapping + offset, paths[i], records[i].path_size);
            offset += records[i].path_size;
            records[i].soname_offset = offset;
            records[i].soname_size = strlen(names[i]) + 1;
            memcpy(mapping + offset, names[i], records[i].soname_size);
            offset += records[i].soname_size;
            if (!resource_identity(files[i + 1], &records[i])) {
                valid = false;
                break;
            }
        }
        os_unmap_file(mapping, size);
    }
    if (valid)
        valid = dynamorio_syscall(SYS_fcntl, 3, manifest, F_ADD_SEALS,
                                  F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                                      F_SEAL_SEAL) == 0;
    if (valid) {
        files[0] = manifest;
        dr_exec_resource_request_t request = { DR_EXEC_RESOURCE_MAGIC,
                                               DR_EXEC_RESOURCE_VERSION,
                                               DR_EXEC_RESOURCE_REGISTER,
                                               nonce,
                                               count,
                                               0,
                                               size };
        dr_exec_resource_reply_t reply;
        file_t received[DR_EXEC_RESOURCE_LIMIT + 1];
        uint received_count;
        valid = exchange(&request, files, count + 1, &reply, received, &received_count) &&
            received_count == 0;
        for (uint i = 0; i < received_count; ++i)
            os_close(received[i]);
    }
    if (manifest != INVALID_FILE)
        os_close(manifest);
    release_recursive_lock(&privload_lock);
    return valid;
}
#endif
