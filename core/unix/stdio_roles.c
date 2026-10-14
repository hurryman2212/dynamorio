/* Private libc shares its FILE objects across CLONE_VM descriptor domains.
 * Keep their descriptor numbers immutable and rebind only the current table's
 * real aliases. An initially closed stream uses a protected O_PATH sentinel:
 * read/write/seek/tty operations fail with EBADF, while internal fstat can see
 * the inert sentinel's metadata. Application descriptors 0/1/2 are unchanged. */
#include <unistd.h>

#include "../globals.h"
#include "../utils.h"
#include "os_private.h"
#include "module.h"
#include "include/syscall.h"
#include "stdio_roles.h"

/* Written only during single-thread initialization and final teardown. */
static file_t stdio_aliases[3] = { INVALID_FILE, INVALID_FILE, INVALID_FILE };
static uint stdio_enabled;

void
os_stdio_private_loaded(void)
{
#ifdef STDFILE_FILENO
    stdfile_t **streams[3] = { privmod_stdin, privmod_stdout, privmod_stderr };
    for (uint index = 0; index < 3; ++index) {
        if (TESTANY(1u << index, stdio_enabled) && streams[index] != NULL &&
            *streams[index] != NULL)
            (*streams[index])->STDFILE_FILENO = stdio_aliases[index];
    }
#else
    /* Preserve the existing unsupported-libc diagnostic rather than assuming
     * a foreign FILE layout. Core/client dr_* I/O still uses protected aliases. */
    if (stdio_enabled != 0)
        SYSLOG_INTERNAL_WARNING_ONCE(
            "DynamoRIO cannot bind private libc standard FILEs on this platform");
#endif
}

bool
os_stdio_init(void)
{
    uint enabled = (DYNAMO_OPTION(dup_stdin_on_close) ? 1u : 0u) |
        (DYNAMO_OPTION(dup_stdout_on_close) ? 2u : 0u) |
        (DYNAMO_OPTION(dup_stderr_on_close) ? 4u : 0u);
    if (!os_stdio_open_aliases(stdio_aliases, enabled))
        return false;
    stdio_enabled = enabled;
    our_stdin = TESTANY(1u, enabled) ? stdio_aliases[0] : STDIN_FILENO;
    our_stdout = TESTANY(2u, enabled) ? stdio_aliases[1] : STDOUT_FILENO;
    our_stderr = TESTANY(4u, enabled) ? stdio_aliases[2] : STDERR_FILENO;
    os_stdio_private_loaded();
    return true;
}

void
os_stdio_exit(void)
{
    /* Private-library fini/flush and unload precede OS teardown. Their FILE
     * addresses are no longer valid and must not be rewritten here. */
    for (uint index = 0; index < 3; ++index) {
        if (stdio_aliases[index] != INVALID_FILE)
            os_close_protected(stdio_aliases[index]);
        stdio_aliases[index] = INVALID_FILE;
    }
    our_stdin = STDIN_FILENO;
    our_stdout = STDOUT_FILENO;
    our_stderr = STDERR_FILENO;
    stdio_enabled = 0;
}

void
os_stdio_refresh(void)
{
    const uint following = os_stdio_following() & stdio_enabled;
    for (uint index = 0; index < 3; ++index) {
        if (TESTANY(1u << index, following) &&
            !os_stdio_refresh_alias((file_t)index, stdio_aliases[index]))
            SYSLOG_INTERNAL_WARNING_ONCE("DynamoRIO could not refresh a private standard "
                                         "stream after native execution");
    }
}

void
os_stdio_fd_replaced(file_t fd)
{
    if (fd >= 0 && fd <= 2 && TESTANY(1u << fd, stdio_enabled) &&
        TESTANY(1u << fd, os_stdio_following()))
        os_stdio_bind_alias(fd, stdio_aliases[fd]);
}

void
os_stdio_fd_closing(file_t fd)
{
    if (fd >= 0 && fd <= 2 && TESTANY(1u << fd, stdio_enabled) &&
        TESTANY(1u << fd, os_stdio_following()) &&
        os_stdio_bind_alias(fd, stdio_aliases[fd]))
        os_stdio_stop_following((uint)fd);
}

bool
os_stdio_tracks_syscall(int sysnum)
{
    /* A copied domain can retain a pending stream, and dr_app_start can discover
     * newly closed streams. Shared BB filtering must not depend on the caller's
     * current pending bits. Bound streams incur no post-syscall descriptor work. */
    if (stdio_enabled == 0)
        return false;
    switch (sysnum) {
#ifdef SYS_open
    case SYS_open:
#endif
#ifdef SYS_openat
    case SYS_openat:
#endif
#ifdef SYS_openat2
    case SYS_openat2:
#endif
#ifdef SYS_creat
    case SYS_creat:
#endif
#ifdef SYS_dup
    case SYS_dup:
#endif
#ifdef SYS_dup2
    case SYS_dup2:
#endif
#ifdef SYS_dup3
    case SYS_dup3:
#endif
#ifdef SYS_fcntl
    case SYS_fcntl:
#endif
#ifdef SYS_pipe
    case SYS_pipe:
#endif
#ifdef SYS_pipe2
    case SYS_pipe2:
#endif
#ifdef SYS_socket
    case SYS_socket:
#endif
#ifdef SYS_socketpair
    case SYS_socketpair:
#endif
#ifdef SYS_accept
    case SYS_accept:
#endif
#ifdef SYS_accept4
    case SYS_accept4:
#endif
#ifdef SYS_recvmsg
    case SYS_recvmsg:
#endif
#ifdef SYS_recvmmsg
    case SYS_recvmmsg:
#endif
#ifdef SYS_eventfd
    case SYS_eventfd:
#endif
#ifdef SYS_eventfd2
    case SYS_eventfd2:
#endif
#ifdef SYS_epoll_create
    case SYS_epoll_create:
#endif
#ifdef SYS_epoll_create1
    case SYS_epoll_create1:
#endif
#ifdef SYS_inotify_init
    case SYS_inotify_init:
#endif
#ifdef SYS_inotify_init1
    case SYS_inotify_init1:
#endif
#ifdef SYS_signalfd
    case SYS_signalfd:
#endif
#ifdef SYS_signalfd4
    case SYS_signalfd4:
#endif
#ifdef SYS_timerfd_create
    case SYS_timerfd_create:
#endif
#ifdef SYS_memfd_create
    case SYS_memfd_create:
#endif
#ifdef SYS_userfaultfd
    case SYS_userfaultfd:
#endif
#ifdef SYS_pidfd_open
    case SYS_pidfd_open:
#endif
#ifdef SYS_pidfd_getfd
    case SYS_pidfd_getfd:
#endif
#ifdef SYS_perf_event_open
    case SYS_perf_event_open:
#endif
#ifdef SYS_fanotify_init
    case SYS_fanotify_init:
#endif
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup:
#endif
#ifdef SYS_io_uring_enter
    case SYS_io_uring_enter:
#endif
#ifdef SYS_fsopen
    case SYS_fsopen:
#endif
#ifdef SYS_fsmount
    case SYS_fsmount:
#endif
#ifdef SYS_open_tree
    case SYS_open_tree:
#endif
#ifdef SYS_landlock_create_ruleset
    case SYS_landlock_create_ruleset:
#endif
#ifdef SYS_bpf
    case SYS_bpf:
#endif
#ifdef SYS_seccomp
    case SYS_seccomp:
#endif
        return true;
    default: return false;
    }
}

void
os_stdio_post_syscall(dcontext_t *dcontext, int sysnum, bool success, reg_t result)
{
    (void)dcontext;
    (void)result;
    if (!success || !os_stdio_tracks_syscall(sysnum))
        return;
    const uint pending = os_stdio_pending();
    for (uint index = 0; index < 3; ++index)
        if (TESTANY(1u << index, pending))
            os_stdio_fd_replaced((file_t)index);
}
