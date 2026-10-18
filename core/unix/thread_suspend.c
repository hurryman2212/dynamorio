/* The suspension path cannot enter client code, allocate, or acquire an FD-table
 * lock: its target may own those locks. Registration prepares all resources. */
#include <errno.h> /* IWYU pragma: keep: GCC uses these constants directly. */
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include "../globals.h"
#include "../utils.h"
#include "os_private.h"
#include "include/syscall.h" /* IWYU pragma: keep: GCC requires raw SYS_* definitions. */
#include "thread_suspend.h"

/* Bound a dead or wedged broker independently of the target's suspend ACK. */
static const int exchange_timeout_ms = 5000;

/* Written during serialized runtime initialization and ordinary fork. */
static file_t suspend_service = INVALID_FILE;
static uint64 suspend_realm;
static uint64 suspend_generation = 1;

static int64
suspend_clock_ms(void)
{
    struct timespec now;
    if (dynamorio_syscall(SYS_clock_gettime, 2, CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_sec > (INT64_MAX - 999) / 1000)
        return -1;
    return (int64)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool
suspend_wait(file_t fd, short events, int64 deadline)
{
    struct pollfd polling = { fd, events, 0 };
    for (;;) {
        int64 now = suspend_clock_ms();
        if (now < 0 || now >= deadline)
            return false;
        ptr_int_t result =
            dynamorio_syscall(SYS_poll, 3, &polling, 1, (int)(deadline - now));
        if (result == -EINTR)
            continue;
        return result == 1 && (polling.revents & events) != 0 &&
            (polling.revents & (POLLERR | POLLNVAL)) == 0;
    }
}

/* Registration alone supplies descriptors. Every response has no ancillary
 * data; MSG_CTRUNC rejects unexpected rights, which Linux closes when omitted. */
static bool
suspend_exchange(file_t destination, file_t channel,
                 const dr_thread_suspend_request_t *request, const file_t *files,
                 dr_thread_suspend_reply_t *reply, bool *submitted, bool drain)
{
    if (submitted != NULL)
        *submitted = false;
    int64 now = suspend_clock_ms();
    if (now < 0 || now > INT64_MAX - exchange_timeout_ms)
        return false;
    int64 deadline = now + exchange_timeout_ms;
    struct iovec payload = { (void *)request, sizeof(*request) };
    struct msghdr message = { 0 };
    union {
        struct cmsghdr alignment;
        byte data[CMSG_SPACE(DR_THREAD_SUSPEND_REGISTER_FILES * sizeof(file_t))];
    } control;
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    if (files != NULL) {
        memset(&control, 0, sizeof(control));
        message.msg_control = control.data;
        message.msg_controllen = sizeof(control.data);
        struct cmsghdr *rights = CMSG_FIRSTHDR(&message);
        rights->cmsg_level = SOL_SOCKET;
        rights->cmsg_type = SCM_RIGHTS;
        rights->cmsg_len = CMSG_LEN(DR_THREAD_SUSPEND_REGISTER_FILES * sizeof(file_t));
        memcpy(CMSG_DATA(rights), files,
               DR_THREAD_SUSPEND_REGISTER_FILES * sizeof(file_t));
    }
    for (;;) {
        ptr_int_t result = dynamorio_syscall(SYS_sendmsg, 3, destination, &message,
                                             MSG_DONTWAIT | MSG_NOSIGNAL);
        if (result == sizeof(*request)) {
            if (submitted != NULL)
                *submitted = true;
            break;
        }
        if (result != -EINTR && result != -EAGAIN)
            return false;
        if (!suspend_wait(destination, POLLOUT, deadline))
            return false;
    }
    memset(&message, 0, sizeof(message));
    payload.iov_base = reply;
    payload.iov_len = sizeof(*reply);
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    for (;;) {
        ptr_int_t result =
            dynamorio_syscall(SYS_recvmsg, 3, channel, &message, MSG_DONTWAIT);
        if (result == sizeof(*reply)) {
            bool valid = !TESTANY(MSG_TRUNC | MSG_CTRUNC, message.msg_flags) &&
                reply->magic == DR_THREAD_SUSPEND_MAGIC &&
                memcmp(reply->contract, DR_THREAD_SUSPEND_CONTRACT_HASH,
                       sizeof(reply->contract)) == 0 &&
                reply->sequence != 0 && reply->reserved == 0 &&
                reply->status <= DR_THREAD_SUSPEND_UNKNOWN && reply->system_error >= 0 &&
                ((reply->status != DR_THREAD_SUSPEND_OK &&
                  reply->status < DR_THREAD_SUSPEND_LIVE) ||
                 reply->system_error == 0);
            if (!valid)
                return false;
            if (drain && reply->sequence < request->sequence) {
                int64 current = suspend_clock_ms();
                if (current < 0 || current >= deadline)
                    return false;
                continue; /* A reply from the earlier timed-out command. */
            }
            return reply->sequence == request->sequence &&
                (request->operation == DR_THREAD_SUSPEND_REGISTER ||
                 (reply->realm == request->realm && reply->task == request->task));
        }
        if (result != -EINTR && result != -EAGAIN)
            return false;
        if (!suspend_wait(channel, POLLIN, deadline))
            return false;
    }
}

bool
os_thread_suspend_set_service(file_t broker)
{
    int type;
    socklen_t size = sizeof(type);
    dcontext_t *dcontext = get_thread_private_dcontext();
    ptr_int_t flags = dynamorio_syscall(SYS_fcntl, 3, broker, F_GETFD, 0);
    if (broker < 0 || dcontext == NULL || dcontext == GLOBAL_DCONTEXT || flags < 0 ||
        TESTANY(FD_CLOEXEC, flags) ||
        (suspend_service != INVALID_FILE && suspend_service != broker) ||
        dynamorio_syscall(SYS_getsockopt, 5, broker, SOL_SOCKET, SO_TYPE, &type, &size) !=
            0 ||
        size != sizeof(type) || type != SOCK_SEQPACKET)
        return false;
    suspend_service = broker;
    bool ready = os_thread_suspend_register(dcontext);
    /* Optional service failure must not make every subsequent ordinary thread
     * repeat an unsupported registration or wait for a dead broker. Existing
     * registered peers, if any, retain their service and realm. */
    if (!ready && suspend_realm == 0)
        suspend_service = INVALID_FILE;
    return ready;
}

bool
os_thread_suspend_register(dcontext_t *dcontext)
{
    if (suspend_service == INVALID_FILE || dcontext == NULL ||
        dcontext->owning_runtime_id != get_runtime_thread_id() ||
        dcontext->os_field == NULL || suspend_generation == 0)
        return false;
    os_thread_data_t *ostd = dcontext->os_field;
    thread_suspend_channel_t *state = &ostd->suspend_channel;
    if (state->generation == suspend_generation && state->ready)
        return true;
    /* A fork child has already closed inherited CLOSE_ON_FORK descriptors.
     * Never send RELEASE for its parent's registration or close a stale number. */
    if (state->generation == suspend_generation && state->channel_owned &&
        !os_thread_suspend_release(dcontext, false))
        return false;
    memset(state, 0, sizeof(*state));
    state->channel = INVALID_FILE;
    state->acknowledgment = INVALID_FILE;
    state->generation = suspend_generation;
    state->filetable_id = os_file_table_identity(dcontext);
    if (state->filetable_id == 0)
        return false;
    file_t sockets[2], pidfd, ackfd;
    if (!os_thread_suspend_open_resources(sockets, &pidfd, &ackfd))
        return false;
    dr_thread_suspend_request_t request = { 0 };
    dr_thread_suspend_reply_t reply;
    request.magic = DR_THREAD_SUSPEND_MAGIC;
    memcpy(request.contract, DR_THREAD_SUSPEND_CONTRACT_HASH, sizeof(request.contract));
    request.operation = DR_THREAD_SUSPEND_REGISTER;
    request.sequence = ++state->sequence;
    request.realm = suspend_realm;
    request.runtime_id = get_runtime_thread_id();
    request.runtime_group = get_runtime_thread_group();
    request.signal_number = SUSPEND_SIGNAL;
    kernel_siginfo_t info;
    ASSERT(sizeof(info) == sizeof(request.suspend_payload));
    bool valid = create_nudge_signal_payload(&info, DR_THREAD_SUSPEND_MARKER,
                                             NUDGE_IS_SUSPEND, 0, 0);
    if (valid) {
        /* pidfd_send_signal requires this field to match its signal argument.
         * The remaining nudge payload, including its overlaid fields, is exact. */
        info.si_signo = SUSPEND_SIGNAL;
        memcpy(request.suspend_payload, &info, sizeof(info));
        request.payload_size = sizeof(info);
        file_t files[DR_THREAD_SUSPEND_REGISTER_FILES] = { sockets[1], pidfd, ackfd };
        valid = suspend_exchange(suspend_service, sockets[0], &request, files, &reply,
                                 NULL, false) &&
            reply.status == DR_THREAD_SUSPEND_OK && reply.realm != 0 && reply.task != 0 &&
            (suspend_realm == 0 || reply.realm == suspend_realm);
    }
    os_close_protected(sockets[1]);
    os_close_protected(pidfd);
    if (!valid) {
        os_close_protected(sockets[0]);
        os_close_protected(ackfd);
        return false;
    }
    suspend_realm = reply.realm;
    state->channel = sockets[0];
    state->acknowledgment = ackfd;
    state->channel_owned = true;
    state->realm = reply.realm;
    state->task = reply.task;
    state->ready = true;
    return true;
}

thread_suspend_result_t
os_thread_suspend_relay(thread_record_t *target, int signum)
{
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (signum != SUSPEND_SIGNAL || dcontext == NULL || dcontext == GLOBAL_DCONTEXT ||
        dcontext->os_field == NULL || target == NULL || target->dcontext == NULL ||
        target->dcontext->os_field == NULL)
        return THREAD_SUSPEND_NOT_SENT;
    thread_suspend_channel_t *caller =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    const thread_suspend_channel_t *peer =
        &((os_thread_data_t *)target->dcontext->os_field)->suspend_channel;
    if (!caller->ready || !peer->ready || caller->generation != suspend_generation ||
        peer->generation != suspend_generation || caller->realm != peer->realm ||
        caller->sequence == UINT64_MAX ||
        !atomic_compare_exchange_int(&caller->busy, 0, 1))
        return THREAD_SUSPEND_NOT_SENT;
    dr_thread_suspend_request_t request = { 0 };
    dr_thread_suspend_reply_t reply;
    request.magic = DR_THREAD_SUSPEND_MAGIC;
    memcpy(request.contract, DR_THREAD_SUSPEND_CONTRACT_HASH, sizeof(request.contract));
    request.operation = DR_THREAD_SUSPEND_SEND;
    request.sequence = ++caller->sequence;
    request.realm = peer->realm;
    request.task = peer->task;
    bool submitted;
    bool valid = suspend_exchange(caller->channel, caller->channel, &request, NULL,
                                  &reply, &submitted, false);
    /* A late response after timeout must never satisfy a future request. Keep
     * the FD until normal cleanup: closing it here would acquire an FD lock. */
    if (!valid)
        caller->ready = false;
    atomic_compare_exchange_int(&caller->busy, 1, 0);
    if (!valid)
        return submitted ? THREAD_SUSPEND_UNKNOWN : THREAD_SUSPEND_NOT_SENT;
    return reply.status == DR_THREAD_SUSPEND_OK ? THREAD_SUSPEND_DELIVERED
                                                : THREAD_SUSPEND_REJECTED;
}

bool
os_thread_suspend_acknowledge(dcontext_t *dcontext, uint64 ticket)
{
    if (ticket == 0 || ticket == UINT64_MAX || dcontext == NULL ||
        dcontext == GLOBAL_DCONTEXT || dcontext->os_field == NULL)
        return false;
    thread_suspend_channel_t *state =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    if (!state->channel_owned || state->generation != suspend_generation)
        return false;
    uint64 observed = __atomic_load_n(&state->acknowledged_ticket, __ATOMIC_ACQUIRE);
    for (;;) {
        if (ticket < observed)
            return true; /* An old duplicate cannot acknowledge a newer ticket. */
        if (ticket == observed) {
            uint64 pending = ticket;
            if (!__atomic_compare_exchange_n(&state->pending_ticket, &pending, 0, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return true;
            break; /* Retry a write that was not accepted by the kernel. */
        }
        if (__atomic_compare_exchange_n(&state->acknowledged_ticket, &observed, ticket,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    /* The broker never emits another notification until it reads this ticket.
     * Thus a valid eventfd is empty here and accepts the entire eight-byte write.
     * Publish ownership before writing so a nested newer notification cannot
     * cause the outer handler to overwrite its acknowledgement state. */
    if (dynamorio_syscall(SYS_write, 3, state->acknowledgment, &ticket, sizeof(ticket)) ==
        sizeof(ticket))
        return true;
    __atomic_store_n(&state->pending_ticket, ticket, __ATOMIC_RELEASE);
    state->ready = false; /* Future callers must not wait on a coalesced old request. */
    return false;
}

static bool
suspend_control(dcontext_t *dcontext, uint operation)
{
    thread_suspend_channel_t *state =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    uint64 pending = __atomic_load_n(&state->pending_ticket, __ATOMIC_ACQUIRE);
    if ((pending != 0 && !os_thread_suspend_acknowledge(dcontext, pending)) ||
        state->sequence == UINT64_MAX || !atomic_compare_exchange_int(&state->busy, 0, 1))
        return false;
    state->ready = false;
    dr_thread_suspend_request_t request = { 0 };
    dr_thread_suspend_reply_t reply;
    request.magic = DR_THREAD_SUSPEND_MAGIC;
    memcpy(request.contract, DR_THREAD_SUSPEND_CONTRACT_HASH, sizeof(request.contract));
    request.operation = operation;
    request.sequence = ++state->sequence;
    request.realm = state->realm;
    request.task = state->task;
    bool complete = suspend_exchange(state->channel, state->channel, &request, NULL,
                                     &reply, NULL, true) &&
        reply.status == DR_THREAD_SUSPEND_OK;
    atomic_compare_exchange_int(&state->busy, 1, 0);
    if (complete && operation == DR_THREAD_SUSPEND_RESUME)
        state->ready = true;
    return complete;
}

bool
os_thread_suspend_quiesce_for_exec(dcontext_t *dcontext)
{
    if (dcontext == NULL || dcontext == GLOBAL_DCONTEXT || dcontext->os_field == NULL)
        return false;
    thread_suspend_channel_t *state =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    if (!state->channel_owned || state->generation != suspend_generation)
        return true;
    if (dcontext->owning_runtime_id != get_runtime_thread_id())
        return false;
    state->exec_quiesce_attempted = true;
    return suspend_control(dcontext, DR_THREAD_SUSPEND_QUIESCE);
}

bool
os_thread_suspend_restore_after_exec(dcontext_t *dcontext)
{
    if (dcontext == NULL || dcontext == GLOBAL_DCONTEXT || dcontext->os_field == NULL)
        return false;
    thread_suspend_channel_t *state =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    if (!state->exec_quiesce_attempted || !state->channel_owned ||
        state->generation != suspend_generation)
        return true;
    if (dcontext->owning_runtime_id != get_runtime_thread_id())
        return false;
    /* A timeout is not proof that QUIESCE failed. Repeat the same barrier with
     * a fresh command sequence and discard only older replies before RESUME. */
    if (!suspend_control(dcontext, DR_THREAD_SUSPEND_QUIESCE) ||
        !suspend_control(dcontext, DR_THREAD_SUSPEND_RESUME))
        return false;
    state->exec_quiesce_attempted = false;
    return true;
}

/* The caller owns the exchange channel. The peer's numeric fd and readiness
 * are irrelevant, including after a successful exec in another CLONE_VM group. */
static uint
suspend_peer_control(dcontext_t *target, uint operation)
{
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (dcontext == NULL || dcontext == GLOBAL_DCONTEXT || dcontext->os_field == NULL ||
        target == NULL || target->os_field == NULL)
        return DR_THREAD_SUSPEND_UNKNOWN;
    thread_suspend_channel_t *caller =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    const thread_suspend_channel_t *peer =
        &((os_thread_data_t *)target->os_field)->suspend_channel;
    if (!caller->channel_owned || caller->generation != suspend_generation ||
        peer->generation != suspend_generation || caller->realm != peer->realm ||
        peer->task == 0 || caller->sequence == UINT64_MAX ||
        !atomic_compare_exchange_int(&caller->busy, 0, 1))
        return DR_THREAD_SUSPEND_UNKNOWN;
    dr_thread_suspend_request_t request = { 0 };
    dr_thread_suspend_reply_t reply;
    request.magic = DR_THREAD_SUSPEND_MAGIC;
    memcpy(request.contract, DR_THREAD_SUSPEND_CONTRACT_HASH, sizeof(request.contract));
    request.operation = operation;
    request.sequence = ++caller->sequence;
    request.realm = peer->realm;
    request.task = peer->task;
    bool valid = suspend_exchange(caller->channel, caller->channel, &request, NULL,
                                  &reply, NULL, true);
    atomic_compare_exchange_int(&caller->busy, 1, 0);
    return valid ? reply.status : DR_THREAD_SUSPEND_UNKNOWN;
}

bool
os_thread_suspend_departed(thread_record_t *target)
{
    return target != NULL &&
        suspend_peer_control(target->dcontext, DR_THREAD_SUSPEND_STATUS) ==
        DR_THREAD_SUSPEND_DEPARTED;
}

bool
os_thread_suspend_release(dcontext_t *dcontext, bool other_thread)
{
    if (dcontext == NULL || dcontext->os_field == NULL)
        return true;
    thread_suspend_channel_t *state =
        &((os_thread_data_t *)dcontext->os_field)->suspend_channel;
    if (state->generation != suspend_generation || !state->channel_owned)
        return true;
    bool own_task =
        !other_thread && dcontext->owning_runtime_id == get_runtime_thread_id();
    /* Forget only when the runtime has established that this context can be
     * disposed of. This is resource retirement, never departure evidence. */
    if (other_thread)
        (void)suspend_peer_control(dcontext, DR_THREAD_SUSPEND_FORGET);
    /* A peer's FD is meaningful only in the same file table. Its pidfd death or
     * channel disconnect retires the registration in the broker. A live caller
     * that unshared its table retains its own copied descriptor. */
    if (!own_task && state->filetable_id != os_file_table_identity(NULL))
        return true;
    if (own_task) {
        if (!suspend_control(dcontext, DR_THREAD_SUSPEND_RELEASE))
            return false; /* Keep both descriptors until the retirement barrier. */
        (void)suspend_peer_control(dcontext, DR_THREAD_SUSPEND_FORGET);
    }
    state->ready = false;
    os_close_protected(state->channel);
    os_close_protected(state->acknowledgment);
    state->channel_owned = false;
    state->channel = INVALID_FILE;
    state->acknowledgment = INVALID_FILE;
    return true;
}

void
os_thread_suspend_fork_child(void)
{
    suspend_realm = 0;
    if (suspend_generation != 0)
        ++suspend_generation; /* Wrap permanently disables further registrations. */
}

void
os_thread_suspend_service_exit(void)
{
    /* The control descriptor is borrowed; its owner closes it after shutdown.
     * Reattach starts a new lifetime with no surviving channel/realm handles. */
    suspend_service = INVALID_FILE;
    suspend_realm = 0;
    suspend_generation = 1;
}
