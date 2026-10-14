/* Linux x86-64 internal-suspend relay wire format. Records contain no runtime
 * pointers and use the native byte order of the same-ISA tracing family. */
#ifndef DR_THREAD_SUSPEND_H
#define DR_THREAD_SUSPEND_H

#include <stdint.h>

#define DR_THREAD_SUSPEND_MAGIC UINT64_C(0x3150535553524444)
#define DR_THREAD_SUSPEND_VERSION 1
#define DR_THREAD_SUSPEND_PAYLOAD_SIZE 128
#define DR_THREAD_SUSPEND_REGISTER_FILES 3
/* Linux x86-64 SI_QUEUE si_value holds the notification ticket. The registered
 * template is zero here; the broker supplies a nonzero, non-UINT64_MAX ticket. */
#define DR_THREAD_SUSPEND_TICKET_OFFSET 24
/* Linux rewrites SI_QUEUE si_pid/si_uid across namespaces: neither can carry a
 * marker. The nudge's lower 28 action bits reside in the preserved si_errno. */
#define DR_THREAD_SUSPEND_MARKER UINT32_C(0x03535244)
#define DR_THREAD_SUSPEND_ERRNO UINT32_C(0x93535244)

enum {
    DR_THREAD_SUSPEND_REGISTER = 1,
    DR_THREAD_SUSPEND_SEND = 2,
    DR_THREAD_SUSPEND_RELEASE = 3,
    DR_THREAD_SUSPEND_QUIESCE = 4,
    DR_THREAD_SUSPEND_RESUME = 5,
};

enum {
    DR_THREAD_SUSPEND_OK = 0,
    DR_THREAD_SUSPEND_INVALID = 1,
    DR_THREAD_SUSPEND_UNAVAILABLE = 2,
    DR_THREAD_SUSPEND_DEAD = 3,
    DR_THREAD_SUSPEND_UNAUTHORIZED = 4,
    DR_THREAD_SUSPEND_TRANSPORT = 5,
};

/* REGISTER is sent on the inherited service endpoint with exactly three
 * SCM_RIGHTS descriptors: a new private reply/channel peer, then the caller's
 * PIDFD_THREAD descriptor, then a zero-valued non-semaphore eventfd for ACKs.
 * realm==0 creates a new address-space realm; otherwise
 * the caller joins that realm. task is zero. The remaining identity and payload
 * fields are required only for REGISTER. signal_number and the entire fixed
 * kernel_siginfo payload must match the internal-suspend template for the realm.
 * The template has nudge_action_mask=DR_THREAD_SUSPEND_MARKER, client_arg=0 and
 * si_value=0. Receivers ignore namespace-rewritten si_pid/si_uid. Each actual
 * notification carries a service-lifetime unique ticket in si_value. Tickets
 * never equal zero or UINT64_MAX. The receiving handler writes that ticket once
 * to its eventfd; there is no ACK socket command or response. The broker compares
 * the read ticket exactly and permits only one unacknowledged notification per
 * target. SEND coalesces with an outstanding notification after first checking
 * for an already-written ACK, including one absent from an earlier poll snapshot.
 *
 * SEND, RELEASE, QUIESCE and RESUME use the caller's already registered private
 * channel without SCM_RIGHTS. realm/task name the authorized target registration;
 * other identity and payload fields are zero. SEND is thread-directed (the broker
 * uses PIDFD_SIGNAL_THREAD), never a process-group signal. The other operations
 * apply only to the calling channel's own task. RELEASE permanently rejects new
 * sends, waits for the outstanding notification ACK before replying, then closes
 * the broker's pidfd. It is idempotent for that exact handle. QUIESCE temporarily
 * rejects sends with UNAVAILABLE/EBUSY and uses the same ACK barrier while keeping
 * the pidfd/channel. RESUME is permitted only after that barrier completes and
 * cannot undo RELEASE. This lets a failed exec restore the existing registration.
 *
 * A newer QUIESCE or RELEASE sequence may replace the same owner's unfinished
 * barrier reply. A client that timed out discards older valid replies while
 * reconciling the newest barrier. It must observe completion before RESUME or
 * before removing its signal handler; a timeout is not permission to do either.
 *
 * Handles and nonzero sequences are not recycled during the service lifetime.
 * A kernel delivery acknowledgement is not a DR suspension acknowledgement. */
typedef struct {
    uint64_t magic;
    uint32_t version, operation;
    uint64_t sequence;
    uint64_t realm, task;
    uint64_t runtime_id, runtime_group;
    uint32_t signal_number, payload_size;
    unsigned char suspend_payload[DR_THREAD_SUSPEND_PAYLOAD_SIZE];
} dr_thread_suspend_request_t;

/* No descriptors accompany replies. system_error is a nonnegative errno only
 * on failure; reserved is zero. Successful REGISTER returns new nonzero realm
 * and task handles. Every other reply echoes the request's realm and task. */
typedef struct {
    uint64_t magic;
    uint32_t version, status;
    uint64_t sequence, realm, task;
    int32_t system_error;
    uint32_t reserved;
} dr_thread_suspend_reply_t;

#endif /* DR_THREAD_SUSPEND_H */
