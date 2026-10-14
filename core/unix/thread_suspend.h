/* A caller owns its channel. A target is addressed only by broker handles. */
#ifndef THREAD_SUSPEND_H
#define THREAD_SUSPEND_H

#include "../lib/dr_thread_suspend.h"

typedef struct {
    file_t channel;
    file_t acknowledgment;
    bool channel_owned;
    bool ready;
    bool exec_quiesce_attempted;
    volatile int busy;
    uint64 sequence;
    uint64 generation;
    uint64 filetable_id;
    uint64 realm;
    uint64 task;
    volatile uint64 acknowledged_ticket;
    volatile uint64 pending_ticket;
} thread_suspend_channel_t;

typedef enum {
    THREAD_SUSPEND_NOT_SENT,
    THREAD_SUSPEND_DELIVERED,
    THREAD_SUSPEND_REJECTED,
    THREAD_SUSPEND_UNKNOWN,
} thread_suspend_result_t;

/* Entry and cancellation race through the target's atomic notification gate. */
enum {
    THREAD_SUSPEND_IDLE,
    THREAD_SUSPEND_ARMED,
    THREAD_SUSPEND_ENTERED,
    THREAD_SUSPEND_CANCELLED,
};

/* Called only during normal thread initialization. The file-table transaction
 * creates and protects all four CLOEXEC/CLOSE_ON_FORK descriptors atomically. */
bool
os_thread_suspend_open_resources(file_t sockets[2], file_t *pidfd, file_t *ackfd);

bool
os_thread_suspend_set_service(file_t broker);
bool
os_thread_suspend_register(dcontext_t *dcontext);
thread_suspend_result_t
os_thread_suspend_relay(thread_record_t *target, int signum);
/* Async-signal-safe; writes at most one ticket to the task's precreated eventfd. */
bool
os_thread_suspend_acknowledge(dcontext_t *dcontext, uint64 ticket);
bool
os_thread_suspend_release(dcontext_t *dcontext, bool other_thread);
bool
os_thread_suspend_quiesce_for_exec(dcontext_t *dcontext);
bool
os_thread_suspend_restore_after_exec(dcontext_t *dcontext);
void
os_thread_suspend_fork_child(void);
/* Final runtime teardown only, after all registrations have been retired. */
void
os_thread_suspend_service_exit(void);

#endif /* THREAD_SUSPEND_H */
