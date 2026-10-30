/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef USERSPACE_STATS_H
#define USERSPACE_STATS_H

#include "globals.h"
#include "lib/dr_userspace_stats.h"

typedef struct _userspace_stats_t {
    dr_userspace_transition_counts_t counts;
    volatile int writing;
} userspace_stats_t;

enum {
    USERSPACE_STATS_REQUEST,
    USERSPACE_STATS_REJECT,
    USERSPACE_STATS_QUEUE,
    USERSPACE_STATS_CANCEL,
    USERSPACE_STATS_GATE,
    USERSPACE_STATS_PROBE,
    USERSPACE_STATS_PROBE_FALLBACK,
    USERSPACE_STATS_SIGNAL_BEGIN,
    USERSPACE_STATS_SIGNAL_END,
    USERSPACE_STATS_SIGNAL_REENTRY,
    USERSPACE_STATS_TAKEOVER,
};

void
userspace_stats_event(dcontext_t *dcontext, uint event, uint route);

#endif /* USERSPACE_STATS_H */
