/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef DR_USERSPACE_STATS_H
#define DR_USERSPACE_STATS_H

#include <stddef.h>
#include <stdint.h>

#include "dr_service_contract.h" /* IWYU pragma: export */

/* Array indices are prepared code and original-address code, respectively.
 * PREPARED requires a live original-PC mapping at the requested entry. ORIGINAL
 * denotes an unregistered entry; the redirect caller still owns its original-code
 * eligibility proof. State fields use NONE, PREPARED, or ORIGINAL, not indices. */
enum {
    DR_USERSPACE_ROUTE_NONE = 0,
    DR_USERSPACE_ROUTE_PREPARED = 1,
    DR_USERSPACE_ROUTE_ORIGINAL = 2,
};

typedef struct _dr_userspace_transition_counts_t {
    uint64_t requests, rejected_requests, cancelled_requests;
    uint64_t dispatch_entries[2], gate_exits[2];
    uint64_t probe_entries[2], probe_returns[2], probe_fallbacks[2];
    uint64_t signal_interruptions[2], signal_resumes[2], signal_reentries[2];
    uint64_t takeover_reentries[2];
    uint64_t pending_route, active_route, probe_route, signal_depth;
    uint64_t overflow, incomplete;
} dr_userspace_transition_counts_t;

typedef struct _dr_userspace_transition_stats_t {
    size_t struct_size;
    /* Initialize to DR_USERSPACE_TRANSITION_CONTRACT_HASH before querying. */
    char contract[65];
    dr_userspace_transition_counts_t counts;
} dr_userspace_transition_stats_t;

#endif /* DR_USERSPACE_STATS_H */
