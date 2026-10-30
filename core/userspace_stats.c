/* SPDX-License-Identifier: BSD-3-Clause */

#include "globals.h"
#include "userspace_stats.h"

#if defined(LINUX) && defined(X86) && defined(X64)
static void
userspace_stats_increment(dr_userspace_transition_counts_t *counts, uint64_t *value)
{
    if (*value == UINT64_MAX)
        __atomic_store_n(&counts->overflow, 1, __ATOMIC_RELAXED);
    else
        ++*value;
}
#endif

/* Never wait: a signal may interrupt the writer using this same dcontext.
 * An unexpected overlapping write makes the measurement explicitly incomplete. */
void
userspace_stats_event(dcontext_t *dcontext, uint event, uint route)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    if (!DYNAMO_OPTION(userspace_transition_stats) || dcontext == NULL ||
        dcontext == GLOBAL_DCONTEXT)
        return;
    userspace_stats_t *state =
        __atomic_load_n(&dcontext->client_userspace_stats, __ATOMIC_ACQUIRE);
    if (state == NULL)
        return;
    dr_userspace_transition_counts_t *counts = &state->counts;
    if (__atomic_exchange_n(&state->writing, 1, __ATOMIC_ACQUIRE) != 0) {
        __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        return;
    }
    uint active = (uint)counts->active_route;
    uint probe = (uint)counts->probe_route;
    switch (event) {
    case USERSPACE_STATS_REQUEST:
        userspace_stats_increment(counts, &counts->requests);
        break;
    case USERSPACE_STATS_REJECT:
        userspace_stats_increment(counts, &counts->rejected_requests);
        break;
    case USERSPACE_STATS_QUEUE:
        if (counts->pending_route != 0 || active != 0 || probe != 0 || route < 1 ||
            route > 2)
            __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        counts->pending_route = route;
        break;
    case USERSPACE_STATS_CANCEL:
        if (counts->pending_route != 0) {
            userspace_stats_increment(counts, &counts->cancelled_requests);
            counts->pending_route = 0;
        }
        break;
    case USERSPACE_STATS_GATE:
    case USERSPACE_STATS_SIGNAL_REENTRY:
    case USERSPACE_STATS_TAKEOVER:
        if (active >= 1 && active <= 2) {
            uint64_t *value = event == USERSPACE_STATS_GATE
                ? &counts->gate_exits[active - 1]
                : event == USERSPACE_STATS_TAKEOVER
                ? &counts->takeover_reentries[active - 1]
                : &counts->signal_reentries[active - 1];
            userspace_stats_increment(counts, value);
            counts->active_route = 0;
        } else if (event == USERSPACE_STATS_GATE)
            __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        break;
    case USERSPACE_STATS_PROBE:
        if (active >= 1 && active <= 2 && active == route && probe == 0) {
            userspace_stats_increment(counts, &counts->probe_entries[active - 1]);
            counts->probe_route = active;
            counts->active_route = 0;
        } else
            __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        break;
    case USERSPACE_STATS_PROBE_FALLBACK:
        if (probe >= 1 && probe <= 2) {
            userspace_stats_increment(counts, &counts->probe_fallbacks[probe - 1]);
            counts->probe_route = 0;
        } else
            __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        break;
    case USERSPACE_STATS_SIGNAL_BEGIN:
        if (active >= 1 && active <= 2) {
            userspace_stats_increment(counts, &counts->signal_interruptions[active - 1]);
            userspace_stats_increment(counts, &counts->signal_depth);
        } else
            __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        break;
    case USERSPACE_STATS_SIGNAL_END:
        if (counts->signal_depth != 0) {
            --counts->signal_depth;
            if (active >= 1 && active <= 2)
                userspace_stats_increment(counts, &counts->signal_resumes[active - 1]);
        } else
            __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED);
        break;
    default: __atomic_store_n(&counts->incomplete, 1, __ATOMIC_RELAXED); break;
    }
    __atomic_store_n(&state->writing, 0, __ATOMIC_RELEASE);
#endif
}

DR_API
bool
dr_get_userspace_transition_stats(void *drcontext,
                                  dr_userspace_transition_stats_t *result)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    dcontext_t *dcontext = (dcontext_t *)drcontext;
    if (!DYNAMO_OPTION(userspace_transition_stats) || result == NULL ||
        result->struct_size != sizeof(*result) ||
        memcmp(result->contract, DR_USERSPACE_TRANSITION_CONTRACT_HASH,
               sizeof(result->contract)) != 0 ||
        dcontext == NULL || dcontext == GLOBAL_DCONTEXT ||
        dcontext != get_thread_private_dcontext())
        return false;
    userspace_stats_t *state =
        __atomic_load_n(&dcontext->client_userspace_stats, __ATOMIC_ACQUIRE);
    if (state == NULL)
        return false;
    if (__atomic_exchange_n(&state->writing, 1, __ATOMIC_ACQUIRE) != 0)
        return false;
    result->counts = state->counts;
    /* A nested writer records a loss even while this snapshot owns the lock. */
    result->counts.incomplete =
        __atomic_load_n(&state->counts.incomplete, __ATOMIC_RELAXED);
    __atomic_store_n(&state->writing, 0, __ATOMIC_RELEASE);
    return true;
#else
    return false;
#endif
}
