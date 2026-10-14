/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _FRAGMENT_SHARED_H_
#define _FRAGMENT_SHARED_H_

#include "lib/instrument.h"

bool
fragment_shared_candidate(dcontext_t *dcontext, instrlist_t *ilist, uint flags);

void
fragment_shared_add_entry(dcontext_t *dcontext, instrlist_t *ilist);

void
fragment_shared_publish(dcontext_t *dcontext, fragment_t *fragment, instrlist_t *ilist);

void
fragment_shared_free(dcontext_t *dcontext, fragment_t *fragment);

uint
fragment_shared_recipe_id(dcontext_t *dcontext, app_pc tag);

/* Caller owns the shared linking lock and a stable published table entry. */
bool
fragment_shared_snapshot(dcontext_t *dcontext, fragment_t *fragment,
                         dr_shared_fragment_snapshot_t *snapshot);

/* Caller holds a complete world stop and has excluded every old execution or
 * restoration continuation. This routine acquires the linking/allocator locks
 * in their normal order. Failure leaves the prepared fragment intact. */
bool
fragment_shared_rebind(dcontext_t *dcontext, fragment_t *fragment, uint recipe_id,
                       bool *retry);

cache_pc
fragment_shared_original_pc(fragment_t *fragment, cache_pc pc);

cache_pc
fragment_shared_original_end(fragment_t *fragment);

/* Inter-process backing is separate from FRAG_SHARED (thread sharing). The
 * provider table and every live view remain private to this process image.
 */
bool
fragment_shared_provider_enabled(void);

/* A compact provider needs address-independent clean-callee instruction widths. */
bool
fragment_shared_compact_enabled(void);

dr_shared_fragment_status_t
fragment_shared_request(dcontext_t *dcontext, const dr_shared_fragment_request_t *request,
                        dr_shared_fragment_file_t *file);

void
fragment_shared_file_finished(dcontext_t *dcontext, void *token, bool adopted);

void
fragment_shared_retired(dcontext_t *dcontext, void *token);

#endif /* _FRAGMENT_SHARED_H_ */
