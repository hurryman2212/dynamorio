/* SPDX-License-Identifier: BSD-3-Clause */

#include "globals.h"
#ifdef LINUX
#    include <sys/stat.h>
#    include <sys/syscall.h>
#endif
#include "fragment.h"
#include "fcache.h"
#include "heap.h"
#include "link.h"
#include "instr.h"
#include "instrlist.h"
#include "instr_create_shared.h"
#include "decode.h"
#include "fragment_shared.h"
#include "synch.h"

/* Registration happens before application threads run. Callback targets are
 * never part of an immutable shared-code object.
 */
static dr_shared_fragment_provider_t provider;

DR_API
bool
dr_register_shared_fragment_provider(const dr_shared_fragment_provider_t *callbacks)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    if (dynamo_initialized || provider.request != NULL || callbacks == NULL ||
        callbacks->struct_size != sizeof(*callbacks) || callbacks->request == NULL ||
        callbacks->file_finished == NULL || callbacks->retired == NULL)
        return false;
    provider = *callbacks;
    return true;
#else
    return false;
#endif
}

bool
fragment_shared_provider_enabled(void)
{
    return provider.request != NULL;
}

bool
fragment_shared_compact_enabled(void)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    return provider.request != NULL && provider.compact_private_bindings;
#else
    return false;
#endif
}

DR_API
bool
dr_delay_shared_fragment_promotion(app_pc tag, uint emission_id)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (tag == NULL || !fragment_shared_provider_enabled() ||
        !DYNAMO_OPTION(shared_bbs) || !DYNAMO_OPTION(disable_traces) ||
        DYNAMO_OPTION(coarse_units))
        return false;
    if (emission_id == 0 || fragment_shared_recipe_id(dcontext, tag) != emission_id)
        return false;
    client_flush_req_t *request =
        HEAP_TYPE_ALLOC(GLOBAL_DCONTEXT, client_flush_req_t, ACCT_CLIENT, UNPROTECTED);
    memset(request, 0, sizeof(*request));
    request->start = tag;
    request->flush_id = emission_id;
    /* Region flush APIs reject zero sizes; reserve that value for exact tags.
     * The dispatcher coalesces all pending promotions into one synchronization.
     */
    d_r_mutex_lock(&client_flush_request_lock);
    for (client_flush_req_t *pending = client_flush_requests; pending != NULL;
         pending = pending->next) {
        if (pending->size == 0 && pending->start == tag) {
            /* A stale lookup must not replace a newer queued incarnation. */
            if (pending->flush_id <= emission_id) {
                pending->flush_id = emission_id;
                pending->promotion_delay = 0;
            }
            d_r_mutex_unlock(&client_flush_request_lock);
            HEAP_TYPE_FREE(GLOBAL_DCONTEXT, request, client_flush_req_t, ACCT_CLIENT,
                           UNPROTECTED);
            return true;
        }
    }
    request->next = client_flush_requests;
    client_flush_requests = request;
    d_r_mutex_unlock(&client_flush_request_lock);
    return true;
#else
    return false;
#endif
}

dr_shared_fragment_status_t
fragment_shared_request(dcontext_t *dcontext, const dr_shared_fragment_request_t *request,
                        dr_shared_fragment_file_t *file)
{
    memset(file, 0, sizeof(*file));
    file->fd = INVALID_FILE;
    if (provider.request == NULL || request == NULL ||
        request->struct_size != sizeof(*request) || request->tag == NULL ||
        request->identity == NULL || request->identity_size == 0 ||
        request->code_size == 0 || !ALIGNED(request->code_size, PAGE_SIZE) ||
        request->content_size == 0 || request->content_size > request->code_size)
        return DR_SHARED_FRAGMENT_DECLINED;
    const dr_shared_fragment_status_t status = provider.request(dcontext, request, file);
    if (status != DR_SHARED_FRAGMENT_READY)
        return status == DR_SHARED_FRAGMENT_DEFER ? status : DR_SHARED_FRAGMENT_DECLINED;
    bool valid = file->fd != INVALID_FILE && ALIGNED(file->offset, PAGE_SIZE) &&
        file->member_offset <= file->size &&
        request->content_size <= file->size - file->member_offset;
    if (provider.compact_private_bindings) {
        valid = valid && file->size != 0 &&
            file->size <= DR_SHARED_FRAGMENT_BUNDLE_LIMIT &&
            ALIGNED(file->size, PAGE_SIZE) && ALIGNED(file->member_offset, 16) &&
            file->private_extent != 0 &&
            file->private_extent <= DR_SHARED_FRAGMENT_BUNDLE_LIMIT &&
            ALIGNED(file->private_extent, PAGE_SIZE) && file->private_instance != 0 &&
            ALIGNED(file->private_offset, 16) &&
            file->private_offset <= file->private_extent &&
            request->private_slot_size <= file->private_extent - file->private_offset;
    } else {
        valid = valid && file->size == request->code_size;
    }
    if (!valid) {
        provider.file_finished(dcontext, file->token, false);
        memset(file, 0, sizeof(*file));
        file->fd = INVALID_FILE;
        return DR_SHARED_FRAGMENT_DECLINED;
    }
    return DR_SHARED_FRAGMENT_READY;
}

void
fragment_shared_file_finished(dcontext_t *dcontext, void *token, bool adopted)
{
    ASSERT(provider.file_finished != NULL);
    provider.file_finished(dcontext, token, adopted);
}

void
fragment_shared_retired(dcontext_t *dcontext, void *token)
{
    ASSERT(provider.retired != NULL);
    provider.retired(dcontext, token);
}

/* These records are also the layout identity. All coordinates are relative;
 * neither callback arguments nor other process-local operands enter it.
 */
typedef struct {
    ushort original;
    ushort length;
    uint body;
    uint island;
    ushort target;
    byte body_length;
    byte kind;
} shared_instruction_t;

typedef struct {
    uint magic;
    uint schema;
    uint count;
    uint code_offset;
    uint code_size;
    uint island_size;
    uint original_size;
    uint reserved;
} shared_layout_t;

enum {
    SHARED_COPY,
    SHARED_PRIVATE,
    SHARED_BRANCH,
    SHARED_EXIT,
};

typedef struct _fragment_shared_arena_t {
    struct _fragment_shared_arena_t *next;
    byte *base;
    byte *private_base;
    size_t size;
    uint body_size;
    uint cell_size;
    uint cells;
    uint64 occupied;
} fragment_shared_arena_t;

static fragment_shared_arena_t *shared_arenas;

typedef struct _fragment_shared_batch_t {
    struct _fragment_shared_batch_t *next;
    byte *base;
    uint64 device;
    uint64 inode;
    uint64 file_offset;
    uint body_size;
    uint private_size;
    uint bitmap_words;
    bool compact_bindings;
    size_t private_instance;
    uint64 occupied[]; /* Separate RX and binding intervals, in 16-byte units. */
} fragment_shared_batch_t;

static fragment_shared_batch_t *shared_batches;

typedef struct _fragment_shared_view_t {
    byte *mapping;
    size_t body_size;
    byte *private_start;
    size_t private_size;
    uint count;
    uint exit_count;
    bool compact_frame;
    const shared_instruction_t *instructions;
    void *registration;
    void *private_registration;
    void *token;
    fragment_shared_arena_t *arena;
    fragment_shared_batch_t *batch;
    uint cell;
    uint span;
    uint member_span;
    uint private_offset;
    ushort exits[];
} fragment_shared_view_t;

typedef struct _fragment_shared_recipe_layout_t {
    struct _fragment_shared_recipe_layout_t *next;
    size_t allocation;
    uint count, references;
    shared_instruction_t instructions[];
} fragment_shared_recipe_layout_t;

typedef struct _fragment_shared_recipe_t {
    fragment_t *fragment;
    struct _fragment_shared_recipe_t *previous, *next;
    fragment_shared_recipe_layout_t *layout;
    uint allocation, saving;
} fragment_shared_recipe_t;

typedef struct _fragment_shared_anchor_t {
    byte proof[DR_SHARED_FRAGMENT_PROOF_SIZE];
    byte digest[MD5_RAW_BYTES];
    byte body_identity[DR_SHARED_FRAGMENT_BODY_IDENTITY_SIZE];
    fragment_shared_recipe_t *recipe;
    uint serial, original_size;
} fragment_shared_anchor_t;
#ifdef X64
_Static_assert(sizeof(fragment_shared_anchor_t) == 128,
               "durable emission proof must fit one 128-byte allocation");
_Static_assert(sizeof(fragment_shared_recipe_t) <= 64,
               "optional recipe must fit one arena unit");
#endif

/* One bounded, lazily touched metadata arena. Records and shared layouts occupy
 * whole 64-byte units; no variable-size heap bins or complete ilists are retained. */
static byte *recipe_arena;
static uint64 recipe_occupied[DR_SHARED_FRAGMENT_BUNDLE_LIMIT / (64 * 64)];
static size_t recipe_live_size;
static size_t anchor_live_size;
static uint recipe_serial;
static fragment_shared_recipe_t *recipe_first, *recipe_last;
static fragment_shared_recipe_layout_t *recipe_layouts;

static void
shared_recipe_digest(const fragment_t *fragment, const byte *original_copy,
                     const shared_instruction_t *nodes, uint count,
                     byte digest[MD5_RAW_BYTES])
{
    struct MD5Context context;
    d_r_md5_init(&context);
    d_r_md5_update(&context, original_copy, fragment->prefix_size);
    for (uint i = 0; i < count; ++i) {
        /* Linking changes only the final displacement of these known exits.
         * This local integrity check is not the canonical equivalence key;
         * the provider digest and exact sealed-byte comparison still apply. */
        uint length = nodes[i].length;
        if (nodes[i].kind == SHARED_EXIT) {
            ASSERT(length >= sizeof(uint));
            length -= sizeof(uint);
        }
        d_r_md5_update(&context, original_copy + nodes[i].original, length);
    }
    d_r_md5_final(digest, &context);
}

/* Only unpublished prototype/node buffers and wholly unused recipe storage use
 * this path. Shared batch/arena mappings retain their own backing lifetime. */
static void
shared_release_temporary(void *memory, size_t size, which_vmm_t which)
{
#ifdef LINUX
    /* Eligible shared fragments exclude dual-mapped caches. These dedicated
     * scratch allocations are private anonymous memory, including any reserved
     * prototype tail. Linux heap decommit otherwise only recycles VM blocks. */
    ASSERT(!DYNAMO_OPTION(satisfy_w_xor_x));
    if (!DYNAMO_OPTION(satisfy_w_xor_x) && !os_heap_discard_unused(memory, size)) {
        LOG(GLOBAL, LOG_HEAP, 2,
            "shared temporary discard failed; recycling owned storage\n");
    }
#endif
    heap_munmap(memory, size, which);
}

static void
shared_recipe_space_release(void *pointer, size_t allocation, bool keep_mapping)
{
    ASSERT_OWN_RECURSIVE_LOCK(true, &change_linking_lock);
    uint first = (uint)((byte *)pointer - recipe_arena) / 64;
    uint units = (uint)allocation / 64;
    recipe_live_size -= allocation;
    for (uint i = first; i < first + units; ++i) {
        ASSERT(TESTANY((uint64)1 << (i % 64), recipe_occupied[i / 64]));
        recipe_occupied[i / 64] &= ~((uint64)1 << (i % 64));
    }
    if (recipe_live_size == 0 && !keep_mapping) {
        shared_release_temporary(recipe_arena, DR_SHARED_FRAGMENT_BUNDLE_LIMIT,
                                 VMM_SPECIAL_MMAP);
        recipe_arena = NULL;
        ASSERT(recipe_first == NULL && recipe_last == NULL && recipe_layouts == NULL);
    }
}

static void
shared_recipe_layout_release(fragment_shared_recipe_layout_t *layout, bool keep_mapping)
{
    ASSERT_OWN_RECURSIVE_LOCK(true, &change_linking_lock);
    ASSERT(layout->references != 0);
    if (--layout->references != 0)
        return;
    fragment_shared_recipe_layout_t **entry = &recipe_layouts;
    while (*entry != layout) {
        ASSERT(*entry != NULL);
        entry = &(*entry)->next;
    }
    *entry = layout->next;
    shared_recipe_space_release(layout, layout->allocation, keep_mapping);
}

static void
shared_recipe_release(fragment_t *fragment, bool keep_mapping)
{
    ASSERT_OWN_RECURSIVE_LOCK(true, &change_linking_lock);
    fragment_shared_recipe_t *recipe =
        fragment->shared_anchor == NULL ? NULL : fragment->shared_anchor->recipe;
    if (recipe == NULL)
        return;
    if (recipe->previous != NULL)
        recipe->previous->next = recipe->next;
    else
        recipe_first = recipe->next;
    if (recipe->next != NULL)
        recipe->next->previous = recipe->previous;
    else
        recipe_last = recipe->previous;
    fragment->shared_anchor->recipe = NULL;
    shared_recipe_layout_release(recipe->layout, keep_mapping);
    shared_recipe_space_release(recipe, recipe->allocation, keep_mapping);
}

static void
shared_anchor_release(fragment_t *fragment)
{
    ASSERT_OWN_RECURSIVE_LOCK(true, &change_linking_lock);
    if (fragment->shared_anchor == NULL)
        return;
    shared_recipe_release(fragment, false);
    global_heap_free(fragment->shared_anchor,
                     sizeof(*fragment->shared_anchor) HEAPACCT(ACCT_FRAGMENT));
    anchor_live_size -= sizeof(*fragment->shared_anchor);
    fragment->shared_anchor = NULL;
}

/* Reserve a contiguous interval in a private planning bitmap, never live state. */
static uint
shared_recipe_plan_space(uint64 *occupied, size_t allocation)
{
    ASSERT(ALIGNED(allocation, 64) && allocation <= DR_SHARED_FRAGMENT_BUNDLE_LIMIT);
    const uint units = (uint)allocation / 64;
    uint available = 0;
    for (uint i = 0; i < DR_SHARED_FRAGMENT_BUNDLE_LIMIT / 64; ++i) {
        if (TESTANY((uint64)1 << (i % 64), occupied[i / 64]))
            available = 0;
        else if (++available == units) {
            const uint first = i + 1 - units;
            for (uint j = first; j <= i; ++j)
                occupied[j / 64] |= (uint64)1 << (j % 64);
            return first;
        }
    }
    return UINT_MAX;
}

static void *
shared_recipe_space_allocate(size_t allocation, uint first)
{
    ASSERT_OWN_RECURSIVE_LOCK(true, &change_linking_lock);
    ASSERT(ALIGNED(allocation, 64) && allocation <= DR_SHARED_FRAGMENT_BUNDLE_LIMIT);
    const uint units = (uint)allocation / 64;
    ASSERT(first <= DR_SHARED_FRAGMENT_BUNDLE_LIMIT / 64 - units);
    if (recipe_arena == NULL) {
        /* READ first avoids DEBUG_MEMORY eagerly touching the entire arena. */
        recipe_arena =
            heap_mmap(DR_SHARED_FRAGMENT_BUNDLE_LIMIT, MEMPROT_READ, VMM_SPECIAL_MMAP);
        if (!set_protection(recipe_arena, DR_SHARED_FRAGMENT_BUNDLE_LIMIT,
                            MEMPROT_READ | MEMPROT_WRITE)) {
            heap_munmap(recipe_arena, DR_SHARED_FRAGMENT_BUNDLE_LIMIT, VMM_SPECIAL_MMAP);
            recipe_arena = NULL;
            return NULL;
        }
    }
    byte *result = recipe_arena + first * 64;
    memset(result, 0, allocation);
    for (uint i = first; i < first + units; ++i) {
        ASSERT(!TESTANY((uint64)1 << (i % 64), recipe_occupied[i / 64]));
        recipe_occupied[i / 64] |= (uint64)1 << (i % 64);
    }
    recipe_live_size += allocation;
    return result;
}

static void
shared_recipe_save(fragment_t *fragment, const shared_instruction_t *nodes, uint count,
                   uint island_base, uint saving)
{
    if (fragment->shared_anchor == NULL || fragment->shared_anchor->recipe != NULL)
        return;
    size_t allocation = ALIGN_FORWARD(sizeof(fragment_shared_recipe_t), 64);
    size_t layout_allocation = ALIGN_FORWARD(
        sizeof(fragment_shared_recipe_layout_t) + count * sizeof(*nodes), 64);
    if (layout_allocation > DR_SHARED_FRAGMENT_BUNDLE_LIMIT - allocation)
        return;
    acquire_recursive_lock(&change_linking_lock);
    if (fragment->shared_anchor == NULL || fragment->shared_anchor->recipe != NULL) {
        release_recursive_lock(&change_linking_lock);
        return;
    }
    fragment_shared_recipe_layout_t *layout;
    for (layout = recipe_layouts; layout != NULL; layout = layout->next) {
        if (layout->count != count)
            continue;
        uint i;
        for (i = 0; i < count; ++i) {
            shared_instruction_t normalized = nodes[i];
            if (normalized.kind == SHARED_PRIVATE || normalized.kind == SHARED_EXIT)
                normalized.island -= island_base;
            if (memcmp(&normalized, &layout->instructions[i], sizeof(normalized)) != 0)
                break;
        }
        if (i == count)
            break;
    }
    /* Plan the complete replacement before deleting anything. The bitmap is
     * 128 bytes and at most 1024 record pointers fit this 64 KiB arena. Scores
     * use the current owner snapshot, excluding the later temporary layout pin.
     * Do not reduce other layouts' reference counts while choosing victims:
     * that would make their remaining peers progressively easier to evict. */
    uint64 planned[BUFFER_SIZE_ELEMENTS(recipe_occupied)];
    memcpy(planned, recipe_occupied, sizeof(planned));
    fragment_shared_recipe_t *victims[DR_SHARED_FRAGMENT_BUNDLE_LIMIT / 64];
    uint victim_count = 0, record_first = UINT_MAX, layout_first = UINT_MAX;
    uint incoming_references = layout == NULL ? 1 : layout->references + 1;
    for (;;) {
        uint64 attempt[BUFFER_SIZE_ELEMENTS(recipe_occupied)];
        memcpy(attempt, planned, sizeof(attempt));
        /* Allocate the larger interval first to preserve contiguous layout space. */
        if (layout == NULL && layout_allocation >= allocation) {
            layout_first = shared_recipe_plan_space(attempt, layout_allocation);
            record_first = layout_first == UINT_MAX
                ? UINT_MAX
                : shared_recipe_plan_space(attempt, allocation);
        } else {
            record_first = shared_recipe_plan_space(attempt, allocation);
            layout_first = layout != NULL || record_first == UINT_MAX
                ? UINT_MAX
                : shared_recipe_plan_space(attempt, layout_allocation);
        }
        if (record_first != UINT_MAX && (layout != NULL || layout_first != UINT_MAX))
            break;

        fragment_shared_recipe_t *victim = NULL;
        uint64 victim_gain = 0, victim_charge = 0;
        for (fragment_shared_recipe_t *candidate = recipe_first; candidate != NULL;
             candidate = candidate->next) {
            const uint unit = (uint)((byte *)candidate - recipe_arena) / 64;
            if (!TESTANY((uint64)1 << (unit % 64), planned[unit / 64]))
                continue; /* already selected */
            /* Compare exact rational shares without rounding each owner's
             * layout charge upward. Arena/fragment bounds keep cross-products
             * below 2^64 (at most 1024 owners and a 64 KiB layout). */
            const uint64 gain = (uint64)candidate->saving * candidate->layout->references;
            const uint64 charge =
                (uint64)candidate->allocation * candidate->layout->references +
                candidate->layout->allocation;
            const uint references =
                incoming_references - (candidate->layout == layout ? 1 : 0);
            const uint64 incoming_gain = (uint64)saving * references;
            const uint64 incoming_charge = allocation * references +
                (layout == NULL ? layout_allocation : layout->allocation);
            if (incoming_gain * charge < gain * incoming_charge)
                continue;
            bool acceptable = true;
            for (uint i = 0; i < victim_count && acceptable; ++i) {
                const fragment_shared_recipe_t *prior = victims[i];
                const uint64 prior_gain =
                    (uint64)prior->saving * prior->layout->references;
                const uint64 prior_charge =
                    (uint64)prior->allocation * prior->layout->references +
                    prior->layout->allocation;
                acceptable = incoming_gain * prior_charge >= prior_gain * incoming_charge;
            }
            if (!acceptable)
                continue;
            if (victim == NULL || gain * victim_charge < victim_gain * charge) {
                victim = candidate;
                victim_gain = gain;
                victim_charge = charge;
            }
        }
        if (victim == NULL) {
            release_recursive_lock(&change_linking_lock);
            return;
        }
        ASSERT(victim_count < BUFFER_SIZE_ELEMENTS(victims));
        victims[victim_count++] = victim;
        uint first = (uint)((byte *)victim - recipe_arena) / 64;
        for (uint i = first; i < first + victim->allocation / 64; ++i)
            planned[i / 64] &= ~((uint64)1 << (i % 64));
        if (victim->layout == layout) {
            --incoming_references;
        } else {
            bool remaining = false;
            for (fragment_shared_recipe_t *owner = recipe_first; owner != NULL;
                 owner = owner->next) {
                const uint unit = (uint)((byte *)owner - recipe_arena) / 64;
                if (owner->layout == victim->layout &&
                    TESTANY((uint64)1 << (unit % 64), planned[unit / 64])) {
                    remaining = true;
                    break;
                }
            }
            if (!remaining) {
                first = (uint)((byte *)victim->layout - recipe_arena) / 64;
                for (uint i = first; i < first + victim->layout->allocation / 64; ++i)
                    planned[i / 64] &= ~((uint64)1 << (i % 64));
            }
        }
    }
    /* The existing layout must survive deletion of its last old owner. Preserve
     * an otherwise empty arena only across this proven replacement transaction. */
    if (layout != NULL)
        ++layout->references;
    for (uint i = 0; i < victim_count; ++i)
        shared_recipe_release(victims[i]->fragment, true);
    if (layout == NULL) {
        layout = shared_recipe_space_allocate(layout_allocation, layout_first);
        if (layout == NULL) {
            release_recursive_lock(&change_linking_lock);
            return;
        }
        layout->allocation = layout_allocation;
        layout->count = count;
        layout->references = 1;
        memcpy(layout->instructions, nodes, count * sizeof(*nodes));
        for (uint i = 0; i < count; ++i) {
            shared_instruction_t *node = &layout->instructions[i];
            if (node->kind == SHARED_PRIVATE || node->kind == SHARED_EXIT) {
                ASSERT(node->island >= island_base);
                node->island -= island_base;
            }
        }
        layout->next = recipe_layouts;
        recipe_layouts = layout;
    }
    fragment_shared_recipe_t *recipe =
        shared_recipe_space_allocate(allocation, record_first);
    if (recipe == NULL) {
        shared_recipe_layout_release(layout, false);
        release_recursive_lock(&change_linking_lock);
        return;
    }
    recipe->fragment = fragment;
    recipe->layout = layout;
    recipe->allocation = (uint)allocation;
    recipe->saving = saving;
    recipe->previous = recipe_last;
    if (recipe_last != NULL)
        recipe_last->next = recipe;
    else
        recipe_first = recipe;
    recipe_last = recipe;
    fragment->shared_anchor->recipe = recipe;
    release_recursive_lock(&change_linking_lock);
}

uint
fragment_shared_recipe_id(dcontext_t *dcontext, app_pc tag)
{
    uint serial = 0;
    if (dcontext == NULL || dcontext == GLOBAL_DCONTEXT)
        return 0;
    acquire_recursive_lock(&change_linking_lock);
    fragment_t *fragment = fragment_lookup_shared_bb(dcontext, tag);
    if (fragment != NULL && fragment->shared_anchor != NULL)
        serial = fragment->shared_anchor->serial;
    release_recursive_lock(&change_linking_lock);
    return serial;
}

DR_API
size_t
dr_shared_fragment_pending_count(void)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    if (!fragment_shared_provider_enabled())
        return 0;
    if (!try_recursive_lock(&change_linking_lock))
        return SIZE_MAX;
    size_t count = anchor_live_size / sizeof(fragment_shared_anchor_t);
    release_recursive_lock(&change_linking_lock);
    return count;
#else
    return 0;
#endif
}

static uint
shared_retained_code_size(dcontext_t *dcontext, fragment_t *fragment, uint compact_end)
{
    uint size = compact_end;
    for (linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment); stub != NULL;
         stub = LINKSTUB_NEXT_EXIT(stub)) {
        if (!EXIT_HAS_STUB(stub->flags, fragment->flags) ||
            TESTANY(LINK_SEPARATE_STUB, stub->flags))
            continue;
        if (PAD_FRAGMENT_JMPS(fragment->flags))
            size += bytes_for_exitstub_alignment(dcontext, stub, fragment,
                                                 fragment->start_pc + size);
        size += exit_stub_size(dcontext, EXIT_TARGET_TAG(dcontext, fragment, stub),
                               fragment->flags);
    }
    return size;
}

bool
fragment_shared_snapshot(dcontext_t *dcontext, fragment_t *fragment,
                         dr_shared_fragment_snapshot_t *snapshot)
{
    ASSERT_OWN_RECURSIVE_LOCK(true, &change_linking_lock);
    if (TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_IS_TRACE | FRAG_COARSE_GRAIN |
                    FRAG_WAS_DELETED | FRAG_CANNOT_DELETE,
                fragment->flags) ||
        fragment->shared_view != NULL || fragment->shared_anchor == NULL ||
        fragment->size != fragment->shared_anchor->original_size)
        return false;
    uint compact_end = fragment->prefix_size + fragment->shared_entry_size;
    uint exits = 0;
    bool valid = true;
    instr_t decoded;
    instr_init(dcontext, &decoded);
    for (linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment); stub != NULL;
         stub = LINKSTUB_NEXT_EXIT(stub)) {
        instr_reset(dcontext, &decoded);
        if (stub->cti_offset >= fragment->size) {
            valid = false;
            break;
        }
        byte instruction[MAX_INSTR_LENGTH] = { 0 };
        uint available = MIN(sizeof(instruction), fragment->size - stub->cti_offset);
        memcpy(instruction, fragment->start_pc + stub->cti_offset, available);
        byte *next = decode_from_copy(dcontext, instruction,
                                      fragment->start_pc + stub->cti_offset, &decoded);
        if (LINKSTUB_CBR_FALLTHROUGH(stub->flags) || next == NULL ||
            next <= instruction || next > instruction + available ||
            instr_is_cti_short(&decoded)) {
            valid = false;
            break;
        }
        if (PAD_FRAGMENT_JMPS(fragment->flags))
            compact_end += patchable_exit_cti_align_offs(
                dcontext, &decoded, fragment->start_pc + compact_end);
        compact_end += (uint)(next - instruction);
        ++exits;
    }
    instr_free(dcontext, &decoded);
    if (!valid)
        return false;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->tag = fragment->tag;
    snapshot->emission_id = fragment->shared_anchor->serial;
    snapshot->original_size = fragment->size;
    snapshot->retained_code_size =
        shared_retained_code_size(dcontext, fragment, compact_end);
    snapshot->retained_private_size = compact_end +
        (fragment->start_pc + fragment->size - fragment_body_end_pc(dcontext, fragment)) +
        exits * 64 + sizeof(fragment_shared_view_t) + exits * sizeof(ushort) +
        2 * sizeof(fcache_shared_view_t);
    memcpy(snapshot->proof, fragment->shared_anchor->proof, sizeof(snapshot->proof));
    memcpy(snapshot->body_identity, fragment->shared_anchor->body_identity,
           sizeof(snapshot->body_identity));
    return true;
}

DR_API
dr_shared_fragment_rebind_status_t
dr_shared_fragment_snapshot(app_pc tag, dr_shared_fragment_snapshot_t *snapshot)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    if (snapshot == NULL)
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;
    memset(snapshot, 0, sizeof(*snapshot));
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (tag == NULL || dcontext == NULL || dcontext == GLOBAL_DCONTEXT ||
        !fragment_shared_provider_enabled())
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (!try_recursive_lock(&change_linking_lock))
        return DR_SHARED_FRAGMENT_REBIND_BUSY;
    fragment_t *fragment = fragment_lookup_shared_bb(dcontext, tag);
    const bool found =
        fragment != NULL && fragment_shared_snapshot(dcontext, fragment, snapshot);
    release_recursive_lock(&change_linking_lock);
    return found ? DR_SHARED_FRAGMENT_REBIND_AVAILABLE : DR_SHARED_FRAGMENT_REBIND_ABSENT;
#else
    if (snapshot != NULL)
        memset(snapshot, 0, sizeof(*snapshot));
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
#endif
}

DR_API
dr_shared_fragment_rebind_status_t
dr_shared_fragment_rebind_available(app_pc tag,
                                    const byte proof[DR_SHARED_FRAGMENT_PROOF_SIZE],
                                    uint emission_id)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (tag == NULL || proof == NULL || emission_id == 0 || dcontext == NULL ||
        dcontext == GLOBAL_DCONTEXT || !fragment_shared_provider_enabled())
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (!try_recursive_lock(&change_linking_lock))
        return DR_SHARED_FRAGMENT_REBIND_BUSY;
    /* A saved emission recipe can precede fragment_add(). Use the same
     * published table as promotion, never credit an invisible emission. The
     * linking lock excludes normal shared-table publication/removal writers. */
    fragment_t *fragment = fragment_lookup_shared_bb(dcontext, tag);
    fragment_shared_anchor_t *anchor = fragment != NULL &&
            !TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_COARSE_GRAIN | FRAG_WAS_DELETED |
                         FRAG_CANNOT_DELETE,
                     fragment->flags)
        ? fragment->shared_anchor
        : NULL;
    dr_shared_fragment_rebind_status_t status = DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (anchor != NULL && anchor->serial == emission_id &&
        fragment->shared_view == NULL && fragment->size == anchor->original_size &&
        memcmp(anchor->proof, proof, DR_SHARED_FRAGMENT_PROOF_SIZE) == 0) {
        if (anchor->recipe == NULL) {
            status = provider.restore_layout == NULL
                ? DR_SHARED_FRAGMENT_REBIND_ABSENT
                : DR_SHARED_FRAGMENT_REBIND_RESTORABLE;
        } else {
            byte digest[MD5_RAW_BYTES];
            shared_recipe_digest(fragment, fragment->start_pc,
                                 anchor->recipe->layout->instructions,
                                 anchor->recipe->layout->count, digest);
            if (memcmp(digest, anchor->digest, sizeof(digest)) == 0)
                status = DR_SHARED_FRAGMENT_REBIND_AVAILABLE;
        }
    }
    release_recursive_lock(&change_linking_lock);
    return status;
#else
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
#endif
}

DR_API
dr_shared_fragment_rebind_status_t
dr_shared_fragment_discard(app_pc tag, uint emission_id,
                           const byte proof[DR_SHARED_FRAGMENT_PROOF_SIZE])
{
#if defined(LINUX) && defined(X86) && defined(X64)
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (tag == NULL || emission_id == 0 || proof == NULL || dcontext == NULL ||
        dcontext == GLOBAL_DCONTEXT || !fragment_shared_provider_enabled())
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (!try_recursive_lock(&change_linking_lock))
        return DR_SHARED_FRAGMENT_REBIND_BUSY;
    fragment_t *fragment = fragment_lookup_shared_bb(dcontext, tag);
    fragment_shared_anchor_t *anchor = fragment != NULL &&
            !TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_IS_TRACE | FRAG_COARSE_GRAIN |
                         FRAG_WAS_DELETED | FRAG_CANNOT_DELETE,
                     fragment->flags) &&
            fragment->shared_view == NULL
        ? fragment->shared_anchor
        : NULL;
    dr_shared_fragment_rebind_status_t status = DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (anchor != NULL && anchor->serial == emission_id &&
        anchor->original_size == fragment->size &&
        memcmp(anchor->proof, proof, DR_SHARED_FRAGMENT_PROOF_SIZE) == 0) {
        /* The provider has proved this exact source generation permanently stale.
         * Retire only its nonexecuting recovery state; existing code and queued
         * requests retain their normal lifetime and serial checks. */
        shared_anchor_release(fragment);
        status = DR_SHARED_FRAGMENT_REBIND_AVAILABLE;
    }
    release_recursive_lock(&change_linking_lock);
    return status;
#else
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
#endif
}

static uint
shared_private_cell_size(uint island_size)
{
    uint width = 64; /* At most 64 cells, represented by the occupancy word. */
    if (island_size > PAGE_SIZE)
        return ALIGN_FORWARD(island_size, PAGE_SIZE);
    while (width < island_size)
        width *= 2;
    return width;
}

/* The shared body uses a deterministic cell coordinate. Different local arenas
 * may have different owners, but a template's relative private displacement is
 * independent of process addresses and allocation order. An occupied cell selects
 * another arena, retaining the same relative coordinate for equal templates.
 * The private window is anonymous memory, retaining normal COW across fork.
 * Returns with change_linking_lock held until all private writes are complete.
 */
static fragment_shared_arena_t *
shared_arena_acquire(uint body_size, uint island_size, const shared_instruction_t *nodes,
                     uint count, uint *cell)
{
    uint width = shared_private_cell_size(island_size);
    uint cells = width > PAGE_SIZE ? 1 : PAGE_SIZE / width;
    uint64 hash = 14695981039346656037ULL;
    const byte *identity = (const byte *)nodes;
    for (size_t i = 0; i < count * sizeof(*nodes); ++i) {
        hash ^= identity[i];
        hash *= 1099511628211ULL;
    }
    /* Cell counts are powers of two. Fold all input bits into the low bits so
     * similarly aligned instruction records do not collapse onto one cell.
     */
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;
    *cell = (uint)(hash % cells);
    const uint64 occupied_bit = (uint64)1 << *cell;
    acquire_recursive_lock(&change_linking_lock);
    fragment_shared_arena_t *arena;
    for (arena = shared_arenas; arena != NULL; arena = arena->next) {
        if (arena->body_size == body_size && arena->cell_size == width &&
            !TESTANY(occupied_bit, arena->occupied))
            break;
    }
    if (arena == NULL) {
        arena = global_heap_alloc(sizeof(*arena) HEAPACCT(ACCT_FRAGMENT));
        memset(arena, 0, sizeof(*arena));
        arena->body_size = body_size;
        arena->cell_size = width;
        arena->cells = cells;
        arena->size = (size_t)body_size * cells + ALIGN_FORWARD(width * cells, PAGE_SIZE);
        arena->base =
            heap_mmap_reserve(arena->size, 0, MEMPROT_NONE, VMM_CACHE | VMM_REACHABLE);
        arena->private_base = arena->base + (size_t)body_size * cells;
        heap_mmap_extend_commitment(arena->private_base,
                                    ALIGN_FORWARD(width * cells, PAGE_SIZE),
                                    VMM_CACHE | VMM_REACHABLE);
        arena->next = shared_arenas;
        shared_arenas = arena;
    } else {
        bool writable =
            set_protection(arena->private_base, ALIGN_FORWARD(width * cells, PAGE_SIZE),
                           MEMPROT_READ | MEMPROT_WRITE | MEMPROT_EXEC);
        if (!writable) {
            release_recursive_lock(&change_linking_lock);
            return NULL;
        }
    }
    arena->occupied |= occupied_bit;
    heap_mmap_extend_commitment(arena->base + (size_t)*cell * body_size, body_size,
                                VMM_CACHE | VMM_REACHABLE);
    return arena;
}

static void
shared_arena_release(fragment_shared_arena_t *arena, uint cell)
{
    acquire_recursive_lock(&change_linking_lock);
    byte *body = arena->base + (size_t)cell * arena->body_size;
    size_t restored_size = arena->body_size;
    byte *restored =
        os_map_file(INVALID_FILE, &restored_size, 0, body, MEMPROT_NONE,
                    MAP_FILE_FIXED | MAP_FILE_VMM_COMMIT | MAP_FILE_COPY_ON_WRITE);
    ASSERT(restored == body);
    if (restored == body) {
        heap_mmap_retract_commitment(body, arena->body_size, VMM_CACHE | VMM_REACHABLE);
        arena->occupied &= ~((uint64)1 << cell);
        if (arena->occupied == 0) {
            fragment_shared_arena_t **previous = &shared_arenas;
            while (*previous != arena)
                previous = &(*previous)->next;
            *previous = arena->next;
            heap_munmap(arena->base, arena->size, VMM_CACHE | VMM_REACHABLE);
            global_heap_free(arena, sizeof(*arena) HEAPACCT(ACCT_FRAGMENT));
        }
    }
    release_recursive_lock(&change_linking_lock);
}

/* A local reservation shares one complete immutable RX bundle. RX members and
 * their private intervals are independently exclusive: a second binding for an
 * occupied member requires another reservation of the same file. Returns with
 * change_linking_lock held until the new private instructions are initialized.
 */
static fragment_shared_batch_t *
shared_batch_acquire(const dr_shared_fragment_file_t *file, uint member_span,
                     uint private_span)
{
#ifdef LINUX
    struct stat backing;
    if (dynamorio_syscall(SYS_fstat, 2, file->fd, &backing) != 0)
        return NULL;
    bool compact = provider.compact_private_bindings;
    uint body_size = (uint)file->size;
    uint private_size = compact ? (uint)file->private_extent : PAGE_SIZE;
    uint private_offset = compact ? (uint)file->private_offset : file->member_offset;
    uint first[2] = { (uint)file->member_offset / 16, (body_size + private_offset) / 16 };
    uint units[2] = { member_span / 16, private_span / 16 };
    uint words = (body_size + private_size) / (16 * 64);
    acquire_recursive_lock(&change_linking_lock);
    fragment_shared_batch_t *batch;
    for (batch = shared_batches; batch != NULL; batch = batch->next) {
        if (batch->compact_bindings != compact ||
            (compact && batch->private_instance != file->private_instance))
            continue;
        if (batch->device != backing.st_dev || batch->inode != backing.st_ino ||
            batch->file_offset != file->offset || batch->body_size != body_size ||
            batch->private_size != private_size) {
            if (compact) {
                release_recursive_lock(&change_linking_lock);
                return NULL;
            }
            continue;
        }
        bool available = true;
        for (uint interval = 0; interval < 2 && available; ++interval) {
            for (uint i = first[interval]; i < first[interval] + units[interval]; ++i) {
                if (TESTANY((uint64)1 << (i % 64), batch->occupied[i / 64])) {
                    available = false;
                    break;
                }
            }
        }
        if (available)
            break;
        if (compact) {
            release_recursive_lock(&change_linking_lock);
            return NULL;
        }
    }
    if (batch == NULL) {
        size_t allocation = sizeof(*batch) + words * sizeof(*batch->occupied);
        batch = global_heap_alloc(allocation HEAPACCT(ACCT_FRAGMENT));
        memset(batch, 0, allocation);
        batch->device = backing.st_dev;
        batch->inode = backing.st_ino;
        batch->file_offset = file->offset;
        batch->body_size = body_size;
        batch->private_size = private_size;
        batch->bitmap_words = words;
        batch->compact_bindings = compact;
        batch->private_instance = compact ? file->private_instance : 0;
        batch->base = heap_mmap(body_size + private_size,
                                MEMPROT_READ | MEMPROT_WRITE | MEMPROT_EXEC,
                                VMM_CACHE | VMM_REACHABLE);
        size_t size = body_size;
        if (os_map_file(file->fd, &size, file->offset, batch->base,
                        MEMPROT_READ | MEMPROT_EXEC,
                        MAP_FILE_FIXED | MAP_FILE_VMM_COMMIT) != batch->base ||
            size != body_size) {
            heap_munmap(batch->base, body_size + private_size, VMM_CACHE | VMM_REACHABLE);
            global_heap_free(batch, allocation HEAPACCT(ACCT_FRAGMENT));
            release_recursive_lock(&change_linking_lock);
            return NULL;
        }
        batch->next = shared_batches;
        shared_batches = batch;
    } else if (!set_protection(batch->base + body_size, private_size,
                               MEMPROT_READ | MEMPROT_WRITE | MEMPROT_EXEC)) {
        release_recursive_lock(&change_linking_lock);
        return NULL;
    }
    for (uint interval = 0; interval < 2; ++interval) {
        for (uint i = first[interval]; i < first[interval] + units[interval]; ++i)
            batch->occupied[i / 64] |= (uint64)1 << (i % 64);
    }
    return batch;
#else
    return NULL;
#endif
}

static void
shared_batch_release(fragment_shared_batch_t *batch, uint offset, uint member_span,
                     uint private_offset, uint private_span)
{
    acquire_recursive_lock(&change_linking_lock);
    uint first[2] = { offset / 16, (batch->body_size + private_offset) / 16 };
    uint units[2] = { member_span / 16, private_span / 16 };
    for (uint interval = 0; interval < 2; ++interval) {
        for (uint i = first[interval]; i < first[interval] + units[interval]; ++i) {
            ASSERT(TESTANY((uint64)1 << (i % 64), batch->occupied[i / 64]));
            batch->occupied[i / 64] &= ~((uint64)1 << (i % 64));
        }
    }
    bool empty = true;
    for (uint i = 0; i < batch->bitmap_words; ++i)
        empty &= batch->occupied[i] == 0;
    if (empty) {
        size_t size = batch->body_size;
        byte *restored =
            os_map_file(INVALID_FILE, &size, 0, batch->base, MEMPROT_NONE,
                        MAP_FILE_FIXED | MAP_FILE_VMM_COMMIT | MAP_FILE_COPY_ON_WRITE);
        ASSERT(restored == batch->base);
        if (restored == batch->base) {
            fragment_shared_batch_t **previous = &shared_batches;
            while (*previous != batch)
                previous = &(*previous)->next;
            *previous = batch->next;
            heap_munmap(batch->base, batch->body_size + batch->private_size,
                        VMM_CACHE | VMM_REACHABLE);
            global_heap_free(
                batch,
                (sizeof(*batch) + batch->bitmap_words * sizeof(*batch->occupied))
                    HEAPACCT(ACCT_FRAGMENT));
        }
    }
    release_recursive_lock(&change_linking_lock);
}

bool
fragment_shared_candidate(dcontext_t *dcontext, instrlist_t *ilist, uint flags)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    /* Trace formation decodes the mutable original body. It needs a dedicated
     * lowered-body decoder before composite trace fragments can use this view.
     * Dual-mapped caches likewise need alias-aware shared lowering; retain the
     * ordinary instrumented fragment until that binding path is supported.
     */
    return fragment_shared_provider_enabled() && dr_bb_hook_exists() &&
        DYNAMO_OPTION(disable_traces) && !DYNAMO_OPTION(satisfy_w_xor_x) &&
        !TESTANY(FRAG_IS_TRACE | FRAG_COARSE_GRAIN | FRAG_32_BIT | FRAG_X86_TO_X64 |
                     FRAG_SELFMOD_SANDBOXED | FRAG_HAS_SYSCALL | FRAG_HAS_RSEQ_ENDPOINT |
                     FRAG_STARTS_RSEQ_REGION,
                 flags) &&
        (provider.candidate == NULL || provider.candidate(dcontext, ilist));
#else
    return false;
#endif
}

void
fragment_shared_add_entry(dcontext_t *dcontext, instrlist_t *ilist)
{
    /* Five bytes reserved solely for an unpublished-entry redirect. Recreated
     * ilists retain these no-state-change bytes; even a decoded redirect has
     * the same length and does not spill a register or touch application flags.
     */
    for (uint i = 0; i < 5; ++i) {
        instr_t *nop = INSTR_CREATE_nop(dcontext);
        instr_set_meta(nop);
        instrlist_prepend(ilist, nop);
    }
}

static bool
shared_relative_jump(byte *output, byte *pc, byte *target)
{
    ptr_int_t displacement = target - (pc + 5);
    if (displacement != (int)displacement)
        return false;
    output[0] = 0xe9;
    int relative = (int)displacement;
    memcpy(output + 1, &relative, sizeof(relative));
    return true;
}

static bool
shared_operand_targets_fragment(opnd_t operand, const fragment_t *fragment)
{
    /* Only JMP/Jcc nodes currently relocate references into the emitted body.
     * A private CALL, data reference or materialized label would otherwise keep
     * pointing at original cache bytes reclaimed by frame compaction. Do not
     * infer pointers from numeric immediates: preserve symbolic operands before
     * encoding erases that distinction, and inspect explicit decoded addresses.
     */
    if (opnd_is_instr(operand) || opnd_is_mem_instr(operand))
        return true;
    byte *target = NULL;
    if (opnd_is_pc(operand))
        target = opnd_get_pc(operand);
    else if (opnd_is_rel_addr(operand) ||
             (opnd_is_abs_addr(operand) && opnd_get_segment(operand) == DR_REG_NULL))
        target = opnd_get_addr(operand);
    return target != NULL && target >= fragment->start_pc &&
        target < fragment->start_pc + fragment->size;
}

static bool
shared_operand_private(opnd_t operand, bool copy_immediates)
{
    /* Literal arithmetic operands stay in the exact canonical byte sequence:
     * differing values cannot match its digest or final byte comparison. Do
     * not classify integers by value. MOV immediates and explicitly absolute
     * or RIP-relative operands retain independent process-local bindings.
     * Base/index displacements and TLS offsets remain position-independent.
     */
    bool thread_relative = IF_X86_ELSE(opnd_is_abs_addr(operand) &&
                                           (opnd_get_segment(operand) == DR_SEG_FS ||
                                            opnd_get_segment(operand) == DR_SEG_GS),
                                       false);
    return (opnd_is_immed(operand) && !copy_immediates) || opnd_is_pc(operand) ||
        opnd_is_instr(operand) || opnd_is_rel_addr(operand) ||
        (opnd_is_abs_addr(operand) && !thread_relative) ||
        (opnd_is_base_disp(operand) && opnd_get_base(operand) == DR_REG_NULL &&
         opnd_get_index(operand) == DR_REG_NULL &&
         opnd_get_segment(operand) == DR_REG_NULL);
}

#if defined(LINUX) && defined(X86) && defined(X64)
static int
shared_instruction_kind(instr_t *decoded, const fragment_t *fragment)
{
    if (instr_is_syscall(decoded) || instr_is_return(decoded))
        return -1;
    bool local = instr_is_cti(decoded);
    bool copy_immediates = false;
    switch (instr_get_opcode(decoded)) {
    case OP_add:
    case OP_adc:
    case OP_sub:
    case OP_sbb:
    case OP_and:
    case OP_or:
    case OP_xor:
    case OP_cmp:
    case OP_test:
    case OP_imul:
    case OP_shl:
    case OP_shr:
    case OP_sar:
    case OP_shld:
    case OP_shrd:
    case OP_rol:
    case OP_ror:
    case OP_rcl:
    case OP_rcr: copy_immediates = true; break;
    default: break;
    }
    for (int i = 0; i < instr_num_srcs(decoded); ++i) {
        opnd_t operand = instr_get_src(decoded, i);
        if (shared_operand_targets_fragment(operand, fragment))
            return -1;
        local |= shared_operand_private(operand, copy_immediates);
    }
    for (int i = 0; i < instr_num_dsts(decoded); ++i) {
        opnd_t operand = instr_get_dst(decoded, i);
        if (shared_operand_targets_fragment(operand, fragment))
            return -1;
        local |= shared_operand_private(operand, copy_immediates);
    }
    return local ? SHARED_PRIVATE : SHARED_COPY;
}
#endif

static int
shared_instruction_index(const shared_instruction_t *instructions, uint count,
                         uint offset)
{
    uint low = 0, high = count;
    while (low < high) {
        uint middle = low + (high - low) / 2;
        if (instructions[middle].original <= offset)
            low = middle + 1;
        else
            high = middle;
    }
    if (low == 0)
        return -1;
    --low;
    const shared_instruction_t *node = &instructions[low];
    return offset == node->original ||
            ((node->kind == SHARED_COPY || node->kind == SHARED_PRIVATE) &&
             offset < node->original + node->length)
        ? (int)low
        : -1;
}

#if defined(LINUX) && defined(X86) && defined(X64)
static bool
shared_prepare_nodes(dcontext_t *dcontext, const fragment_t *fragment,
                     const byte *original_copy, shared_instruction_t *nodes,
                     uint *node_count, ushort *boundaries)
{
    uint count = *node_count;
    if (count == 0)
        return false;
    bool valid = true, success = false;
    uint shared_bytes = 0;
    memset(boundaries, 0, count * sizeof(*boundaries));
    instr_t decoded;
    instr_init(dcontext, &decoded);
    for (uint i = 0; i < count && valid; ++i) {
        shared_instruction_t *node = &nodes[i];
        if (node->length == 0 || node->original >= fragment->size ||
            node->length > fragment->size - node->original ||
            node->original !=
                (i == 0 ? fragment->prefix_size
                        : nodes[i - 1].original + nodes[i - 1].length)) {
            valid = false;
            break;
        }
        byte *original = (byte *)original_copy + node->original;
        instr_reset(dcontext, &decoded);
        if (decode_from_copy(dcontext, original, fragment->start_pc + node->original,
                             &decoded) != original + node->length) {
            valid = false;
            break;
        }
        bool branch = instr_is_ubr(&decoded) || instr_is_cbr(&decoded);
        if (branch && !instr_is_mbr(&decoded)) {
            int opcode = instr_get_opcode(&decoded);
            if (opcode == OP_jmp_short)
                opcode = OP_jmp;
            else if (opcode >= OP_jo_short && opcode <= OP_jnle_short)
                opcode += OP_jo - OP_jo_short;
            if (opcode != OP_jmp && !(opcode >= OP_jo && opcode <= OP_jnle)) {
                valid = false;
                break;
            }
            if (node->kind != SHARED_EXIT) {
                byte *target = opnd_get_pc(instr_get_target(&decoded));
                int target_index = target >= fragment->start_pc &&
                        target < fragment->start_pc + fragment->size
                    ? shared_instruction_index(nodes, count,
                                               (uint)(target - fragment->start_pc))
                    : -1;
                if (target_index < 0 ||
                    nodes[target_index].original != (uint)(target - fragment->start_pc)) {
                    valid = false;
                    break;
                }
                node->kind = SHARED_BRANCH;
                node->target = (ushort)(target - fragment->start_pc);
                /* Temporary boundary bitmap; this storage later holds exit offsets.
                 */
                boundaries[target_index] = 1;
            }
            node->body_length = opcode == OP_jmp ? 5 : 6;
        } else {
            if (node->kind == SHARED_EXIT || instr_is_syscall(&decoded) ||
                instr_is_return(&decoded)) {
                valid = false;
                break;
            }
            int kind = shared_instruction_kind(&decoded, fragment);
            if (kind < 0) {
                valid = false;
                break;
            }
            bool local = kind == SHARED_PRIVATE;
            node->kind = (byte)kind;
            if (local)
                node->target = instr_is_cti(&decoded); /* Do not merge calls. */
            node->body_length = local ? 5 : node->length;
            if (!local)
                shared_bytes += node->length;
        }
    }
    /* Last node must transfer to an ordinary DR exit stub. There must also be
     * useful immutable instructions beyond the five-byte entry reservation.
     */
    if (!valid || nodes[count - 1].kind != SHARED_EXIT || shared_bytes <= 5)
        goto done;
    /* Runs retain exact byte coordinates and each instruction's encoded length.
     * COPY runs may contain branch targets. PRIVATE runs stop at every internal
     * target and on either side of a CTI, preserving existing call return PCs.
     * Their intermediate fault/restore PCs are recovered by decoding locally.
     */
    uint compact_count = 0;
    for (uint i = 0; i < count; ++i) {
        bool copy_run = compact_count != 0 && nodes[i].kind == SHARED_COPY &&
            nodes[compact_count - 1].kind == SHARED_COPY;
        bool private_run = compact_count != 0 && nodes[i].kind == SHARED_PRIVATE &&
            nodes[compact_count - 1].kind == SHARED_PRIVATE && !boundaries[i] &&
            nodes[i].target == 0 && nodes[compact_count - 1].target == 0;
        if ((copy_run || private_run) &&
            nodes[compact_count - 1].original + nodes[compact_count - 1].length ==
                nodes[i].original) {
            nodes[compact_count - 1].length += nodes[i].length;
        } else {
            nodes[compact_count++] = nodes[i];
        }
    }
    count = compact_count;
    for (uint i = 0; i < count; ++i) {
        if (nodes[i].kind == SHARED_PRIVATE)
            nodes[i].target = 0;
    }
    *node_count = count;
    success = true;
done:
    instr_free(dcontext, &decoded);
    return success;
}

/* The durable anchor certifies the original symbolic validation. This rechecks
 * the sealed table against the exact local emission, including every decoded
 * boundary, branch and real exit. It grants no file-supplied relocation permission.
 */
static bool
shared_restore_validate(dcontext_t *dcontext, fragment_t *fragment,
                        const dr_shared_fragment_restore_t *restore)
{
    if (restore == NULL || restore->struct_size != sizeof(*restore) ||
        restore->buffer == NULL || !ALIGNED(restore->buffer, sizeof(uint64)) ||
        restore->capacity < restore->content_size ||
        restore->content_size < sizeof(shared_layout_t) ||
        restore->content_size > DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
        restore->private_base > 2 * DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
        restore->private_base < restore->content_size)
        return false;
    const shared_layout_t *layout = (const shared_layout_t *)restore->buffer;
    if (layout->magic != 0x58525244 || layout->schema != 11 || layout->count == 0 ||
        layout->count >
            (restore->content_size - sizeof(*layout)) / sizeof(shared_instruction_t) ||
        layout->code_offset !=
            ALIGN_FORWARD(sizeof(*layout) + layout->count * sizeof(shared_instruction_t),
                          16) ||
        layout->code_offset > restore->content_size ||
        layout->code_size != restore->content_size - layout->code_offset ||
        layout->island_size == 0 ||
        layout->island_size > DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
        layout->reserved != ALIGN_FORWARD(layout->island_size, 16) ||
        layout->original_size > fragment->size ||
        layout->original_size >
            (size_t)(fragment_body_end_pc(dcontext, fragment) - fragment->start_pc) ||
        layout->original_size <= fragment->prefix_size + fragment->shared_entry_size)
        return false;
    const shared_instruction_t *nodes =
        (const shared_instruction_t *)(restore->buffer + sizeof(*layout));
    uint original = fragment->prefix_size, body = layout->code_offset, island = 0;
    uint exits = 0, shared_bytes = 0;
    linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment);
    bool valid = true;
    instr_t decoded;
    instr_init(dcontext, &decoded);
    for (uint i = 0; i < layout->count && valid; ++i) {
        const shared_instruction_t *node = &nodes[i];
        if (node->original != original || node->length == 0 ||
            node->length > layout->original_size - original || node->body != body ||
            node->kind > SHARED_EXIT) {
            valid = false;
            break;
        }
        uint end = original + node->length;
        while (original < end && valid) {
            byte instruction[MAX_INSTR_LENGTH] = { 0 };
            uint available = MIN(sizeof(instruction), end - original);
            memcpy(instruction, fragment->start_pc + original, available);
            instr_reset(dcontext, &decoded);
            byte *next = decode_from_copy(dcontext, instruction,
                                          fragment->start_pc + original, &decoded);
            if (next == NULL || next <= instruction || next > instruction + available) {
                valid = false;
                break;
            }
            uint length = (uint)(next - instruction);
            bool branch = (instr_is_ubr(&decoded) || instr_is_cbr(&decoded)) &&
                !instr_is_mbr(&decoded);
            if (node->kind == SHARED_BRANCH || node->kind == SHARED_EXIT) {
                int opcode = instr_get_opcode(&decoded);
                if (opcode == OP_jmp_short)
                    opcode = OP_jmp;
                else if (opcode >= OP_jo_short && opcode <= OP_jnle_short)
                    opcode += OP_jo - OP_jo_short;
                valid = branch && length == node->length &&
                    (opcode == OP_jmp || (opcode >= OP_jo && opcode <= OP_jnle)) &&
                    node->body_length == (opcode == OP_jmp ? 5 : 6);
                if (node->kind == SHARED_EXIT) {
                    valid = valid && stub != NULL && stub->cti_offset == original &&
                        !LINKSTUB_CBR_FALLTHROUGH(stub->flags) &&
                        !instr_is_cti_short(&decoded) && node->target == exits;
                    if (valid) {
                        stub = LINKSTUB_NEXT_EXIT(stub);
                        ++exits;
                    }
                } else {
                    byte *target =
                        branch ? opnd_get_pc(instr_get_target(&decoded)) : NULL;
                    int target_index =
                        shared_instruction_index(nodes, layout->count, node->target);
                    valid = valid && target == fragment->start_pc + node->target &&
                        target_index >= 0 &&
                        (nodes[target_index].original == node->target ||
                         nodes[target_index].kind == SHARED_COPY);
                }
            } else {
                valid = !branch &&
                    shared_instruction_kind(&decoded, fragment) == node->kind &&
                    node->target == 0 &&
                    (node->kind != SHARED_PRIVATE || !instr_is_cti(&decoded) ||
                     length == node->length);
                if (original == node->original)
                    valid = valid &&
                        node->body_length == (node->kind == SHARED_PRIVATE ? 5 : length);
            }
            original += length;
        }
        if (node->kind == SHARED_COPY)
            shared_bytes += node->length;
        uint body_length = node->kind == SHARED_COPY ? node->length : node->body_length;
        if (body > restore->content_size || body_length > restore->content_size - body) {
            valid = false;
            break;
        }
        body += body_length;
        if (node->kind == SHARED_PRIVATE || node->kind == SHARED_EXIT) {
            uint length = node->kind == SHARED_PRIVATE ? node->length + 5 : 5;
            valid = valid && node->island == restore->private_base + island &&
                island <= layout->island_size && length <= layout->island_size - island;
            island += length;
        } else {
            valid = valid && node->island == 0;
        }
    }
    /* COPY runs can contain internal branch targets. Require an actual decoded
     * boundary, not merely a coordinate inside their combined byte span. */
    for (uint i = 0; i < layout->count && valid; ++i) {
        if (nodes[i].kind != SHARED_BRANCH)
            continue;
        int target_index =
            shared_instruction_index(nodes, layout->count, nodes[i].target);
        if (target_index < 0) {
            valid = false;
            break;
        }
        uint cursor = nodes[target_index].original;
        uint end = cursor + nodes[target_index].length;
        while (cursor < nodes[i].target && valid) {
            byte instruction[MAX_INSTR_LENGTH] = { 0 };
            uint available = MIN(sizeof(instruction), end - cursor);
            memcpy(instruction, fragment->start_pc + cursor, available);
            instr_reset(dcontext, &decoded);
            byte *next = decode_from_copy(dcontext, instruction,
                                          fragment->start_pc + cursor, &decoded);
            valid = next != NULL && next > instruction && next <= instruction + available;
            if (valid)
                cursor += (uint)(next - instruction);
        }
        valid = valid && cursor == nodes[i].target;
    }
    instr_free(dcontext, &decoded);
    if (!valid || original != layout->original_size || body != restore->content_size ||
        island != layout->island_size || stub != NULL || exits == 0 ||
        shared_bytes <= 5 || nodes[layout->count - 1].kind != SHARED_EXIT)
        return false;
    byte digest[MD5_RAW_BYTES];
    shared_recipe_digest(fragment, fragment->start_pc, nodes, layout->count, digest);
    return memcmp(digest, fragment->shared_anchor->digest, sizeof(digest)) == 0;
}
#endif

DR_API
dr_shared_fragment_rebind_status_t
dr_shared_fragment_rebind_validate(
    app_pc tag, uint emission_id, const byte proof[DR_SHARED_FRAGMENT_PROOF_SIZE],
    const byte body_identity[DR_SHARED_FRAGMENT_BODY_IDENTITY_SIZE],
    const dr_shared_fragment_restore_t *restore)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (tag == NULL || emission_id == 0 || proof == NULL || body_identity == NULL ||
        dcontext == NULL || dcontext == GLOBAL_DCONTEXT ||
        !fragment_shared_provider_enabled())
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (!try_recursive_lock(&change_linking_lock))
        return DR_SHARED_FRAGMENT_REBIND_BUSY;
    fragment_t *fragment = fragment_lookup_shared_bb(dcontext, tag);
    bool valid = fragment != NULL &&
        !TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_IS_TRACE | FRAG_COARSE_GRAIN |
                     FRAG_WAS_DELETED | FRAG_CANNOT_DELETE,
                 fragment->flags) &&
        fragment->shared_view == NULL && fragment->shared_anchor != NULL;
    if (valid) {
        const fragment_shared_anchor_t *anchor = fragment->shared_anchor;
        valid = anchor->serial == emission_id &&
            anchor->original_size == fragment->size &&
            memcmp(proof, anchor->proof, sizeof(anchor->proof)) == 0 &&
            memcmp(body_identity, anchor->body_identity, sizeof(anchor->body_identity)) ==
                0 &&
            shared_restore_validate(dcontext, fragment, restore);
    }
    release_recursive_lock(&change_linking_lock);
    return valid ? DR_SHARED_FRAGMENT_REBIND_AVAILABLE : DR_SHARED_FRAGMENT_REBIND_ABSENT;
#else
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
#endif
}

DR_API
byte *
dr_decode_fragment_instruction(void *drcontext, byte *cache_start_pc, byte *pc,
                               instr_t *instruction)
{
    dcontext_t *dcontext = drcontext;
    if (dcontext == NULL || cache_start_pc == NULL || pc == NULL || instruction == NULL)
        return NULL;
    fragment_t wrapper;
    fragment_t *fragment = fragment_pclookup(dcontext, cache_start_pc, &wrapper);
    if (fragment == NULL)
        return NULL;
    if (TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_COARSE_GRAIN, fragment->flags) ||
        fragment->shared_view == NULL)
        return decode(dcontext, pc, instruction);
    fragment_shared_view_t *view = fragment->shared_view;
    if (pc < fragment->start_pc || pc - fragment->start_pc > UINT_MAX)
        return NULL;
    if (pc < FCACHE_ENTRY_PC(fragment))
        return decode(dcontext, pc, instruction);
    int index = shared_instruction_index(view->instructions, view->count,
                                         (uint)(pc - fragment->start_pc));
    if (index < 0)
        return NULL;
    const shared_instruction_t *node = &view->instructions[index];
    uint within = (uint)(pc - fragment->start_pc) - node->original;
    byte *actual = node->kind == SHARED_EXIT
        ? fragment->start_pc + view->exits[node->target]
        : view->mapping +
            (node->kind == SHARED_PRIVATE ? node->island + within : node->body + within);
    byte *next = decode(dcontext, actual, instruction);
    if (next == NULL)
        return NULL;
    uint length = node->kind == SHARED_COPY || node->kind == SHARED_PRIVATE
        ? (uint)(next - actual)
        : node->length;
    if (within + length > node->length)
        return NULL;
    if (node->kind == SHARED_BRANCH) {
        instr_set_raw_bits_valid(instruction, false);
        int opcode = instr_get_opcode(instruction);
        if (length == 2) {
            if (opcode == OP_jmp)
                instr_set_opcode(instruction, OP_jmp_short);
            else if (opcode >= OP_jo && opcode <= OP_jnle)
                instr_set_opcode(instruction, opcode + OP_jo_short - OP_jo);
        }
        instr_set_target(instruction, opnd_create_pc(fragment->start_pc + node->target));
    }
    return pc + length;
}

cache_pc
fragment_shared_original_pc(fragment_t *fragment, cache_pc pc)
{
    if (TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_COARSE_GRAIN, fragment->flags))
        return pc;
    fragment_shared_view_t *view = fragment->shared_view;
    if (view == NULL)
        return pc;
    if ((pc < view->mapping || pc >= view->mapping + view->body_size) &&
        (pc < view->private_start || pc >= view->private_start + view->private_size)) {
        if (view->compact_frame && pc >= fragment->start_pc &&
            pc < fragment->start_pc + fragment->size) {
            for (uint i = 0; i < view->count; ++i) {
                const shared_instruction_t *node = &view->instructions[i];
                if (node->kind == SHARED_EXIT &&
                    pc >= fragment->start_pc + view->exits[node->target] &&
                    pc < fragment->start_pc + view->exits[node->target] + node->length)
                    return fragment->start_pc + node->original;
            }
        }
        return pc;
    }
    uint offset = (uint)(pc - view->mapping);
    for (uint i = 0; i < view->count; ++i) {
        const shared_instruction_t *node = &view->instructions[i];
        uint length = node->kind == SHARED_COPY ? node->length : node->body_length;
        if (offset >= node->body && offset < node->body + length)
            return fragment->start_pc + node->original +
                (node->kind == SHARED_COPY ? offset - node->body : 0);
        if (node->kind == SHARED_PRIVATE && offset >= node->island &&
            offset < node->island + node->length + 5) {
            return fragment->start_pc + node->original +
                (offset >= node->island + node->length ? node->length
                                                       : offset - node->island);
        }
        if (node->kind == SHARED_EXIT && offset >= node->island &&
            offset < node->island + 5)
            return fragment->start_pc + node->original;
    }
    /* Padding is deliberately non-executable (INT3). Never invent an app PC. */
    return pc;
}

cache_pc
fragment_shared_original_end(fragment_t *fragment)
{
    if (!TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_COARSE_GRAIN, fragment->flags) &&
        fragment->shared_view != NULL) {
        const shared_layout_t *layout =
            (const shared_layout_t *)fragment->shared_view->mapping;
        return fragment->start_pc + layout->original_size;
    }
    return fragment->start_pc + fragment->size;
}

void
fragment_shared_free(dcontext_t *dcontext, fragment_t *fragment)
{
    if (TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_COARSE_GRAIN, fragment->flags))
        return;
    /* Private thread fragments never own recipes. Their deletion mutex has a
     * later rank than the shared linking lock and must not acquire it here. */
    if (TESTANY(FRAG_SHARED, fragment->flags)) {
        acquire_recursive_lock(&change_linking_lock);
        shared_anchor_release(fragment);
        release_recursive_lock(&change_linking_lock);
    } else {
        ASSERT(fragment->shared_anchor == NULL);
    }
    fragment_shared_view_t *view = fragment->shared_view;
    if (view == NULL)
        return;
    fragment->shared_view = NULL;
    /* Called only at the existing fragment safe reclamation point, not when
     * outgoing links are first removed during lazy invalidation.
     */
    fcache_unregister_shared_view(view->registration);
    fcache_unregister_shared_view(view->private_registration);
    if (view->batch != NULL)
        shared_batch_release(view->batch, view->cell, view->member_span,
                             view->private_offset, view->span);
    else
        shared_arena_release(view->arena, view->cell);
    fragment_shared_retired(dcontext, view->token);
    global_heap_free(view,
                     (sizeof(*view) + view->exit_count * sizeof(*view->exits))
                         HEAPACCT(ACCT_FRAGMENT));
}

static bool
shared_encode_private_run(dcontext_t *dcontext, instr_t *decoded, byte *original,
                          byte *island, uint length, byte *successor)
{
    byte *end = original + length;
    while (original < end) {
        instr_reset(dcontext, decoded);
        byte *next = decode(dcontext, original, decoded);
        if (next == NULL || next > end)
            return false;
        uint size = (uint)(next - original);
        if (instr_encode_to_copy(dcontext, decoded, island, island) != island + size)
            return false;
        original = next;
        island += size;
    }
    return shared_relative_jump(island, island, successor);
}

/* Compare against this emission's own normalized bytes and relocation records.
 * The sealed file cannot supply extra relocation permissions. Unchanged spans
 * are compared directly, avoiding another full-size transformed scratch copy.
 */
static bool
shared_rebased_equal(const dr_shared_fragment_request_t *request,
                     const dr_shared_fragment_file_t *file, const byte *member)
{
    size_t previous = 0;
    for (size_t i = 0; i < request->relocation_count; ++i) {
        const dr_shared_fragment_relocation_t *relocation = &request->relocations[i];
        size_t offset = relocation->field_offset;
        if (relocation->reserved != 0 || offset < previous ||
            offset > request->content_size || request->content_size - offset < 4 ||
            relocation->target_offset >= request->private_island_size)
            return false;
        int64 normalized = request->prototype_private_offset + relocation->target_offset;
        int64 final = file->size + file->private_offset - file->member_offset +
            relocation->target_offset;
        if (relocation->kind == DR_SHARED_FRAGMENT_REL32_PRIVATE) {
            normalized -= (int64)offset + 4;
            final -= (int64)offset + 4;
            if (normalized != (int)normalized || final != (int) final)
                return false;
        } else if (relocation->kind != DR_SHARED_FRAGMENT_U32_PRIVATE || normalized < 0 ||
                   normalized > UINT_MAX || final < 0 || final > UINT_MAX) {
            return false;
        }
        uint original_word, final_word;
        memcpy(&original_word, request->code + offset, sizeof(original_word));
        memcpy(&final_word, member + offset, sizeof(final_word));
        if (original_word != (uint)normalized || final_word != (uint) final ||
            memcmp(member + previous, request->code + previous, offset - previous) != 0)
            return false;
        previous = offset + 4;
    }
    return request->relocation_count != 0 &&
        memcmp(member + previous, request->code + previous,
               request->content_size - previous) == 0;
}

#if defined(LINUX) && defined(X86) && defined(X64)
static uint
shared_layout_nodes(shared_instruction_t *nodes, uint count, uint code_offset,
                    uint *island_size)
{
    uint body_size = code_offset;
    *island_size = 0;
    for (uint i = 0; i < count; ++i) {
        shared_instruction_t *node = &nodes[i];
        node->body = body_size;
        body_size += node->kind == SHARED_COPY ? node->length : node->body_length;
        if (node->kind == SHARED_PRIVATE || node->kind == SHARED_EXIT) {
            node->island = *island_size;
            *island_size += node->kind == SHARED_PRIVATE ? node->length + 5 : 5;
        }
    }
    return body_size;
}

/* Shared by original emission and nonexecuting reconstruction. All instruction
 * bytes and relocation permissions come from the same normalized node rules. */
static bool
shared_encode_template(dcontext_t *dcontext, byte *original_pc, const byte *original_copy,
                       shared_instruction_t *nodes, const shared_layout_t *layout,
                       byte *mapping, uint body_size, uint island_base,
                       const ushort *exit_offsets,
                       dr_shared_fragment_relocation_t *relocations,
                       size_t *relocation_count)
{
    bool valid = true;
    bool compact_bindings = layout->schema == 11;
    uint count = layout->count;
    instr_t decoded;
    instr_init(dcontext, &decoded);
    memset(mapping, 0xcc, body_size);
    if (!compact_bindings)
        memset(mapping + island_base, 0xcc, layout->island_size);
    for (uint i = 0; i < count && valid; ++i) {
        shared_instruction_t *node = &nodes[i];
        byte *original = (byte *)original_copy + node->original;
        byte *body = mapping + node->body;
        instr_reset(dcontext, &decoded);
        decode_from_copy(dcontext, original, original_pc + node->original, &decoded);
        if (node->kind == SHARED_COPY) {
            memcpy(body, original, node->length);
            continue;
        }
        if (node->kind == SHARED_PRIVATE || node->kind == SHARED_EXIT)
            node->island += island_base;
        byte *island = mapping + node->island;
        if (node->kind == SHARED_PRIVATE) {
            valid = shared_relative_jump(body, body, island);
            if (!valid || i + 1 >= count ||
                (!compact_bindings &&
                 !shared_encode_private_run(dcontext, &decoded, original, island,
                                            node->length, mapping + nodes[i + 1].body))) {
                valid = false;
                break;
            }
        } else {
            int target_index = shared_instruction_index(nodes, count, node->target);
            if (node->kind != SHARED_EXIT && target_index < 0) {
                valid = false;
                break;
            }
            byte *target = node->kind == SHARED_EXIT
                ? island
                : mapping + nodes[target_index].body + node->target -
                    nodes[target_index].original;
            int opcode = instr_get_opcode(&decoded);
            if (opcode == OP_jmp_short)
                instr_set_opcode(&decoded, OP_jmp);
            else if (opcode >= OP_jo_short && opcode <= OP_jnle_short)
                instr_set_opcode(&decoded, opcode + OP_jo - OP_jo_short);
            instr_set_target(&decoded, opnd_create_pc(target));
            valid = instr_encode_to_copy(dcontext, &decoded, body, body) ==
                body + node->body_length;
            if (valid && node->kind == SHARED_EXIT && !compact_bindings)
                valid = shared_relative_jump(island, island,
                                             original_pc + exit_offsets[node->target]);
        }
    }
    if (!valid)
        goto done;
    memcpy(mapping, layout, sizeof(*layout));
    memcpy(mapping + sizeof(*layout), nodes, count * sizeof(*nodes));
    *relocation_count = 0;
    if (compact_bindings) {
        /* Metadata fields precede every encoded branch field. Keep the list
         * sorted without sorting or retaining a second relocation table. */
        for (uint pass = 0; pass < 2; ++pass) {
            for (uint i = 0; i < count; ++i) {
                const shared_instruction_t *node = &nodes[i];
                if (node->kind != SHARED_PRIVATE && node->kind != SHARED_EXIT)
                    continue;
                dr_shared_fragment_relocation_t *relocation =
                    &relocations[(*relocation_count)++];
                relocation->field_offset = pass == 0
                    ? sizeof(*layout) + i * sizeof(*node) +
                        offsetof(shared_instruction_t, island)
                    : node->body + node->body_length - sizeof(uint);
                relocation->kind = pass == 0 ? DR_SHARED_FRAGMENT_U32_PRIVATE
                                             : DR_SHARED_FRAGMENT_REL32_PRIVATE;
                relocation->target_offset = node->island - island_base;
                relocation->reserved = 0;
            }
        }
    }
done:
    instr_free(dcontext, &decoded);
    return valid;
}
#endif

DR_API
dr_shared_fragment_rebind_status_t
dr_shared_fragment_export(app_pc tag, uint emission_id,
                          dr_shared_fragment_export_t *result)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    dcontext_t *dcontext = get_thread_private_dcontext();
    if (tag == NULL || emission_id == 0 || result == NULL ||
        result->struct_size != sizeof(*result) || result->buffer == NULL ||
        !ALIGNED(result->buffer, sizeof(uint64)) ||
        result->capacity < DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
        result->capacity > 2 * DR_SHARED_FRAGMENT_BUNDLE_LIMIT || dcontext == NULL ||
        dcontext == GLOBAL_DCONTEXT || !provider.compact_private_bindings ||
        provider.capture_proof == NULL || DYNAMO_OPTION(satisfy_w_xor_x))
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;

    /* Read only the size first, then allocate outside the lifetime lock. The
     * second lookup below must still match the same nonrecycled emission. */
    if (!try_recursive_lock(&change_linking_lock))
        return DR_SHARED_FRAGMENT_REBIND_BUSY;
    fragment_t *current = fragment_lookup_shared_bb(dcontext, tag);
    size_t original_capacity = 0;
    if (current != NULL &&
        !TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_COARSE_GRAIN, current->flags) &&
        current->shared_anchor != NULL && current->shared_anchor->serial == emission_id)
        original_capacity = current->size;
    release_recursive_lock(&change_linking_lock);
    if (original_capacity == 0)
        return DR_SHARED_FRAGMENT_REBIND_ABSENT;

    /* One entry per possible original byte bounds all scratch independently of
     * instruction density. No heap allocator is entered while holding the
     * fragment lifetime lock, and no pointer into a live fragment escapes it. */
    typedef struct {
        ushort ordinal, stub_size;
        bool patchable;
    } export_exit_t;
    const size_t scratch_size = ALIGN_FORWARD(
        original_capacity *
            (sizeof(shared_instruction_t) + sizeof(export_exit_t) + sizeof(ushort) + 1),
        PAGE_SIZE);
    byte *scratch =
        heap_mmap(scratch_size, MEMPROT_READ | MEMPROT_WRITE, VMM_SPECIAL_MMAP);
    if (scratch == NULL)
        return DR_SHARED_FRAGMENT_REBIND_BUSY;
    memset(scratch, 0, scratch_size);
    shared_instruction_t *nodes = (shared_instruction_t *)scratch;
    export_exit_t *exits = (export_exit_t *)(nodes + original_capacity);
    ushort *boundaries = (ushort *)(exits + original_capacity);
    byte *original_copy = (byte *)(boundaries + original_capacity);
    fragment_t source_fragment = { 0 };
    dr_shared_fragment_snapshot_t snapshot = { 0 };
    byte expected_digest[MD5_RAW_BYTES];
    uint exit_count = 0, last_exit = 0, old_stub_size = 0;
    uint count = 0, original_end = 0, compact_end = 0, island_size = 0;
    bool valid = false;
    dr_shared_fragment_rebind_status_t status = DR_SHARED_FRAGMENT_REBIND_ABSENT;
    if (!try_recursive_lock(&change_linking_lock)) {
        status = DR_SHARED_FRAGMENT_REBIND_BUSY;
        goto release_scratch;
    }
    fragment_t *fragment = fragment_lookup_shared_bb(dcontext, tag);
    if (fragment != NULL &&
        !TESTANY(FRAG_FAKE | FRAG_IS_FUTURE | FRAG_IS_TRACE | FRAG_COARSE_GRAIN |
                     FRAG_WAS_DELETED | FRAG_CANNOT_DELETE | FRAG_32_BIT |
                     FRAG_X86_TO_X64 | FRAG_SELFMOD_SANDBOXED | FRAG_HAS_SYSCALL |
                     FRAG_HAS_RSEQ_ENDPOINT | FRAG_STARTS_RSEQ_REGION,
                 fragment->flags) &&
        fragment->shared_view == NULL && fragment->shared_anchor != NULL &&
        fragment->shared_anchor->serial == emission_id &&
        fragment->shared_anchor->original_size == fragment->size &&
        fragment->size == original_capacity) {
        source_fragment.start_pc = fragment->start_pc;
        source_fragment.size = fragment->size;
        source_fragment.prefix_size = fragment->prefix_size;
        source_fragment.flags = fragment->flags;
        source_fragment.shared_entry_size = fragment->shared_entry_size;
        snapshot.tag = fragment->tag;
        snapshot.emission_id = emission_id;
        snapshot.original_size = fragment->size;
        memcpy(snapshot.proof, fragment->shared_anchor->proof, sizeof(snapshot.proof));
        memcpy(snapshot.body_identity, fragment->shared_anchor->body_identity,
               sizeof(snapshot.body_identity));
        memcpy(expected_digest, fragment->shared_anchor->digest, sizeof(expected_digest));
        memcpy(original_copy, fragment->start_pc, fragment->size);
        old_stub_size = (uint)(fragment->start_pc + fragment->size -
                               fragment_body_end_pc(dcontext, fragment));
        valid = true;
        for (linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment); stub != NULL;
             stub = LINKSTUB_NEXT_EXIT(stub)) {
            uint offset = stub->cti_offset;
            if (offset < fragment->prefix_size || offset >= fragment->size ||
                LINKSTUB_CBR_FALLTHROUGH(stub->flags) ||
                (exit_count != 0 && offset <= last_exit) || exit_count == USHRT_MAX) {
                valid = false;
                break;
            }
            export_exit_t *exit = &exits[offset];
            exit->ordinal = (ushort)++exit_count;
            if (EXIT_HAS_STUB(stub->flags, fragment->flags) &&
                !TESTANY(LINK_SEPARATE_STUB, stub->flags)) {
                int size = exit_stub_size(
                    dcontext, EXIT_TARGET_TAG(dcontext, fragment, stub), fragment->flags);
                if (size <= 0 || size > USHRT_MAX) {
                    valid = false;
                    break;
                }
                exit->stub_size = (ushort)size;
                exit->patchable = is_patchable_exit_stub(dcontext, stub, fragment);
            }
            last_exit = offset;
        }
    }
    release_recursive_lock(&change_linking_lock);
    if (!valid || exit_count == 0)
        goto release_scratch;

    instr_t decoded;
    instr_init(dcontext, &decoded);
    /* The last real exit ends the original ilist. Stub-alignment padding is
     * outside that list and must not silently enter its captured byte digest. */
    byte instruction[MAX_INSTR_LENGTH] = { 0 };
    uint available = MIN(sizeof(instruction), source_fragment.size - last_exit);
    memcpy(instruction, original_copy + last_exit, available);
    byte *next = decode_from_copy(dcontext, instruction,
                                  source_fragment.start_pc + last_exit, &decoded);
    if (next == NULL || next <= instruction || next > instruction + available)
        goto free_decoded;
    original_end = last_exit + (uint)(next - instruction);
    compact_end = source_fragment.prefix_size + source_fragment.shared_entry_size;
    uint observed_exits = 0;
    for (uint offset = source_fragment.prefix_size; offset < original_end;) {
        memset(instruction, 0, sizeof(instruction));
        available = MIN(sizeof(instruction), original_end - offset);
        memcpy(instruction, original_copy + offset, available);
        instr_reset(dcontext, &decoded);
        next = decode_from_copy(dcontext, instruction, source_fragment.start_pc + offset,
                                &decoded);
        if (next == NULL || next <= instruction || next > instruction + available)
            goto free_decoded;
        uint length = (uint)(next - instruction);
        shared_instruction_t *node = &nodes[count++];
        node->original = (ushort)offset;
        node->length = (ushort)length;
        node->kind = exits[offset].ordinal == 0 ? SHARED_COPY : SHARED_EXIT;
        if (node->kind == SHARED_EXIT) {
            if (exits[offset].ordinal != ++observed_exits || instr_is_cti_short(&decoded))
                goto free_decoded;
            node->target = (ushort)(observed_exits - 1);
            if (PAD_FRAGMENT_JMPS(source_fragment.flags))
                compact_end += patchable_exit_cti_align_offs(
                    dcontext, &decoded, source_fragment.start_pc + compact_end);
            if (compact_end > offset)
                goto free_decoded;
            compact_end += length;
        }
        offset += length;
    }
    if (observed_exits != exit_count ||
        !shared_prepare_nodes(dcontext, &source_fragment, original_copy, nodes, &count,
                              boundaries))
        goto free_decoded;
    byte digest[MD5_RAW_BYTES];
    shared_recipe_digest(&source_fragment, original_copy, nodes, count, digest);
    if (memcmp(digest, expected_digest, sizeof(digest)) != 0)
        goto free_decoded;

    snapshot.retained_private_size = compact_end + old_stub_size + exit_count * 64 +
        sizeof(fragment_shared_view_t) + exit_count * sizeof(ushort) +
        2 * sizeof(fcache_shared_view_t);
    uint retained = compact_end;
    for (uint offset = source_fragment.prefix_size; offset < original_end; ++offset) {
        const export_exit_t *exit = &exits[offset];
        if (exit->ordinal == 0 || exit->stub_size == 0)
            continue;
        if (PAD_FRAGMENT_JMPS(source_fragment.flags) && exit->patchable) {
            /* Same pure alignment calculation as bytes_for_exitstub_alignment,
             * using only the scalar stub metadata copied under the lifetime lock. */
            retained +=
                (uint)ALIGN_SHIFT_SIZE(source_fragment.start_pc + retained +
                                           exit->stub_size - EXIT_STUB_PATCH_OFFSET,
                                       EXIT_STUB_PATCH_SIZE, PAD_JMPS_ALIGNMENT);
        }
        retained += exit->stub_size;
    }
    snapshot.retained_code_size = retained;
    if (retained >= source_fragment.size)
        goto free_decoded;
    const uint identity_size = sizeof(shared_layout_t) + count * sizeof(*nodes);
    const uint code_offset = ALIGN_FORWARD(identity_size, 16);
    const uint content_size =
        shared_layout_nodes(nodes, count, code_offset, &island_size);
    const uint code_size = ALIGN_FORWARD(content_size, PAGE_SIZE);
    const uint private_slot = ALIGN_FORWARD(island_size, 16);
    size_t relocation_count = 0;
    for (uint i = 0; i < count; ++i) {
        if (nodes[i].kind == SHARED_PRIVATE || nodes[i].kind == SHARED_EXIT)
            relocation_count += 2;
    }
    if (code_size > DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
        private_slot > DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
        (provider.require_private_saving && private_slot >= source_fragment.size) ||
        code_size > result->capacity ||
        relocation_count >
            (result->capacity - code_size) / sizeof(dr_shared_fragment_relocation_t))
        goto free_decoded;
    shared_layout_t layout = {
        0x58525244,  11,           count,       code_offset, content_size - code_offset,
        island_size, original_end, private_slot
    };
    dr_shared_fragment_relocation_t *relocations =
        (dr_shared_fragment_relocation_t *)(result->buffer + code_size);
    if (!shared_encode_template(dcontext, source_fragment.start_pc, original_copy, nodes,
                                &layout, result->buffer, code_size, code_size, NULL,
                                relocations, &relocation_count))
        goto free_decoded;
    result->snapshot = snapshot;
    result->isa_mode = DR_ISA_AMD64;
    result->fragment_flags = source_fragment.flags;
    result->code_size = code_size;
    result->content_size = content_size;
    result->identity_size = identity_size;
    result->relocation_offset = code_size;
    result->relocation_count = relocation_count;
    result->private_island_size = island_size;
    result->private_slot_size = private_slot;
    result->prototype_private_offset = code_size;
    status = DR_SHARED_FRAGMENT_REBIND_AVAILABLE;
free_decoded:
    instr_free(dcontext, &decoded);
release_scratch:
    shared_release_temporary(scratch, scratch_size, VMM_SPECIAL_MMAP);
    return status;
#else
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
#endif
}

static bool
shared_publish(dcontext_t *dcontext, fragment_t *fragment, instrlist_t *ilist,
               const shared_instruction_t *saved_nodes, uint saved_count,
               uint *unused_tail, bool *retry)
{
#if defined(LINUX) && defined(X86) && defined(X64)
    bool adopted = false;
    uint count = 0, body_size = 0, island_size = 0;
    uint original_offset = fragment->prefix_size;
    byte *mapping = NULL;
    bool compact_bindings = provider.compact_private_bindings;
    fragment_shared_arena_t *arena = NULL;
    fragment_shared_batch_t *batch = NULL;
    byte *prototype = NULL;
    size_t prototype_size = 0;
    uint cell = 0;
    uint span = 0;
    uint member_span = 0;
    uint private_offset = 0;
    bool arena_writing = false;
    bool valid = true;
    instr_t decoded;
    instr_init(dcontext, &decoded);
    if (saved_nodes == NULL) {
        for (instr_t *inst = instrlist_first(ilist); inst != NULL;
             inst = instr_get_next(inst)) {
            if (!instr_ok_to_emit(inst) || instr_length(dcontext, inst) == 0)
                continue;
            if (!instr_is_ubr(inst) && !instr_is_cbr(inst)) {
                for (int i = 0; i < instr_num_srcs(inst); ++i) {
                    if (shared_operand_targets_fragment(instr_get_src(inst, i), fragment))
                        goto done;
                }
                for (int i = 0; i < instr_num_dsts(inst); ++i) {
                    if (shared_operand_targets_fragment(instr_get_dst(inst, i), fragment))
                        goto done;
                }
            }
            ++count;
        }
        if (count <= 5)
            goto done;
    } else {
        count = saved_count;
    }
    size_t relocation_offset =
        ALIGN_FORWARD(count * (sizeof(shared_instruction_t) + sizeof(ushort)), 4);
    size_t node_allocation = ALIGN_FORWARD(
        relocation_offset +
            (compact_bindings ? count * 2 * sizeof(dr_shared_fragment_relocation_t) : 0),
        PAGE_SIZE);
    /* Keep large temporary buffers separate from persistent global-heap users:
     * dedicated mappings permit physical reclamation without heap fragmentation.
     */
    shared_instruction_t *nodes =
        heap_mmap(node_allocation, MEMPROT_READ | MEMPROT_WRITE, VMM_SPECIAL_MMAP);
    if (nodes == NULL)
        goto done;
    memset(nodes, 0, node_allocation);
    ushort *exit_offsets = (ushort *)(nodes + count);
    dr_shared_fragment_relocation_t *relocations =
        (dr_shared_fragment_relocation_t *)((byte *)nodes + relocation_offset);
    if (saved_nodes == NULL) {
        uint index = 0;
        for (instr_t *inst = instrlist_first(ilist); inst != NULL;
             inst = instr_get_next(inst)) {
            uint length = instr_ok_to_emit(inst) ? instr_length(dcontext, inst) : 0;
            if (length == 0)
                continue;
            shared_instruction_t *node = &nodes[index++];
            node->original = (ushort)original_offset;
            node->length = (ushort)length;
            node->kind = instr_is_exit_cti(inst) ? SHARED_EXIT : SHARED_COPY;
            original_offset += length;
        }
        if (!shared_prepare_nodes(dcontext, fragment, fragment->start_pc, nodes, &count,
                                  exit_offsets))
            goto free_nodes;
    } else {
        memcpy(nodes, saved_nodes, count * sizeof(*nodes));
        original_offset = nodes[count - 1].original + nodes[count - 1].length;
    }
    /* Original ilist coordinates are metadata, not an allocation bound. Keep
     * only entry and mutable exits/stubs in the ordinary private fcache slot.
     */
    uint compact_end = fragment->prefix_size + fragment->shared_entry_size;
    uint exits = 0;
    bool compact_frame = true;
    for (linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment); stub != NULL;
         stub = LINKSTUB_NEXT_EXIT(stub)) {
        if (LINKSTUB_CBR_FALLTHROUGH(stub->flags)) {
            compact_frame = false;
            break;
        }
        int node_index = shared_instruction_index(nodes, count, stub->cti_offset);
        if (node_index < 0 || nodes[node_index].kind != SHARED_EXIT) {
            compact_frame = false;
            break;
        }
        shared_instruction_t *node = &nodes[node_index];
        instr_reset(dcontext, &decoded);
        decode(dcontext, fragment->start_pc + node->original, &decoded);
        if (instr_is_cti_short(&decoded)) {
            compact_frame = false;
            break;
        }
        if (PAD_FRAGMENT_JMPS(fragment->flags))
            compact_end += patchable_exit_cti_align_offs(
                dcontext, &decoded, fragment->start_pc + compact_end);
        if (compact_end > node->original) {
            compact_frame = false;
            break;
        }
        node->target = (ushort)exits;
        exit_offsets[exits] = (ushort)compact_end;
        compact_end += node->length;
        ++exits;
    }
    uint old_stub_size = (uint)(fragment->start_pc + fragment->size -
                                fragment_body_end_pc(dcontext, fragment));
    const uint retained_code_size =
        shared_retained_code_size(dcontext, fragment, compact_end);
    if (retained_code_size >= fragment->size)
        compact_frame = false;
    if (!compact_frame) {
        /* Keeping the entire original body while adding a shared copy cannot
         * save memory, even with multiple consumers. Decline before allocating
         * canonical code, private islands or provider ownership state.
         */
        goto free_nodes;
    }
    const size_t identity_size = sizeof(shared_layout_t) + count * sizeof(*nodes);
    const uint code_offset = ALIGN_FORWARD(identity_size, 16);
    body_size = shared_layout_nodes(nodes, count, code_offset, &island_size);
    const uint code_size = body_size - code_offset;
    const uint content_size = body_size;
    body_size = ALIGN_FORWARD(body_size, PAGE_SIZE);
    bool packed = compact_bindings ||
        (provider.pack_small_fragments && body_size == PAGE_SIZE &&
         island_size <= content_size);
    const uint private_slot = compact_bindings ? ALIGN_FORWARD(island_size, 16)
        : packed                               ? ALIGN_FORWARD(content_size, 16)
                                               : shared_private_cell_size(island_size);
    if (compact_bindings &&
        (body_size > DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
         private_slot > DR_SHARED_FRAGMENT_BUNDLE_LIMIT))
        goto free_nodes;
    /* This opt-in provider policy is decided before any canonical/private
     * arena is committed or encoded. It is exactly the slot later reported to
     * request(), not an estimate of physical or whole-family memory savings.
     */
    if (provider.require_private_saving && private_slot >= fragment->size)
        goto free_nodes;
    byte *private_start;
    if (packed) {
        span = private_slot;
        prototype_size = compact_bindings
            ? body_size + ALIGN_FORWARD(private_slot, PAGE_SIZE)
            : 2 * PAGE_SIZE;
        prototype = heap_mmap_reserve(
            prototype_size, compact_bindings ? body_size : prototype_size,
            MEMPROT_READ | MEMPROT_WRITE, VMM_CACHE | VMM_REACHABLE);
        mapping = prototype;
        private_start = mapping + body_size;
    } else {
        arena = shared_arena_acquire(body_size, island_size, nodes, count, &cell);
        if (arena == NULL)
            goto free_nodes;
        arena_writing = true;
        mapping = arena->base + (size_t)cell * body_size;
        private_start = arena->private_base + (size_t)cell * arena->cell_size;
    }
    uint island_base = (uint)(private_start - mapping);
    shared_layout_t layout = { 0x58525244,      compact_bindings ? 11 : packed ? 9 : 10,
                               count,           code_offset,
                               code_size,       island_size,
                               original_offset, packed ? span : arena->cell_size };
    size_t relocation_count = 0;
    if (!shared_encode_template(dcontext, fragment->start_pc, fragment->start_pc, nodes,
                                &layout, mapping, body_size, island_base, exit_offsets,
                                relocations, &relocation_count))
        goto free_mapping;
    if (!packed) {
        set_protection(arena->private_base,
                       ALIGN_FORWARD(arena->cell_size * arena->cells, PAGE_SIZE),
                       MEMPROT_READ | MEMPROT_EXEC);
        release_recursive_lock(&change_linking_lock);
        arena_writing = false;
    }
    /* The original symbolic check and emitted lowering have succeeded. Capture
     * a durable, nonrecycled identity before provider lock or budget outcomes. */
    if (saved_nodes == NULL && provider.capture_proof != NULL &&
        TESTANY(FRAG_SHARED, fragment->flags)) {
        byte proof[DR_SHARED_FRAGMENT_PROOF_SIZE] = { 0 };
        if (provider.capture_proof(dcontext, ilist, proof)) {
            acquire_recursive_lock(&change_linking_lock);
            if (fragment->shared_anchor == NULL && recipe_serial != UINT_MAX) {
                fragment_shared_anchor_t *anchor =
                    global_heap_alloc(sizeof(*anchor) HEAPACCT(ACCT_FRAGMENT));
                memset(anchor, 0, sizeof(*anchor));
                memcpy(anchor->proof, proof, sizeof(proof));
                anchor->serial = ++recipe_serial;
                anchor->original_size = fragment->size;
                shared_recipe_digest(fragment, fragment->start_pc, nodes, count,
                                     anchor->digest);
                fragment->shared_anchor = anchor;
                anchor_live_size += sizeof(*anchor);
            }
            release_recursive_lock(&change_linking_lock);
        }
    }
    if (provider.restore_layout != NULL && fragment->shared_anchor == NULL)
        goto free_mapping;
    dr_shared_fragment_capture_t capture = { { 0 }, { 0 }, false };
    dr_shared_fragment_request_t request = {
        sizeof(request),
        fragment->tag,
        DR_ISA_AMD64,
        fragment->flags,
        mapping,
        identity_size,
        mapping,
        body_size,
        packed ? content_size : body_size,
        fragment->size,
        (compact_frame ? compact_end + old_stub_size + exits * 64 : fragment->size) +
            sizeof(fragment_shared_view_t) + exits * sizeof(ushort) +
            2 * sizeof(fcache_shared_view_t),
        island_size,
        private_slot,
        packed ? private_slot : MAX(PAGE_SIZE, private_slot),
        ilist,
        compact_bindings ? relocations : NULL,
        relocation_count,
        compact_bindings ? island_base : 0,
        saved_nodes == NULL ? NULL : fragment->shared_anchor->proof,
        0,
        0,
        0,
        fragment->shared_anchor == NULL ? 0 : fragment->shared_anchor->serial,
        &capture,
        retained_code_size
    };
    acquire_recursive_lock(&change_linking_lock);
    request.retained_recipe_size = fragment->shared_anchor == NULL
        ? 0
        : sizeof(fragment_shared_anchor_t) +
            (fragment->shared_anchor->recipe == NULL
                 ? 0
                 : fragment->shared_anchor->recipe->allocation);
    request.recipe_storage_size =
        recipe_arena == NULL ? 0 : DR_SHARED_FRAGMENT_BUNDLE_LIMIT;
    request.recipe_live_size =
        recipe_live_size + anchor_live_size + sizeof(recipe_occupied);
    release_recursive_lock(&change_linking_lock);
    dr_shared_fragment_file_t file;
    const dr_shared_fragment_status_t status =
        fragment_shared_request(dcontext, &request, &file);
    if (retry != NULL)
        *retry = status == DR_SHARED_FRAGMENT_DEFER;
    acquire_recursive_lock(&change_linking_lock);
    if (saved_nodes == NULL && fragment->shared_anchor != NULL) {
        if (capture.valid) {
            memcpy(fragment->shared_anchor->proof, capture.proof, sizeof(capture.proof));
            memcpy(fragment->shared_anchor->body_identity, capture.body_identity,
                   sizeof(capture.body_identity));
        } else if (provider.restore_layout != NULL ||
                   status == DR_SHARED_FRAGMENT_DECLINED) {
            shared_anchor_release(fragment);
        }
    }
    valid = saved_nodes == NULL || provider.restore_layout == NULL ||
        (capture.valid &&
         memcmp(fragment->shared_anchor->body_identity, capture.body_identity,
                sizeof(capture.body_identity)) == 0 &&
         memcmp(fragment->shared_anchor->proof, capture.proof, sizeof(capture.proof)) ==
             0);
    release_recursive_lock(&change_linking_lock);
    if (!valid) {
        if (status == DR_SHARED_FRAGMENT_READY)
            fragment_shared_file_finished(dcontext, file.token, false);
        goto free_mapping;
    }
    /* Do not evict a pending producer's recipe for an emission the provider
     * cannot retain. Replay already owns its original recipe and never saves
     * another copy. Counts above describe storage before this callback. */
    if (saved_nodes == NULL && status != DR_SHARED_FRAGMENT_DECLINED) {
        const size_t mandatory =
            request.retained_private_size + request.private_slot_size;
        const uint saving = request.original_private_size > mandatory
            ? (uint)(request.original_private_size - mandatory)
            : 0;
        shared_recipe_save(fragment, nodes, count, island_base, saving);
    }
    if (status != DR_SHARED_FRAGMENT_READY)
        goto free_mapping;
    uint64 file_size = 0;
    size_t compare_size = file.size;
    byte *comparison = NULL;
    /* Linux F_GET_SEALS=1034, and the four immutable-content seals occupy
     * bits 0..3. Numeric ABI constants also work with older libc headers.
     */
    int seals = (int)dynamorio_syscall(SYS_fcntl, 3, file.fd, 1034, 0);
    if (seals >= 0 && (seals & 15) == 15 &&
        os_get_file_size_by_handle(file.fd, &file_size) && file.offset <= file_size &&
        file.size <= file_size - file.offset)
        comparison =
            os_map_file(file.fd, &compare_size, file.offset, NULL, MEMPROT_READ, 0);
    valid = comparison != NULL && compare_size == file.size &&
        (compact_bindings
             ? shared_rebased_equal(&request, &file, comparison + file.member_offset)
             : (packed ? ALIGNED(file.member_offset, 16) &&
                        span <= body_size - file.member_offset
                       : file.member_offset == 0) &&
                 memcmp(comparison + file.member_offset, mapping, request.content_size) ==
                     0);
    if (valid && packed) {
        member_span = ALIGN_FORWARD(request.content_size, 16);
        private_offset = compact_bindings ? file.private_offset : file.member_offset;
        batch = shared_batch_acquire(&file, member_span, span);
        valid = batch != NULL;
        if (valid) {
            cell = file.member_offset;
            mapping = batch->base + cell;
            private_start = batch->base + batch->body_size + private_offset;
            for (uint i = 0; i < count && valid; ++i) {
                const shared_instruction_t *node = &nodes[i];
                byte *island = private_start + node->island - island_base;
                if (node->kind == SHARED_PRIVATE) {
                    valid = i + 1 < count &&
                        shared_encode_private_run(
                                dcontext, &decoded, fragment->start_pc + node->original,
                                island, node->length, mapping + nodes[i + 1].body);
                } else if (node->kind == SHARED_EXIT) {
                    valid = shared_relative_jump(
                        island, island, fragment->start_pc + exit_offsets[node->target]);
                }
            }
            valid &= set_protection(batch->base + batch->body_size, batch->private_size,
                                    MEMPROT_READ | MEMPROT_EXEC);
            release_recursive_lock(&change_linking_lock);
        }
    } else if (valid) {
        size_t shared_size = body_size;
        valid = os_map_file(file.fd, &shared_size, file.offset, mapping,
                            MEMPROT_READ | MEMPROT_EXEC,
                            MAP_FILE_FIXED | MAP_FILE_VMM_COMMIT) == mapping;
    }
    if (comparison != NULL)
        os_unmap_file(comparison, compare_size);
    byte entry_jump[5];
    uint original_entry = fragment->prefix_size + fragment->shared_entry_size;
    int entry_index = shared_instruction_index(nodes, count, original_entry);
    valid = valid && entry_index >= 0 &&
        shared_relative_jump(entry_jump, FCACHE_ENTRY_PC(fragment),
                             mapping + nodes[entry_index].body + original_entry -
                                 nodes[entry_index].original);
    if (!valid) {
        if (batch != NULL) {
            shared_batch_release(batch, cell, member_span, private_offset, span);
            batch = NULL;
        }
        fragment_shared_file_finished(dcontext, file.token, false);
        goto free_mapping;
    }
    if (prototype != NULL) {
        shared_release_temporary(prototype, prototype_size, VMM_CACHE | VMM_REACHABLE);
        prototype = NULL;
    }
    fragment_shared_view_t *view = global_heap_alloc(
        (sizeof(*view) + exits * sizeof(*view->exits)) HEAPACCT(ACCT_FRAGMENT));
    view->mapping = mapping;
    view->body_size = request.content_size;
    view->private_start = private_start;
    view->private_size = island_size;
    view->count = count;
    view->exit_count = exits;
    view->compact_frame = compact_frame;
    memcpy(view->exits, exit_offsets, exits * sizeof(*view->exits));
    view->instructions = (const shared_instruction_t *)(mapping + sizeof(layout));
    view->token = file.token;
    view->arena = arena;
    view->batch = batch;
    view->cell = cell;
    view->span = span;
    view->member_span = member_span;
    view->private_offset = private_offset;
    view->registration =
        fcache_register_shared_view(fragment, mapping, request.content_size);
    view->private_registration =
        fcache_register_shared_view(fragment, private_start, island_size);
    bool outgoing_linked =
        saved_nodes != NULL && TESTANY(FRAG_LINKED_OUTGOING, fragment->flags);
    if (outgoing_linked)
        unlink_fragment_outgoing(dcontext, fragment);
    fragment->shared_view = view;
    if (compact_frame) {
        byte *write_base = vmcode_get_writable_addr(fragment->start_pc);
        for (linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment); stub != NULL;
             stub = LINKSTUB_NEXT_EXIT(stub)) {
            int node_index = shared_instruction_index(nodes, count, stub->cti_offset);
            const shared_instruction_t *node = &nodes[node_index];
            instr_reset(dcontext, &decoded);
            decode(dcontext, fragment->start_pc + node->original, &decoded);
            ushort destination = exit_offsets[node->target];
            byte *target = fragment->start_pc + destination;
            if (EXIT_HAS_STUB(stub->flags, fragment->flags))
                instr_set_target(&decoded, opnd_create_pc(target));
            byte *end = instr_encode_to_copy(dcontext, &decoded, write_base + destination,
                                             target);
            ASSERT(end == write_base + destination + node->length);
            if (end != write_base + destination + node->length)
                dr_abort();
            stub->cti_offset = destination;
        }
        byte *cursor = fragment->start_pc + compact_end;
        for (linkstub_t *stub = FRAGMENT_EXIT_STUBS(fragment); stub != NULL;
             stub = LINKSTUB_NEXT_EXIT(stub)) {
            if (!EXIT_HAS_STUB(stub->flags, fragment->flags))
                continue;
            if (TESTANY(LINK_SEPARATE_STUB, stub->flags)) {
                patch_branch(FRAG_ISA_MODE(fragment->flags), EXIT_CTI_PC(fragment, stub),
                             EXIT_STUB_PC(dcontext, fragment, stub), false);
                continue;
            }
            if (PAD_FRAGMENT_JMPS(fragment->flags))
                cursor = pad_for_exitstub_alignment(dcontext, stub, fragment, cursor);
            if (LINKSTUB_NORMAL_DIRECT(stub->flags))
                ((direct_linkstub_t *)stub)->stub_pc = cursor;
            patch_branch(FRAG_ISA_MODE(fragment->flags), EXIT_CTI_PC(fragment, stub),
                         cursor + linkstub_unlink_entry_offset(dcontext, fragment, stub),
                         false);
            cursor += insert_exit_stub(dcontext, fragment, stub, cursor);
        }
        ASSERT(cursor == fragment->start_pc + retained_code_size);
        ASSERT(cursor <= fragment->start_pc + fragment->size);
        uint unused = fragment->size - (cursor - fragment->start_pc);
        if (unused_tail != NULL)
            *unused_tail = unused;
        else
            fcache_return_extra_space(dcontext, fragment, unused);
    }
    /* Initial emission is unpublished; replay holds the world stop. Every
     * fallible step completed before changing the prepared private body. */
    memcpy(vmcode_get_writable_addr(FCACHE_ENTRY_PC(fragment)), entry_jump,
           sizeof(entry_jump));
    if (outgoing_linked)
        link_fragment_outgoing(dcontext, fragment, false);
    acquire_recursive_lock(&change_linking_lock);
    shared_anchor_release(fragment);
    release_recursive_lock(&change_linking_lock);
    fragment_shared_file_finished(dcontext, file.token, true);
    adopted = true;
    shared_release_temporary(nodes, node_allocation, VMM_SPECIAL_MMAP);
    goto done;
free_mapping:
    if (arena_writing) {
        set_protection(arena->private_base,
                       ALIGN_FORWARD(arena->cell_size * arena->cells, PAGE_SIZE),
                       MEMPROT_READ | MEMPROT_EXEC);
        release_recursive_lock(&change_linking_lock);
    }
    if (batch != NULL)
        shared_batch_release(batch, cell, member_span, private_offset, span);
    if (arena != NULL)
        shared_arena_release(arena, cell);
    if (prototype != NULL)
        shared_release_temporary(prototype, prototype_size, VMM_CACHE | VMM_REACHABLE);
free_nodes:
    shared_release_temporary(nodes, node_allocation, VMM_SPECIAL_MMAP);
done:
    instr_free(dcontext, &decoded);
    return adopted;
#else
    return false;
#endif
}

void
fragment_shared_publish(dcontext_t *dcontext, fragment_t *fragment, instrlist_t *ilist)
{
    shared_publish(dcontext, fragment, ilist, NULL, 0, NULL, NULL);
}

bool
fragment_shared_rebind(dcontext_t *dcontext, fragment_t *fragment, uint recipe_id,
                       bool *retry)
{
    *retry = false;
#if defined(LINUX) && defined(X86) && defined(X64)
    ASSERT(dynamo_all_threads_synched);
    ASSERT(OWN_MUTEX(&all_threads_synch_lock) && OWN_MUTEX(&thread_initexit_lock));
    acquire_recursive_lock(&change_linking_lock);
    fragment_shared_anchor_t *anchor = fragment->shared_anchor;
    bool adopted = false;
    uint unused = 0;
    if (anchor != NULL && anchor->serial == recipe_id &&
        anchor->original_size == fragment->size && fragment->shared_view == NULL) {
        byte digest[MD5_RAW_BYTES];
        if (anchor->recipe != NULL) {
            const fragment_shared_recipe_layout_t *layout = anchor->recipe->layout;
            shared_recipe_digest(fragment, fragment->start_pc, layout->instructions,
                                 layout->count, digest);
            if (memcmp(digest, anchor->digest, sizeof(digest)) != 0)
                shared_anchor_release(fragment);
            else
                adopted = shared_publish(dcontext, fragment, NULL, layout->instructions,
                                         layout->count, &unused, retry);
        } else if (provider.restore_layout != NULL) {
            byte *buffer = heap_mmap(DR_SHARED_FRAGMENT_BUNDLE_LIMIT,
                                     MEMPROT_READ | MEMPROT_WRITE, VMM_SPECIAL_MMAP);
            if (buffer != NULL) {
                dr_shared_fragment_restore_t restore = { sizeof(restore), buffer,
                                                         DR_SHARED_FRAGMENT_BUNDLE_LIMIT,
                                                         0, 0 };
                dr_shared_fragment_rebind_status_t status = provider.restore_layout(
                    dcontext, fragment->tag, anchor->serial, anchor->proof,
                    anchor->body_identity, &restore);
                *retry = status == DR_SHARED_FRAGMENT_REBIND_BUSY;
                if (status == DR_SHARED_FRAGMENT_REBIND_AVAILABLE &&
                    restore.buffer == buffer &&
                    restore.capacity == DR_SHARED_FRAGMENT_BUNDLE_LIMIT &&
                    shared_restore_validate(dcontext, fragment, &restore)) {
                    const shared_layout_t *layout = (const shared_layout_t *)buffer;
                    adopted = shared_publish(
                        dcontext, fragment, NULL,
                        (const shared_instruction_t *)(buffer + sizeof(*layout)),
                        layout->count, &unused, retry);
                }
                shared_release_temporary(buffer, DR_SHARED_FRAGMENT_BUNDLE_LIMIT,
                                         VMM_SPECIAL_MMAP);
            }
        }
    }
    release_recursive_lock(&change_linking_lock);
    /* The cache allocator precedes the linking lock. Peers remain stopped, so
     * the final physical tail release cannot race an old execution. */
    if (adopted && unused != 0)
        fcache_return_extra_space(dcontext, fragment, unused);
    return adopted;
#else
    return false;
#endif
}
