#include "gate.h"
#include <string.h>

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheriintrin.h>
#endif

struct gate_object {
    volatile int value, references;
};
struct gate_cell {
    struct gate_object * volatile object;
};
/* These are capability-valued aliases in purecap, ordinary pointers on host.
 * No public view permits loading the object capability stored in its cell. */
typedef const struct gate_cell *gate_handle;
struct gate_state {
    struct gate_object object;
    struct gate_cell cells[CBPF_CELLS];
    gate_handle views[CBPF_CELLS];
};
enum gate_outcome {
    GATE_OK, GATE_NULL, GATE_STALE, GATE_EXHAUSTED, GATE_REPRESENTATION
};

static void record(struct cbpf_result *r, enum cbpf_event_kind kind,
                   enum cbpf_opcode op, size_t pc, unsigned token)
{
    /* Structural validation permits at most one event per forward step,
     * followed by at most CBPF_CELLS terminal cleanup events. */
    struct cbpf_event *e = &r->events[r->event_count++];
    *e = (struct cbpf_event){kind, op, pc, token, r->object_refs};
}

static int prepare_view(struct gate_cell *private, gate_handle *out)
{
#ifdef __CHERI_PURE_CAPABILITY__
    const size_t permissions = CHERI_PERM_LOAD | CHERI_PERM_GLOBAL;
    gate_handle view = cheri_bounds_set_exact(private, sizeof(*private));
    view = cheri_perms_and(view, permissions);
    /* Bounds preparation may return an untagged capability. Inspect it
     * before publishing a view or causing any provider acquisition effect. */
    if (!cheri_tag_get(view) || cheri_is_sealed(view) ||
        cheri_address_get(view) != cheri_address_get(private) ||
        cheri_base_get(view) != cheri_address_get(private) ||
        cheri_length_get(view) != sizeof(*private) ||
        (size_t)cheri_perms_get(view) != permissions)
        return 0;
    *out = view;
#else
    *out = private;
#endif
    return 1;
}

static int same_handle(gate_handle a, gate_handle b)
{
#ifdef __CHERI_PURE_CAPABILITY__
    return cheri_is_equal_exact(a, b);
#else
    return a == b;
#endif
}

/* The handle never supplies authority for a cell dereference. Trusted table
 * membership selects private authority. Exact purecap comparison also checks
 * the tag, bounds and permissions established when the view was prepared.
 * This lookup preserves the identity of consumed, non-NULL acquisitions. */
static enum gate_outcome identify(const struct gate_state *s, gate_handle view,
                                 unsigned acquired, unsigned *token)
{
    *token = 0;
    if (same_handle(view, NULL)) return GATE_OK;
    for (unsigned i = 0; i < acquired; ++i) {
        if (!same_handle(view, s->views[i])) continue;
        *token = i + 1;
        return GATE_OK;
    }
    return GATE_REPRESENTATION;
}

static int object_is_live(const struct gate_object *object)
{
#ifdef __CHERI_PURE_CAPABILITY__
    return cheri_tag_get(object);
#else
    return object != NULL;
#endif
}

static enum gate_outcome acquire(struct gate_state *s, int success,
                                 gate_handle *out, unsigned *token,
                                 struct cbpf_result *r,
                                 struct cbpf_gate_metrics *m)
{
    ++m->acquisitions;
    if (!success) { *out = NULL; return GATE_OK; }
    if (r->acquired == CBPF_CELLS) return GATE_EXHAUSTED;

    struct gate_cell *private = &s->cells[r->acquired];
    gate_handle view;
    if (!prepare_view(private, &view)) return GATE_REPRESENTATION;
    /* Preparation precedes the first effect for this acquisition. */
    private->object = &s->object;
    ++s->object.references;
    r->object_refs = s->object.references;
    s->views[r->acquired] = view;
    *token = ++r->acquired;
    *out = view;
#ifdef __CHERI_PURE_CAPABILITY__
    ++m->restricted_handles;
#endif
    return GATE_OK;
}

static enum gate_outcome read_field(struct gate_state *s, gate_handle view,
                                    unsigned *token, struct cbpf_result *r,
                                    struct cbpf_gate_metrics *m)
{
    ++m->reads;
    enum gate_outcome outcome = identify(s, view, r->acquired, token);
    if (outcome != GATE_OK) return outcome;
    if (!*token) return GATE_NULL;
    struct gate_object *object = s->cells[*token - 1].object;
    if (!object_is_live(object)) return GATE_STALE;
    r->last_read = object->value; /* Only a scalar leaves this gate. */
    ++r->reads;
    return GATE_OK;
}

/* Return whether a cell was actually consumed. Volatile cell storage and
 * provider accounting preserve the source order of these observable accesses.
 * This is synchronous code, not an atomic or concurrent release protocol. */
static int consume(struct gate_cell *private, unsigned token, int cleanup,
                   struct cbpf_result *r, struct cbpf_gate_metrics *m)
{
    struct gate_object *object = private->object;
    if (!object_is_live(object)) return 0;
#ifdef __CHERI_PURE_CAPABILITY__
    private->object = cheri_tag_clear(object); /* Cursor stays nonzero. */
    ++m->tag_clears;
#else
    private->object = NULL;
#endif
    --object->references; /* Provider effect follows stored-authority removal. */
    r->object_refs = object->references;
    if (cleanup) {
        ++m->cleanups;
        ++r->cleanup_releases;
        ++r->cleanup_by_cell[token - 1];
    } else {
        ++r->explicit_releases;
        ++r->explicit_by_cell[token - 1];
    }
    return 1;
}

static enum gate_outcome release(struct gate_state *s, gate_handle view,
                                 unsigned *token, struct cbpf_result *r,
                                 struct cbpf_gate_metrics *m)
{
    ++m->releases;
    enum gate_outcome outcome = identify(s, view, r->acquired, token);
    if (outcome != GATE_OK) return outcome;
    if (!*token) return GATE_NULL;
    return consume(&s->cells[*token - 1], *token, 0, r, m)
        ? GATE_OK : GATE_STALE;
}

enum cbpf_status cbpf_gate_run(const struct cbpf_insn *p, size_t n,
                              struct cbpf_result *r,
                              struct cbpf_gate_metrics *metrics)
{
    struct cbpf_gate_metrics local_metrics;
    struct cbpf_gate_metrics *m = metrics ? metrics : &local_metrics;
    memset(m, 0, sizeof(*m));
    m->cell_bytes = sizeof(struct gate_cell);
    m->handle_bytes = sizeof(gate_handle);
#ifdef __CHERI_PURE_CAPABILITY__
    m->purecap = 1;
#endif
    memset(r, 0, sizeof(*r));
    r->object_refs = 1;
    if (!cbpf_validate(p, n, &r->pc)) {
        r->status = CBPF_INVALID;
        return r->status;
    }

    /* No invocation state or provider effects precede complete validation. */
    struct gate_state state = {.object = {.value = 42, .references = 1}};
    gate_handle regs[CBPF_REGS] = {NULL}, spills[CBPF_SPILLS] = {NULL};
    for (size_t pc = 0; pc < n; ) {
        const struct cbpf_insn x = p[pc];
        size_t next = pc + 1;
        unsigned token = 0;
        enum gate_outcome outcome = GATE_OK;
        r->pc = pc;
        switch (x.op) {
        case CBPF_ACQUIRE:
            outcome = acquire(&state, (int)x.imm, &regs[x.dst], &token, r, m);
            break;
        case CBPF_COPY:
            regs[x.dst] = regs[x.src]; /* Whole capability assignment. */
            outcome = identify(&state, regs[x.dst], r->acquired, &token);
            break;
        case CBPF_SPILL:
            spills[x.dst] = regs[x.src];
            outcome = identify(&state, spills[x.dst], r->acquired, &token);
            break;
        case CBPF_RELOAD:
            regs[x.dst] = spills[x.src];
            outcome = identify(&state, regs[x.dst], r->acquired, &token);
            break;
        case CBPF_READ:
            outcome = read_field(&state, regs[x.dst], &token, r, m);
            break;
        case CBPF_RELEASE:
            outcome = release(&state, regs[x.dst], &token, r, m);
            break;
        case CBPF_BR_NULL:
            outcome = identify(&state, regs[x.dst], r->acquired, &token);
            if (outcome == GATE_OK && !token) next = (size_t)x.imm;
            break;
        case CBPF_RETURN:
            r->returned = x.imm;
            r->status = CBPF_RETURNED;
            record(r, CBPF_STEP, x.op, pc, 0);
            goto finish;
        default: /* Unreachable after structural validation. */
            r->status = CBPF_INVALID;
            goto finish;
        }
        if (outcome == GATE_REPRESENTATION) {
            ++m->representation_errors;
            r->status = CBPF_INVALID;
            goto finish;
        }
        if (outcome != GATE_OK) {
            r->status = CBPF_TRAPPED;
            r->trap = outcome == GATE_NULL ? CBPF_NULL :
                outcome == GATE_STALE ? CBPF_STALE : CBPF_EXHAUSTED;
            record(r, CBPF_TRAP_EVENT, x.op, pc, token);
            goto finish; /* No later program instruction runs after failure. */
        }
        record(r, CBPF_STEP, x.op, pc, token);
        pc = next;
    }
finish:
    for (unsigned i = 0; i < r->acquired; ++i) {
        if (consume(&state.cells[i], i + 1, 1, r, m))
            record(r, CBPF_CLEANUP, CBPF_RELEASE, r->pc, i + 1);
    }
    return r->status;
}
