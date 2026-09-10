/* Test-only adapter: flat int64_t arrays avoid duplicating C struct layouts in
 * Python. This exports observations, never mutable runtime state or handles. */
#include "../src/cbpf.h"
#include <limits.h>

#ifndef CBPF_CONFORMANCE_GATE
#define CBPF_CONFORMANCE_GATE 0
#endif
#if CBPF_CONFORMANCE_GATE
#include "../src/gate.h"
#endif

size_t cbpf_conformance_info(int64_t *out, size_t capacity)
{
    static const int64_t info[] = {
        CBPF_REGS, CBPF_SPILLS, CBPF_CELLS, CBPF_MAX_INSNS, CBPF_MAX_EVENTS,
        CBPF_ACQUIRE, CBPF_COPY, CBPF_SPILL, CBPF_RELOAD, CBPF_READ,
        CBPF_RELEASE, CBPF_BR_NULL, CBPF_RETURN,
        CBPF_RETURNED, CBPF_TRAPPED, CBPF_INVALID,
        CBPF_NO_TRAP, CBPF_NULL, CBPF_STALE, CBPF_EXHAUSTED,
        CBPF_STEP, CBPF_TRAP_EVENT, CBPF_CLEANUP, CBPF_CONFORMANCE_GATE
    };
    size_t n = sizeof(info) / sizeof(info[0]);
    if (capacity >= n) for (size_t i = 0; i < n; ++i) out[i] = info[i];
    return n;
}

/* Input: (opcode, dst, src, immediate) per instruction.
 * Output: status, trap, pc, scalar, acquired, reads, explicit, cleanup,
 * last_read, refs, per-cell explicit, per-cell cleanup, event count,
 * then (kind, opcode, pc, token, refs) per event. Returns words written. */
size_t cbpf_conformance_run(const int64_t *input, size_t count,
                            int64_t *output, size_t capacity)
{
    struct cbpf_insn program[CBPF_MAX_INSNS];
    struct cbpf_result r;
    size_t used = 0;
    if (count > CBPF_MAX_INSNS ||
        capacity < 11 + 2 * CBPF_CELLS + 5 * CBPF_MAX_EVENTS) return 0;
    for (size_t i = 0; i < count; ++i) {
        const int64_t *x = input + 4 * i;
        if (x[0] < 0 || x[0] >= CBPF_OPCODE_COUNT ||
            x[1] < 0 || x[1] > UINT_MAX ||
            x[2] < 0 || x[2] > UINT_MAX) return 0;
        program[i] = (struct cbpf_insn){(enum cbpf_opcode)x[0],
                                     (unsigned)x[1], (unsigned)x[2], x[3]};
    }
#if CBPF_CONFORMANCE_GATE
    cbpf_gate_run(program, count, &r, NULL);
#else
    cbpf_run(program, count, &r);
#endif
    if (r.event_count > CBPF_MAX_EVENTS) return 0;
    output[used++] = r.status;
    output[used++] = r.trap;
    output[used++] = (int64_t)r.pc;
    output[used++] = r.returned;
    output[used++] = r.acquired;
    output[used++] = r.reads;
    output[used++] = r.explicit_releases;
    output[used++] = r.cleanup_releases;
    output[used++] = r.last_read;
    output[used++] = r.object_refs;
    for (size_t i = 0; i < CBPF_CELLS; ++i) output[used++] = r.explicit_by_cell[i];
    for (size_t i = 0; i < CBPF_CELLS; ++i) output[used++] = r.cleanup_by_cell[i];
    output[used++] = (int64_t)r.event_count;
    for (size_t i = 0; i < r.event_count; ++i) {
        const struct cbpf_event *e = &r.events[i];
        output[used++] = e->kind;
        output[used++] = e->op;
        output[used++] = (int64_t)e->pc;
        output[used++] = e->token;
        output[used++] = e->object_refs;
    }
    return used;
}
