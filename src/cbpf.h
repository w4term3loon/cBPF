/* CBPF: host reference semantics, not Linux eBPF, a JIT, or hardware isolation. */
#ifndef CBPF_H
#define CBPF_H

#include <stddef.h>
#include <stdint.h>

enum { CBPF_CELLS = 2, CBPF_REGS = 4, CBPF_SPILLS = 2,
       CBPF_MAX_INSNS = 64, CBPF_MAX_EVENTS = CBPF_MAX_INSNS + CBPF_CELLS };

/* ACQUIRE imm: 0 = injected NULL, 1 = successful provider acquisition.
 * SPILL dst is a slot; RELOAD src is a slot. BR_NULL imm is a forward PC.
 * READ/RELEASE/BR_NULL use dst. RETURN returns scalar imm, never a token. */
enum cbpf_opcode {
    CBPF_ACQUIRE, CBPF_COPY, CBPF_SPILL, CBPF_RELOAD, CBPF_READ,
    CBPF_RELEASE, CBPF_BR_NULL, CBPF_RETURN, CBPF_OPCODE_COUNT
};
struct cbpf_insn { enum cbpf_opcode op; unsigned dst, src; int64_t imm; };
enum cbpf_status { CBPF_RETURNED, CBPF_TRAPPED, CBPF_INVALID };
enum cbpf_trap { CBPF_NO_TRAP, CBPF_NULL, CBPF_STALE, CBPF_EXHAUSTED };
enum cbpf_event_kind { CBPF_STEP, CBPF_TRAP_EVENT, CBPF_CLEANUP };
struct cbpf_event {
    enum cbpf_event_kind kind;
    enum cbpf_opcode op;
    size_t pc;
    unsigned token;
    int object_refs;
};
struct cbpf_result {
    enum cbpf_status status;
    enum cbpf_trap trap;
    size_t pc;
    int64_t returned;
    unsigned acquired, reads, explicit_releases, cleanup_releases;
    int last_read, object_refs;
    unsigned explicit_by_cell[CBPF_CELLS], cleanup_by_cell[CBPF_CELLS];
    size_t event_count;
    struct cbpf_event events[CBPF_MAX_EVENTS];
};

/* Validate every instruction, including unreachable ones. No fixture matching.
 * Forward-only control flow and a final RETURN bound execution by program size. */
int cbpf_validate(const struct cbpf_insn *program, size_t count, size_t *bad_pc);
/* Each call starts a fresh invocation and object (value 42, baseline refcount 1).
 * Cells are protected abstract state: the IR cannot forge or edit tokens/cells.
 * This is a software-model premise, not isolation from hostile native C code.
 * result must be non-NULL and must not overlap the immutable program array. */
enum cbpf_status cbpf_run(const struct cbpf_insn *program, size_t count,
                         struct cbpf_result *result);
const char *cbpf_status_name(enum cbpf_status status);
const char *cbpf_trap_name(enum cbpf_trap trap);
const char *cbpf_opcode_name(enum cbpf_opcode op);

#endif
