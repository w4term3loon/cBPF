#include "cbpf.h"
#include <string.h>

int cbpf_validate(const struct cbpf_insn *p, size_t n, size_t *bad_pc)
{
    size_t i = 0;
    if (!p || n == 0 || n > CBPF_MAX_INSNS) goto invalid;
    for (i = 0; i < n; ++i) {
        const struct cbpf_insn x = p[i];
        switch (x.op) {
        case CBPF_ACQUIRE:
            if (x.dst >= CBPF_REGS || (x.imm != 0 && x.imm != 1)) goto invalid;
            break;
        case CBPF_COPY:
            if (x.dst >= CBPF_REGS || x.src >= CBPF_REGS) goto invalid;
            break;
        case CBPF_SPILL:
            if (x.dst >= CBPF_SPILLS || x.src >= CBPF_REGS) goto invalid;
            break;
        case CBPF_RELOAD:
            if (x.dst >= CBPF_REGS || x.src >= CBPF_SPILLS) goto invalid;
            break;
        case CBPF_READ: case CBPF_RELEASE:
            if (x.dst >= CBPF_REGS) goto invalid;
            break;
        case CBPF_BR_NULL:
            if (x.dst >= CBPF_REGS || x.imm <= (int64_t)i ||
                x.imm >= (int64_t)n) goto invalid;
            break;
        case CBPF_RETURN: break;
        default: goto invalid;
        }
    }
    if (p[n - 1].op != CBPF_RETURN) { i = n - 1; goto invalid; }
    return 1;
invalid:
    if (bad_pc) *bad_pc = i;
    return 0;
}

static void record(struct cbpf_result *r, enum cbpf_event_kind kind,
                   enum cbpf_opcode op, size_t pc, unsigned token)
{
    /* At most one event per forward instruction, then two cleanup events. */
    struct cbpf_event *e = &r->events[r->event_count++];
    *e = (struct cbpf_event){ kind, op, pc, token, r->object_refs };
}

enum cbpf_status cbpf_run(const struct cbpf_insn *p, size_t n,
                         struct cbpf_result *r)
{
    unsigned regs[CBPF_REGS] = {0}, spills[CBPF_SPILLS] = {0};
    unsigned live[CBPF_CELLS] = {0};
    size_t pc;
    memset(r, 0, sizeof(*r));
    r->object_refs = 1; /* The modeled object remains allocated throughout. */
    if (!cbpf_validate(p, n, &r->pc)) {
        r->status = CBPF_INVALID;
        return r->status;
    }
    for (pc = 0; pc < n; ) {
        const struct cbpf_insn x = p[pc];
        size_t next = pc + 1;
        unsigned token = 0;
        r->pc = pc;
        switch (x.op) {
        case CBPF_ACQUIRE:
            if (!x.imm) { regs[x.dst] = 0; break; }
            if (r->acquired == CBPF_CELLS) {
                r->trap = CBPF_EXHAUSTED;
                goto trap;
            }
            token = ++r->acquired; /* No cell reuse, even after consumption. */
            live[token - 1] = 1;
            regs[x.dst] = token;
            ++r->object_refs;
            break;
        case CBPF_COPY:
            token = regs[x.dst] = regs[x.src];
            break;
        case CBPF_SPILL:
            token = spills[x.dst] = regs[x.src];
            break;
        case CBPF_RELOAD:
            token = regs[x.dst] = spills[x.src];
            break;
        case CBPF_READ: case CBPF_RELEASE:
            token = regs[x.dst];
            if (!token) { r->trap = CBPF_NULL; goto trap; }
            if (!live[token - 1]) { r->trap = CBPF_STALE; goto trap; }
            if (x.op == CBPF_READ) {
                ++r->reads;
                r->last_read = 42;
            } else {
                live[token - 1] = 0; /* Consume BEFORE the provider effect. */
                --r->object_refs;
                ++r->explicit_releases;
                ++r->explicit_by_cell[token - 1];
            }
            break;
        case CBPF_BR_NULL:
            token = regs[x.dst];
            if (!token) next = (size_t)x.imm;
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
        record(r, CBPF_STEP, x.op, pc, token);
        pc = next;
        continue;
trap:
        r->status = CBPF_TRAPPED;
        record(r, CBPF_TRAP_EVENT, x.op, pc, token);
        goto finish; /* No later program instruction executes. */
    }
finish:
    for (unsigned i = 0; i < r->acquired; ++i) {
        if (!live[i]) continue;
        live[i] = 0; /* Trusted terminal cleanup is a separate effect class. */
        --r->object_refs;
        ++r->cleanup_releases;
        ++r->cleanup_by_cell[i];
        record(r, CBPF_CLEANUP, CBPF_RELEASE, r->pc, i + 1);
    }
    return r->status;
}

const char *cbpf_status_name(enum cbpf_status s)
{
    switch (s) {
    case CBPF_RETURNED: return "returned";
    case CBPF_TRAPPED: return "trapped";
    case CBPF_INVALID: return "invalid";
    }
    return "unknown";
}
const char *cbpf_trap_name(enum cbpf_trap t)
{
    switch (t) {
    case CBPF_NO_TRAP: return "none";
    case CBPF_NULL: return "null";
    case CBPF_STALE: return "stale";
    case CBPF_EXHAUSTED: return "exhausted";
    }
    return "unknown";
}
const char *cbpf_opcode_name(enum cbpf_opcode op)
{
    static const char *const names[] = {
        "acquire", "copy", "spill", "reload", "read", "release", "br_null", "return"
    };
    return (unsigned)op < CBPF_OPCODE_COUNT ? names[op] : "invalid";
}
