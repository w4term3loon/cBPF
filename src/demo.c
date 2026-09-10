/* CBPF reference-machine examples. This IR is deliberately NOT Linux eBPF. */
#include "cbpf.h"
#include <inttypes.h>
#include <stdio.h>

#define I(op, dst, src, imm) { CBPF_##op, dst, src, imm }
#define LEN(a) (sizeof(a) / sizeof((a)[0]))

static const struct cbpf_insn valid_ab[] = {
    I(ACQUIRE,0,0,1), I(ACQUIRE,1,0,1), I(READ,0,0,0),
    I(RELEASE,0,0,0), I(READ,1,0,0), I(RELEASE,1,0,0), I(RETURN,0,0,0)
};
static const struct cbpf_insn stale_a_live_b[] = {
    I(ACQUIRE,0,0,1), I(ACQUIRE,1,0,1), I(RELEASE,0,0,0),
    I(READ,1,0,0), I(READ,0,0,0), I(RELEASE,1,0,0), I(RETURN,0,0,0)
};
static const struct cbpf_insn double_release[] = {
    I(ACQUIRE,0,0,1), I(COPY,1,0,0), I(RELEASE,0,0,0),
    I(RELEASE,1,0,0), I(RETURN,0,0,0)
};
static const struct cbpf_insn alias_spill[] = {
    I(ACQUIRE,0,0,1), I(SPILL,0,0,0), I(RELOAD,1,0,0),
    I(READ,1,0,0), I(RELEASE,1,0,0), I(READ,0,0,0), I(RETURN,0,0,0)
};
static const struct cbpf_insn null_branch[] = {
    I(ACQUIRE,0,0,0), I(BR_NULL,0,0,3), I(READ,0,0,0), I(RETURN,0,0,7)
};
static const struct cbpf_insn exhaustion[] = {
    I(ACQUIRE,0,0,1), I(RELEASE,0,0,0), I(ACQUIRE,1,0,1),
    I(RELEASE,1,0,0), I(ACQUIRE,2,0,1), I(RETURN,0,0,0)
};
static const struct cbpf_insn live_cleanup[] = {
    I(ACQUIRE,0,0,1), I(COPY,1,0,0), I(SPILL,0,1,0), I(RETURN,0,0,9)
};

static int example(const char *name, const struct cbpf_insn *p, size_t n,
                   enum cbpf_status status, enum cbpf_trap trap, size_t pc,
                   unsigned acquired, unsigned reads, unsigned releases,
                   unsigned cleanup, int64_t returned, int trace)
{
    struct cbpf_result r;
    cbpf_run(p, n, &r);
    printf("%s: status=%s trap=%s pc=%zu acquired=%u reads=%u release=%u "
           "cleanup=%u refs=%d return=%" PRId64 "\n", name,
           cbpf_status_name(r.status), cbpf_trap_name(r.trap), r.pc,
           r.acquired, r.reads, r.explicit_releases, r.cleanup_releases,
           r.object_refs, r.returned);
    if (trace) for (size_t i = 0; i < r.event_count; ++i) {
        const struct cbpf_event e = r.events[i];
        const char *kind = e.kind == CBPF_CLEANUP ? "cleanup" :
                           e.kind == CBPF_TRAP_EVENT ? "trap" : "step";
        printf("  %s pc=%zu op=%s token=%u refs=%d\n", kind, e.pc,
               cbpf_opcode_name(e.op), e.token, e.object_refs);
    }
    if (r.status != status || r.trap != trap || r.pc != pc ||
        r.acquired != acquired || r.reads != reads ||
        r.explicit_releases != releases || r.cleanup_releases != cleanup ||
        r.object_refs != 1 || r.returned != returned ||
        (reads && r.last_read != 42)) return 1;
    for (unsigned i = 0; i < acquired; ++i)
        if (r.explicit_by_cell[i] + r.cleanup_by_cell[i] != 1) return 1;
    return 0;
}

static int structural_controls(void)
{
    struct cbpf_insn p[] = { I(READ,0,0,0), I(RETURN,0,0,0) };
    const struct cbpf_insn unreachable_bad[] = {
        I(ACQUIRE,0,0,1), I(RETURN,0,0,7),
        I(READ,CBPF_REGS,0,0), I(RETURN,0,0,0)
    };
    struct cbpf_result r;
    /* A legal NULL read traps before any provider effect. */
    cbpf_run(p, LEN(p), &r);
    if (r.status != CBPF_TRAPPED || r.trap != CBPF_NULL || r.reads) return 1;
    p[0].dst = CBPF_REGS;
    if (cbpf_run(p, LEN(p), &r) != CBPF_INVALID) return 1;
    p[0] = (struct cbpf_insn)I(BR_NULL,0,0,0); /* Backward/self edge. */
    if (cbpf_run(p, LEN(p), &r) != CBPF_INVALID) return 1;
    p[0].op = (enum cbpf_opcode)99;
    if (cbpf_run(p, LEN(p), &r) != CBPF_INVALID) return 1;
    p[0] = (struct cbpf_insn)I(ACQUIRE,0,0,1);
    if (cbpf_run(p, 1, &r) != CBPF_INVALID || r.acquired ||
        r.object_refs != 1) return 1; /* Missing scalar return. */
    /* Validation precedes even the reachable acquisition and early return. */
    if (cbpf_run(unreachable_bad, LEN(unreachable_bad), &r) != CBPF_INVALID ||
        r.pc != 2 || r.trap != CBPF_NO_TRAP || r.event_count || r.acquired ||
        r.reads || r.explicit_releases || r.cleanup_releases || r.returned ||
        r.object_refs != 1) return 1;
    puts("structural_controls: passed; malformed input has no provider effects");
    return 0;
}

static int execution_boundaries(void)
{
    const struct cbpf_insn early_return[] = {
        I(ACQUIRE,0,0,1), I(RETURN,0,0,7), I(READ,0,0,0),
        I(RELEASE,0,0,0), I(ACQUIRE,1,0,1), I(RETURN,0,0,9)
    };
    struct cbpf_insn longest[CBPF_MAX_INSNS];
    struct cbpf_result r;
    cbpf_run(early_return, LEN(early_return), &r);
    if (r.status != CBPF_RETURNED || r.trap != CBPF_NO_TRAP || r.pc != 1 ||
        r.returned != 7 || r.acquired != 1 || r.reads || r.explicit_releases ||
        r.cleanup_releases != 1 || r.cleanup_by_cell[0] != 1 ||
        r.object_refs != 1 || r.event_count != 3 ||
        r.events[1].kind != CBPF_STEP || r.events[1].op != CBPF_RETURN ||
        r.events[2].kind != CBPF_CLEANUP || r.events[2].pc != 1) return 1;

    longest[0] = (struct cbpf_insn)I(ACQUIRE,0,0,1);
    longest[1] = (struct cbpf_insn)I(ACQUIRE,1,0,1);
    for (size_t i = 2; i + 1 < LEN(longest); ++i)
        longest[i] = (struct cbpf_insn)I(READ,0,0,0);
    longest[LEN(longest) - 1] = (struct cbpf_insn)I(RETURN,0,0,9);
    cbpf_run(longest, LEN(longest), &r);
    if (r.status != CBPF_RETURNED || r.trap != CBPF_NO_TRAP ||
        r.pc != LEN(longest) - 1 || r.returned != 9 || r.acquired != CBPF_CELLS ||
        r.reads != CBPF_MAX_INSNS - 3 || r.last_read != 42 ||
        r.explicit_releases || r.cleanup_releases != CBPF_CELLS ||
        r.object_refs != 1 || r.event_count != CBPF_MAX_EVENTS) return 1;
    for (size_t i = 0; i < LEN(longest); ++i)
        if (r.events[i].kind != CBPF_STEP || r.events[i].pc != i ||
            r.events[i].op != longest[i].op) return 1;
    for (unsigned i = 0; i < CBPF_CELLS; ++i) {
        const struct cbpf_event e = r.events[CBPF_MAX_INSNS + i];
        if (r.explicit_by_cell[i] || r.cleanup_by_cell[i] != 1 ||
            e.kind != CBPF_CLEANUP || e.op != CBPF_RELEASE ||
            e.pc != LEN(longest) - 1 || e.token != i + 1 ||
            e.object_refs != CBPF_CELLS - (int)i) return 1;
    }
    puts("execution_boundaries: passed; early return halts; maximum trace fits exactly");
    return 0;
}

static int conceptual_object_baseline(void)
{
    /* Plain host pointers stand for object authority without acquisition state.
     * The object stays live: this demonstrates a logical reference-use defect,
     * NOT allocator use-after-free or an executed CHERI attack. */
    struct { int value, refs; } object = {42, 1};
    int *a = &object.value, *b = &object.value;
    int stale_value;
    object.refs += 2; /* Two independent acquisitions of the same live object. */
    --object.refs;    /* Release A; the pointer alone does not encode this. */
    stale_value = *a;
    if (*b != 42 || object.refs != 2) return 1;
    --object.refs;
    printf("conceptual_object_baseline: stale_A_read=%d refs=%d "
           "(plain host pointers; no CHERI)\n", stale_value, object.refs);
    return stale_value != 42 || object.refs != 1;
}

int main(void)
{
    int failed = 0;
    puts("CBPF host reference semantics; tiny IR, not Linux eBPF/JIT or hardware isolation");
    failed |= example("valid_A_B", valid_ab, LEN(valid_ab),
        CBPF_RETURNED, CBPF_NO_TRAP, 6, 2, 2, 2, 0, 0, 0);
    failed |= example("release_A_use_B_stale_A", stale_a_live_b, LEN(stale_a_live_b),
        CBPF_TRAPPED, CBPF_STALE, 4, 2, 1, 1, 1, 0, 1);
    failed |= example("double_release", double_release, LEN(double_release),
        CBPF_TRAPPED, CBPF_STALE, 3, 1, 0, 1, 0, 0, 1);
    failed |= example("alias_spill", alias_spill, LEN(alias_spill),
        CBPF_TRAPPED, CBPF_STALE, 5, 1, 1, 1, 0, 0, 0);
    failed |= example("null_acquisition", null_branch, LEN(null_branch),
        CBPF_RETURNED, CBPF_NO_TRAP, 3, 0, 0, 0, 0, 7, 0);
    failed |= example("exhaustion_no_reuse", exhaustion, LEN(exhaustion),
        CBPF_TRAPPED, CBPF_EXHAUSTED, 4, 2, 0, 2, 0, 0, 0);
    failed |= example("live_alias_cleanup", live_cleanup, LEN(live_cleanup),
        CBPF_RETURNED, CBPF_NO_TRAP, 3, 1, 0, 0, 1, 9, 0);
    failed |= conceptual_object_baseline();
    failed |= structural_controls();
    failed |= execution_boundaries();
    puts(failed ? "CBPF examples: FAILED" : "CBPF examples: passed");
    return failed;
}
