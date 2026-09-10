/* Matched controls for the tiny-IR gate, not arbitrary native-code isolation. */
#define _POSIX_C_SOURCE 200809L
#include "gate.h"
#include <inttypes.h>
#include <stdio.h>

#if defined(__CHERI_PURE_CAPABILITY__)
#include <cheriintrin.h>
#define PURECAP 1
#else
#define PURECAP 0
#endif

#if defined(CBPF_GATE_GUEST)
#if !defined(__CHERI_PURE_CAPABILITY__)
#error "CBPF_GATE_GUEST requires a purecap target"
#endif
#include <sys/reboot.h>
#include <unistd.h>
#endif

#define I(op, dst, src, imm) { CBPF_##op, dst, src, imm }
#define LEN(a) (sizeof(a) / sizeof((a)[0]))

struct expectation {
    enum cbpf_status status;
    enum cbpf_trap trap;
    size_t pc;
    unsigned acquired, reads, releases, cleanups;
    int64_t returned;
    size_t events;
    unsigned explicit_mask, cleanup_mask;
};

static unsigned cases, matched;
static size_t cell_bytes, handle_bytes;

static int mismatch(const char *name, const char *field)
{
    fprintf(stderr, "CBPF_GATE mismatch case=%s field=%s\n", name, field);
    return 0;
}

static int equal_result(const char *name, const struct cbpf_result *a,
                        const struct cbpf_result *b)
{
    /* Compare values explicitly: struct padding is not observable semantics. */
#define SAME(field) do { if (a->field != b->field) \
    return mismatch(name, #field); } while (0)
    SAME(status); SAME(trap); SAME(pc); SAME(returned);
    SAME(acquired); SAME(reads); SAME(explicit_releases); SAME(cleanup_releases);
    SAME(last_read); SAME(object_refs); SAME(event_count);
    for (unsigned i = 0; i < CBPF_CELLS; ++i) {
        SAME(explicit_by_cell[i]); SAME(cleanup_by_cell[i]);
    }
    /* Both APIs zero unused entries; include those fixed-array fields too. */
    for (size_t i = 0; i < CBPF_MAX_EVENTS; ++i) {
        SAME(events[i].kind); SAME(events[i].op); SAME(events[i].pc);
        SAME(events[i].token); SAME(events[i].object_refs);
    }
#undef SAME
    return 1;
}

static int expected_result(const char *name, const struct cbpf_result *r,
                           const struct expectation *e)
{
    if (r->status != e->status || r->trap != e->trap || r->pc != e->pc ||
        r->acquired != e->acquired || r->reads != e->reads ||
        r->explicit_releases != e->releases || r->cleanup_releases != e->cleanups ||
        r->returned != e->returned || r->event_count != e->events ||
        r->object_refs != 1 || r->last_read != (e->reads ? 42 : 0))
        return mismatch(name, "direct_expectation");
    for (unsigned i = 0; i < CBPF_CELLS; ++i)
        if (r->explicit_by_cell[i] != ((e->explicit_mask >> i) & 1u) ||
            r->cleanup_by_cell[i] != ((e->cleanup_mask >> i) & 1u))
            return mismatch(name, "direct_per_cell_effects");
    return 1;
}

static int expected_metrics(const char *name, const struct cbpf_result *r,
                            const struct cbpf_gate_metrics *m)
{
    unsigned acquisitions = 0, reads = 0, releases = 0;
    for (size_t i = 0; i < r->event_count; ++i) {
        const struct cbpf_event *e = &r->events[i];
        if (e->kind == CBPF_CLEANUP) continue;
        acquisitions += e->op == CBPF_ACQUIRE;
        reads += e->op == CBPF_READ;
        releases += e->op == CBPF_RELEASE;
    }
    if (!cell_bytes) { cell_bytes = m->cell_bytes; handle_bytes = m->handle_bytes; }
    if (m->acquisitions != acquisitions || m->reads != reads ||
        m->releases != releases || m->cleanups != r->cleanup_releases ||
        m->purecap != PURECAP || m->representation_errors ||
        m->restricted_handles != (PURECAP ? r->acquired : 0) ||
        m->tag_clears != (PURECAP ? r->explicit_releases + r->cleanup_releases : 0) ||
        !m->cell_bytes || m->cell_bytes != cell_bytes ||
        m->handle_bytes != sizeof(void *) || m->handle_bytes != handle_bytes)
        return mismatch(name, "gate_metrics");
    return 1;
}

static void print_trace(const struct cbpf_insn *p, size_t n,
                        const struct cbpf_result *r)
{
    puts("CBPF_GATE trace=stale_spill_after_B program_begin");
    for (size_t pc = 0; pc < n; ++pc) {
        const struct cbpf_insn x = p[pc];
        printf("  %zu: ", pc);
        switch (x.op) {
        case CBPF_ACQUIRE: printf("r%u = acquire(%" PRId64 ")", x.dst, x.imm); break;
        case CBPF_COPY: printf("r%u = r%u", x.dst, x.src); break;
        case CBPF_SPILL: printf("spill[%u] = r%u", x.dst, x.src); break;
        case CBPF_RELOAD: printf("r%u = spill[%u]", x.dst, x.src); break;
        case CBPF_READ: case CBPF_RELEASE:
            printf("%s(r%u)", cbpf_opcode_name(x.op), x.dst); break;
        case CBPF_BR_NULL: printf("if r%u == NULL goto %" PRId64, x.dst, x.imm); break;
        case CBPF_RETURN: printf("return %" PRId64, x.imm); break;
        default: printf("invalid"); break;
        }
        putchar('\n');
    }
    puts("CBPF_GATE trace=stale_spill_after_B effects_begin");
    for (size_t i = 0; i < r->event_count; ++i) {
        const struct cbpf_event *e = &r->events[i];
        const char *kind = e->kind == CBPF_CLEANUP ? "cleanup" :
                           e->kind == CBPF_TRAP_EVENT ? "trap" : "step";
        printf("  %s pc=%zu op=%s token=%u refs=%d\n", kind, e->pc,
               cbpf_opcode_name(e->op), e->token, e->object_refs);
    }
    printf("CBPF_GATE trace=stale_spill_after_B status=%s trap=%s pc=%zu "
           "reads=%u explicit=%u cleanup=%u refs=%d\n",
           cbpf_status_name(r->status), cbpf_trap_name(r->trap), r->pc,
           r->reads, r->explicit_releases, r->cleanup_releases, r->object_refs);
}

static int check_case(const char *name, const struct cbpf_insn *p, size_t n,
                      const struct expectation *e, int trace)
{
    struct cbpf_result reference, gate;
    struct cbpf_gate_metrics metrics;
    enum cbpf_status reference_status = cbpf_run(p, n, &reference);
    enum cbpf_status gate_status = cbpf_gate_run(p, n, &gate, &metrics);
    int good = reference_status == reference.status && gate_status == gate.status;
    ++cases;
    good &= equal_result(name, &reference, &gate);
    good &= expected_result(name, &reference, e);
    good &= expected_result(name, &gate, e);
    if (gate.event_count <= CBPF_MAX_EVENTS)
        good &= expected_metrics(name, &gate, &metrics);
    else good = 0;
    if (trace && good) print_trace(p, n, &gate);
    if (good) ++matched;
    else fprintf(stderr, "CBPF_GATE failed_case=%u name=%s\n", cases, name);
    return !good;
}

enum family {
    VALID_AB, STALE_COPY, STALE_SPILL, REPEATED_RELEASE, NULL_BRANCH,
    CONSUMED_BRANCH, OVERWRITE_ALIAS, EXHAUSTION, NULL_READ, NULL_RELEASE,
    FAMILIES
};
static const char *const family_names[] = {
    "valid_A_B", "stale_copy_after_B", "stale_spill_after_B", "repeated_release",
    "null_acquisition_branch", "consumed_token_nonnull", "overwrite_last_alias",
    "exhaustion_cleanup", "null_read", "null_release"
};

static size_t build_case(struct cbpf_insn *p, enum family family,
                         unsigned a, unsigned b, unsigned c, unsigned d,
                         unsigned slot, struct expectation *e)
{
    size_t n = 0;
#define ADD(op, dst, src, imm) p[n++] = (struct cbpf_insn)I(op, dst, src, imm)
    if (family <= REPEATED_RELEASE) {
        ADD(ACQUIRE,a,0,1); ADD(ACQUIRE,b,0,1); ADD(COPY,c,a,0); ADD(SPILL,slot,a,0);
        if (family == VALID_AB) {
            ADD(READ,c,0,0); ADD(READ,b,0,0); ADD(RELOAD,d,slot,0);
            ADD(RELEASE,d,0,0); ADD(RELEASE,b,0,0); ADD(RETURN,0,0,7);
            *e = (struct expectation){CBPF_RETURNED,CBPF_NO_TRAP,9,2,2,2,0,7,10,3,0};
        } else {
            ADD(RELEASE,a,0,0); ADD(READ,b,0,0); ADD(RELOAD,d,slot,0);
            if (family == REPEATED_RELEASE) { ADD(RELEASE,d,0,0); }
            else { ADD(READ,family == STALE_COPY ? c : d,0,0); }
            ADD(RELEASE,b,0,0); ADD(RETURN,0,0,7);
            *e = (struct expectation){CBPF_TRAPPED,CBPF_STALE,7,2,1,1,1,0,9,1,2};
        }
    } else if (family == NULL_BRANCH) {
        ADD(ACQUIRE,a,0,0); ADD(COPY,c,a,0); ADD(SPILL,slot,c,0); ADD(RELOAD,d,slot,0);
        ADD(BR_NULL,d,0,7); ADD(READ,d,0,0); ADD(RETURN,0,0,-7);
        ADD(ACQUIRE,b,0,1); ADD(READ,b,0,0); ADD(RELEASE,b,0,0); ADD(RETURN,0,0,7);
        *e = (struct expectation){CBPF_RETURNED,CBPF_NO_TRAP,10,1,1,1,0,7,9,1,0};
    } else if (family == CONSUMED_BRANCH) {
        ADD(ACQUIRE,a,0,1); ADD(ACQUIRE,b,0,1); ADD(COPY,c,a,0); ADD(SPILL,slot,c,0);
        ADD(RELEASE,a,0,0); ADD(RELOAD,d,slot,0); ADD(BR_NULL,d,0,10);
        ADD(READ,b,0,0); ADD(READ,d,0,0); ADD(RELEASE,b,0,0); ADD(RETURN,0,0,7);
        *e = (struct expectation){CBPF_TRAPPED,CBPF_STALE,8,2,1,1,1,0,10,1,2};
    } else if (family == OVERWRITE_ALIAS) {
        ADD(ACQUIRE,a,0,1); ADD(COPY,c,a,0); ADD(SPILL,slot,c,0); ADD(ACQUIRE,b,0,1);
        ADD(ACQUIRE,a,0,0); ADD(COPY,c,a,0); ADD(SPILL,slot,a,0); ADD(RELOAD,d,slot,0);
        ADD(READ,b,0,0); ADD(RETURN,0,0,9);
        *e = (struct expectation){CBPF_RETURNED,CBPF_NO_TRAP,9,2,1,0,2,9,12,0,3};
    } else if (family == EXHAUSTION) {
        ADD(ACQUIRE,a,0,1); ADD(COPY,c,a,0); ADD(SPILL,slot,c,0); ADD(RELEASE,a,0,0);
        ADD(ACQUIRE,b,0,1); ADD(RELOAD,d,slot,0); ADD(ACQUIRE,d,0,1); ADD(RETURN,0,0,9);
        *e = (struct expectation){CBPF_TRAPPED,CBPF_EXHAUSTED,6,2,0,1,1,0,8,1,2};
    } else {
        ADD(ACQUIRE,b,0,1); ADD(ACQUIRE,a,0,0); ADD(COPY,c,a,0); ADD(SPILL,slot,c,0);
        ADD(RELOAD,d,slot,0);
        if (family == NULL_READ) { ADD(READ,d,0,0); }
        else { ADD(RELEASE,d,0,0); }
        ADD(READ,b,0,0); ADD(RETURN,0,0,9);
        *e = (struct expectation){CBPF_TRAPPED,CBPF_NULL,5,1,0,0,1,0,7,0,1};
    }
#undef ADD
    return n;
}

static int corpus(void)
{
    int failed = 0;
    unsigned permutations = 0, family_failures[FAMILIES] = {0};
    for (unsigned a = 0; a < CBPF_REGS; ++a)
    for (unsigned b = 0; b < CBPF_REGS; ++b)
    for (unsigned c = 0; c < CBPF_REGS; ++c)
    for (unsigned d = 0; d < CBPF_REGS; ++d) {
        if (a == b || a == c || a == d || b == c || b == d || c == d) continue;
        ++permutations;
        for (unsigned slot = 0; slot < CBPF_SPILLS; ++slot)
        for (enum family f = VALID_AB; f < FAMILIES; ++f) {
            struct cbpf_insn p[CBPF_MAX_INSNS];
            struct expectation e;
            size_t n = build_case(p, f, a, b, c, d, slot, &e);
            int bad = check_case(family_names[f], p, n, &e,
                                permutations == 1 && slot == 0 && f == STALE_SPILL);
            family_failures[f] += (unsigned)bad;
            failed |= bad;
        }
    }
    if (permutations != 24) failed = 1;
    for (unsigned f = 0; f < FAMILIES; ++f)
        printf("CBPF_GATE family=%s cases=48 result=%s\n", family_names[f],
               family_failures[f] ? "FAIL" : "PASS");
    return failed;
}

static int boundaries(void)
{
    const struct cbpf_insn malformed[] = {
        {(enum cbpf_opcode)99,0,0,0}, I(ACQUIRE,CBPF_REGS,0,1), I(ACQUIRE,0,0,2),
        I(COPY,0,CBPF_REGS,0), I(SPILL,CBPF_SPILLS,0,0), I(RELOAD,0,CBPF_SPILLS,0),
        I(READ,CBPF_REGS,0,0), I(BR_NULL,0,0,2), I(BR_NULL,0,0,4)
    };
    struct cbpf_insn p[] = {
        I(ACQUIRE,0,0,1), I(RETURN,0,0,7), I(READ,0,0,0), I(RETURN,0,0,9)
    };
    struct expectation e = {CBPF_INVALID,CBPF_NO_TRAP,2,0,0,0,0,0,0,0,0};
    struct cbpf_insn longest[CBPF_MAX_INSNS];
    int failed = 0;
    for (size_t i = 0; i < LEN(malformed); ++i) {
        p[2] = malformed[i];
        failed |= check_case("malformed_unreachable", p, LEN(p), &e, 0);
    }
    p[2] = (struct cbpf_insn)I(READ,0,0,0);
    failed |= check_case("missing_final_return", p, 3, &e, 0);
    e.pc = 0;
    failed |= check_case("empty_program", p, 0, &e, 0);
    failed |= check_case("null_program", NULL, 2, &e, 0);
    failed |= check_case("oversized_program", longest, CBPF_MAX_INSNS + 1, &e, 0);

    longest[0] = (struct cbpf_insn)I(ACQUIRE,0,0,1);
    longest[1] = (struct cbpf_insn)I(ACQUIRE,1,0,1);
    for (size_t pc = 2; pc + 1 < LEN(longest); ++pc)
        longest[pc] = (struct cbpf_insn)I(READ,0,0,0);
    longest[LEN(longest) - 1] = (struct cbpf_insn)I(RETURN,0,0,INT64_MIN);
    e = (struct expectation){CBPF_RETURNED,CBPF_NO_TRAP,63,2,61,0,2,INT64_MIN,66,0,3};
    failed |= check_case("full64_event66", longest, LEN(longest), &e, 0);
    printf("CBPF_GATE boundaries=malformed_unreachable_full64_event66 result=%s\n",
           failed ? "FAIL" : "PASS");
    return failed;
}

static int direct_object_baseline(void)
{
    /* Object allocation stays live throughout. This isolates acquisition
     * identity from allocation lifetime without dereferencing freed storage. */
    struct direct_object { int value; };
    _Alignas(16) struct direct_object live = {42};
    struct direct_object *object = &live;
    int refs = 1, representation_ok = 1;
    unsigned effects = 0;
#if defined(__CHERI_PURE_CAPABILITY__)
    object = cheri_bounds_set_exact(object, sizeof(live));
    representation_ok = cheri_tag_get(object) &&
                        cheri_length_get(object) == sizeof(live) && sizeof(void *) == 16;
    if (!representation_ok) {
        puts("CBPF_GATE baseline=direct_object representation=FAIL result=FAIL");
        return 1;
    }
#endif
    struct direct_object *a = object, *b = object;
    refs += 2;
    --refs; ++effects; /* Simulated release A, with baseline and B still live. */
    int a_value = ((volatile struct direct_object *)a)->value;
    int b_value = ((volatile struct direct_object *)b)->value;
    int good = representation_ok && a_value == 42 && b_value == 42 && refs == 2;
    --refs; ++effects;
    good &= refs == 1 && effects == 2;
    printf("CBPF_GATE baseline=direct_object live_object=1 released_A_read=%d "
           "live_B_read=%d refs=%d effects=%u result=%s\n",
           a_value, b_value, refs, effects, good ? "PASS" : "FAIL");
    return !good;
}

int main(void)
{
    int failed;
    puts("CBPF_GATE scope=validated_IR isolation=0 kfunc=0 jit=0");
    printf("CBPF_GATE backend=%s\n", PURECAP ? "cheri" : "software");
    failed = corpus();
    failed |= boundaries();
    failed |= direct_object_baseline();
    if (cases != 494 || matched != cases) failed = 1;
    printf("CBPF_GATE representation=purecap_%d cell_bytes=%zu handle_bytes=%zu\n",
           PURECAP, cell_bytes, handle_bytes);
    printf("CBPF_GATE cases=%u matched=%u\n", cases, matched);
    puts(failed ? "CBPF_GATE result=FAIL" : "CBPF_GATE result=PASS");
    fflush(NULL);
#if defined(CBPF_GATE_GUEST)
    if (reboot(RB_POWER_OFF)) perror("CBPF_GATE poweroff");
    for (;;) pause(); /* Guest PID 1 must never return, including after failure. */
#else
    return failed ? 1 : 0;
#endif
}
