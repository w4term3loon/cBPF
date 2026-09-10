/* CBPF architectural probe: purecap C, not eBPF, kfunc, JIT, or a sandbox. */
#define _POSIX_C_SOURCE 200809L
#include <cheriintrin.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

/* Pinned Morello Linux UAPI: asm-generic/siginfo.h, capability tag fault. */
enum { CBPF_SEGV_CAPTAGERR = 10 };
struct object { int value; };
struct cell { struct object * volatile object; };
static struct cell cells[2];
static unsigned allocated;
static int references = 1, effects, fault_pipe;

static void require(int condition, const char *what)
{
    if (!condition) {
        printf("CBPF CHERI PROBE FAIL %s\n", what);
        fflush(NULL);
        reboot(RB_POWER_OFF);
        _exit(1);
    }
}

static struct cell *acquire(struct object *object)
{
    require(allocated < 2, "cell exhaustion");
    struct cell *private = &cells[allocated++];
    private->object = object;
    ++references;
    struct cell *public = cheri_bounds_set_exact(private, sizeof(*private));
    public = cheri_perms_clear(public, CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
                              CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_EXECUTE);
    require(cheri_tag_get(public), "cell bounds");
    return public;
}

/* Only the trusted test manager has writable cell authority. No slot reuse. */
static int consume(unsigned index)
{
    struct object *object = cells[index].object;
    if (!cheri_tag_get(object)) return 0;
    cells[index].object = cheri_tag_clear(object); /* Keep the nonzero cursor. */
    --references;                               /* Simulated provider effect. */
    ++effects;
    return 1;
}

__attribute__((noinline)) static int resolve_read(struct cell *handle)
{
    struct object *object = handle->object; /* Actual capability load. */
    return ((volatile struct object *)object)->value;
}

/* A fault terminates this child execution. The parent only observes it. */
static void fault_handler(int signal, siginfo_t *info, void *context)
{
    (void)context;
    int report[2] = {signal, info->si_code};
    ssize_t count = write(fault_pipe, report, sizeof(report));
    _exit(count == sizeof(report) ? 0 : 2);
}

static void expect_stale_fault(struct cell *alias, const char *name)
{
    int channel[2], status, report[2] = {0, 0};
    require(pipe(channel) == 0, "pipe");
    pid_t child = fork();
    require(child >= 0, "fork");
    if (child == 0) {
        close(channel[0]);
        fault_pipe = channel[1];
        struct sigaction action = {.sa_sigaction = fault_handler,
                                   .sa_flags = SA_SIGINFO};
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGSEGV, &action, NULL)) _exit(3);
        (void)resolve_read(alias);
        _exit(4); /* Reaching here falsifies this architectural observation. */
    }
    close(channel[1]);
    ssize_t count = read(channel[0], report, sizeof(report));
    close(channel[0]);
    require(waitpid(child, &status, 0) == child, "waitpid");
    require(count == sizeof(report) && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
            report[0] == SIGSEGV && report[1] == CBPF_SEGV_CAPTAGERR,
            "expected terminal capability-tag fault");
    printf("CBPF stale_%s signal=11 code=10 terminal=1\n", name);
}

int main(void)
{
    _Alignas(16) struct object live = {.value = 42};
    struct object *object = cheri_bounds_set_exact(&live, sizeof(live));
    require(sizeof(void *) == 16 && cheri_tag_get(object) &&
            cheri_length_get(object) == sizeof(live), "purecap object authority");
    struct cell *a = acquire(object), *b = acquire(object);
    struct cell *copy_alias = a;
    struct cell * volatile spill_alias = a;
    require(cheri_address_get(a) != cheri_address_get(b) &&
            cheri_address_get(a->object) == cheri_address_get(b->object), "A/B identity");
    require(resolve_read(a) == 42 && resolve_read(b) == 42, "valid reads");
    require(consume(0) && !consume(0) && references == 2 && effects == 1,
            "consume once");
    require(!cheri_tag_get(a->object) &&
            cheri_address_get(a->object) == cheri_address_get(object) &&
            cheri_address_get(a->object) != 0, "nonzero untagged stale authority");
    require(resolve_read(b) == 42 && object->value == 42, "B/direct control");
    puts("CBPF scope=purecap_C_architecture_probe isolation=0 kfunc=0 jit=0");
    puts("CBPF distinct_cells=1 same_object=1 valid_A=42 valid_B=42");
    puts("CBPF consumed_A=1 duplicate_effect=0 references=2 stale_tag=0 cursor_preserved=1");
    puts("CBPF surviving_B=42 direct_object=42");
    fflush(NULL);
    expect_stale_fault(copy_alias, "copy");
    expect_stale_fault(spill_alias, "spill");
    require(consume(1) && references == 1 && effects == 2, "balanced release");
    puts("CBPF final_references=1 effects=2 cells_allocated=2 cells_reused=0");
    puts("CBPF CHERI PROBE PASS");
    fflush(NULL);
    if (reboot(RB_POWER_OFF)) perror("CBPF poweroff");
    for (;;) pause();
}
