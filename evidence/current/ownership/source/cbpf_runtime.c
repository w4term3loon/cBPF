// SPDX-License-Identifier: GPL-2.0-only
/*
 * CBPF bounded kernel acquisition gates.
 * Restricted entry/return and register transport derive from Arm/Linaro's
 * Morello BPF RFC and the corrected CapeBPF replay (tree e6c69574c16b).
 * This extraction omits the historical experiment, mutation and map paths.
 * Provider assignment from executive DDC and synchronous mediation are trust
 * assumptions; this is not a general allocator or concurrent revocation ABI.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cbpf.h>
#include <linux/cheri.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/refcount.h>

#define CBPF_EXEC __ARM_CAP_PERMISSION_EXECUTIVE__
#define CBPF_SYS __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__
#define CBPF_PUBLIC_PERMS (CHERI_PERM_LOAD | CHERI_PERM_GLOBAL)
#define CBPF_FAILURE ((uintcap_t)U64_MAX)

struct cbpf_object {
	int value;
	refcount_t refs;
};
struct cbpf_cell {
	volatile uintcap_t object;
} __aligned(16);
struct cbpf_invocation {
	struct bpf_prog *prog;
	struct cbpf_cell cells[2];
	volatile uintcap_t views[2];
	u32 acquired, released, reads, cleanup, sequence;
	bool entered, failed;
};
static struct cbpf_object cbpf_object = { 42, REFCOUNT_INIT(1) };
static DEFINE_PER_CPU(struct cbpf_invocation *, cbpf_active);

static void *__capability cbpf_exact(u64 address, u64 size, u64 perms)
{
	void *__capability cap = cheri_address_set(cheri_ddc_get(), address);

	cap = cheri_bounds_set_exact(cap, size);
	cap = cheri_perms_and(cap, perms);
	if (!cheri_tag_get(cap) || cheri_is_sealed(cap) ||
	    cheri_address_get(cap) != address || cheri_base_get(cap) != address ||
	    cheri_length_get(cap) != size || cheri_perms_get(cap) != perms)
		return (void *__capability)0;
	return cap;
}

static void cbpf_trace(struct cbpf_invocation *s, const char *event,
		       u64 pc, u32 id)
{
	pr_info("CBPF_GATE seq=%u event=%s pc=%llu id=%u acquired=%u released=%u reads=%u cleanup=%u refs=%u tagA=%u tagB=%u\n",
		++s->sequence, event, pc, id, s->acquired, s->released,
		s->reads, s->cleanup, refcount_read(&cbpf_object.refs),
		(unsigned)cheri_tag_get((void *__capability)s->cells[0].object),
		(unsigned)cheri_tag_get((void *__capability)s->cells[1].object));
}

static uintcap_t cbpf_fail(struct cbpf_invocation *s, u64 pc)
{
	if (s) {
		s->failed = true;
		cbpf_trace(s, "reject", pc, 0);
	}
	return CBPF_FAILURE;
}

static void cbpf_consume(struct cbpf_invocation *s, u32 index, u64 pc,
			 bool cleanup)
{
	void *__capability object = (void *__capability)s->cells[index].object;

	/* Stored-authority invalidation is the release linearization point. */
	s->cells[index].object = (uintcap_t)cheri_tag_clear(object);
	barrier();
	cbpf_trace(s, "clear", pc, index + 1);
	refcount_dec(&cbpf_object.refs);
	++s->released;
	if (cleanup)
		++s->cleanup;
	cbpf_trace(s, cleanup ? "cleanup" : "release", pc, index + 1);
}

/* Only the executive assembly gateway calls this hybrid capability ABI. */
uintcap_t cbpf_gate_impl(uintcap_t argument, u64 operation, u64 pc);
noinline uintcap_t cbpf_gate_impl(uintcap_t argument, u64 operation, u64 pc)
{
	struct cbpf_invocation *s = this_cpu_read(cbpf_active);
	void *__capability view = (void *__capability)argument;
	u32 index;

	if (!s || !s->entered || s->failed)
		return cbpf_fail(s, pc);
	if (operation == 1) {
		void *__capability object;

		if (cheri_tag_get(view) || (u64)argument > 1)
			return cbpf_fail(s, pc);
		if ((u64)argument) {
			cbpf_trace(s, "null", pc, 0);
			return 0;
		}
		if (s->acquired == ARRAY_SIZE(s->cells))
			return cbpf_fail(s, pc);
		index = s->acquired;
		/* Prepare every representability check before the provider effect. */
		view = cbpf_exact((u64)&s->cells[index], sizeof(s->cells[index]),
				  CBPF_PUBLIC_PERMS);
		object = cbpf_exact((u64)&cbpf_object, sizeof(cbpf_object),
				    CBPF_PUBLIC_PERMS);
		if (!cheri_tag_get(view) || !cheri_tag_get(object))
			return cbpf_fail(s, pc);
		refcount_inc(&cbpf_object.refs);
		s->cells[index].object = (uintcap_t)object;
		s->views[index] = (uintcap_t)view;
		++s->acquired;
		pr_info("CBPF_BIND pc=%llu id=%u cell=%px object=%px public_tag=%u public_base=0x%llx public_length=%llu public_perms=0x%llx\n",
			pc, index + 1, &s->cells[index], &cbpf_object,
			(unsigned)cheri_tag_get(view), (u64)cheri_base_get(view),
			(u64)cheri_length_get(view), (u64)cheri_perms_get(view));
		cbpf_trace(s, "acquire", pc, index + 1);
		return (uintcap_t)view;
	}
	if (operation != 2 && operation != 3)
		return cbpf_fail(s, pc);
	/* The public view never supplies authority for a cell dereference. */
	for (index = 0; index < s->acquired; ++index)
		if (cheri_is_equal_exact(view,
				(void *__capability)s->views[index]))
			break;
	if (index == s->acquired ||
	    !cheri_tag_get((void *__capability)s->cells[index].object))
		return cbpf_fail(s, pc);
	if (operation == 2) {
		struct cbpf_object *__capability object =
			(struct cbpf_object *__capability)s->cells[index].object;
		int value = object->value;

		++s->reads;
		cbpf_trace(s, "read", pc, index + 1);
		return (uintcap_t)(u64)value;
	}
	cbpf_consume(s, index, pc, false);
	return 0;
}

/*
 * BTF identity and ownership effects are the normal verifier's contract.
 * Ordinary native calls have no effects: supported calls are lowered only
 * through cbpf_gateway, and entry requires cbpf_test_invoke's private context.
 */
__bpf_kfunc_start_defs();
__bpf_kfunc struct cbpf_cap_ref *cbpf_cap_acquire(u32 want_null)
{
	return NULL;
}
__bpf_kfunc int cbpf_cap_read(struct cbpf_cap_ref *ref)
{
	return 0;
}
__bpf_kfunc void cbpf_cap_release(struct cbpf_cap_ref *ref)
{
}
__bpf_kfunc_end_defs();
BTF_SET8_START(cbpf_cap_ids)
BTF_ID_FLAGS(func, cbpf_cap_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, cbpf_cap_read, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, cbpf_cap_release, KF_RELEASE)
BTF_SET8_END(cbpf_cap_ids)
static const struct btf_kfunc_id_set cbpf_cap_set = { .set = &cbpf_cap_ids };
static int __init cbpf_cap_init(void)
{
	BUILD_BUG_ON(sizeof(struct cbpf_cell) != 16);
	BUILD_BUG_ON(sizeof(struct cbpf_cap_ref) != 16);
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &cbpf_cap_set);
}
late_initcall(cbpf_cap_init);

u32 cbpf_test_invoke(struct bpf_prog *prog, void *ctx)
{
	struct cbpf_invocation state = { .prog = prog };
	/* The generated hybrid entry preserves integer callee-saved registers.
	 * Force tagged roots to memory across it, then reload their full values. */
	volatile uintcap_t saved_rddc, saved_rcsp;
	u32 result, index;

	/* test_run holds local_bh_disable: this CPU context cannot migrate. */
	if (this_cpu_read(cbpf_active) || !prog->aux->cbpf_gate)
		return 0;
	asm volatile("mrs %0, rddc_el0" : "=C" (saved_rddc));
	asm volatile("mrs %0, rcsp_el0" : "=C" (saved_rcsp));
	this_cpu_write(cbpf_active, &state);
	result = bpf_prog_run(prog, ctx);
	/* The common executive epilogue has scrubbed every native BPF alias. */
	for (index = 0; index < state.acquired; ++index)
		if (cheri_tag_get((void *__capability)state.cells[index].object))
			cbpf_consume(&state, index, U64_MAX, true);
	if (!state.entered || state.acquired != state.released)
		state.failed = true;
	cbpf_trace(&state, state.failed ? "failed" : "exit", U64_MAX, 0);
	pr_info("CBPF_RESULT value=%u entered=%u failed=%u balanced=%u\n",
		result, state.entered, state.failed,
		state.acquired == state.released);
	for (index = 0; index < ARRAY_SIZE(state.cells); ++index) {
		state.cells[index].object = 0;
		state.views[index] = 0;
	}
	barrier();
	this_cpu_write(cbpf_active, NULL);
	asm volatile("msr rddc_el0, %0" :: "C" (saved_rddc) : "memory");
	asm volatile("msr rcsp_el0, %0" :: "C" (saved_rcsp) : "memory");
	return state.failed ? 0 : result;
}

/* Full capability saves are necessary even though kernel C uses hybrid ABI. */
asm(
".pushsection .text, \"ax\"\n"
".align 4\n"
".global cbpf_gateway\n"
"cbpf_gateway:\n"
"bti c\n"
"mov x12, sp\n"
"mov sp, x15\n"
"sub sp, sp, #128\n"
"str x15, [sp, #0]\n"
"str x12, [sp, #8]\n"
"str c13, [sp, #16]\n"
"str c17, [sp, #32]\n"
"str c19, [sp, #48]\n"
"str c20, [sp, #64]\n"
"str c21, [sp, #80]\n"
"str c22, [sp, #96]\n"
"str c30, [sp, #112]\n"
"mov x1, x4\n"
"mov x2, x5\n"
"bl cbpf_gate_impl\n"
"ldr x15, [sp, #0]\n"
"ldr x12, [sp, #8]\n"
"ldr c13, [sp, #16]\n"
"ldr c17, [sp, #32]\n"
"ldr c19, [sp, #48]\n"
"ldr c20, [sp, #64]\n"
"ldr c21, [sp, #80]\n"
"ldr c22, [sp, #96]\n"
"ldr c14, [sp, #112]\n"
"add sp, sp, #128\n"
"mov sp, x12\n"
"cmn x0, #1\n"
"b.ne 1f\n"
/* Failure skips the restricted continuation and enters its fixed epilogue. */
"mov c14, c13\n"
"mov x0, xzr\n"
"mov x7, xzr\n"
"1:\n"
"mov c30, c13\n"
"mov x1, xzr\n"
"mov x2, xzr\n"
"mov x3, xzr\n"
"mov x4, xzr\n"
"mov x5, xzr\n"
"mov x6, xzr\n"
"mov x7, xzr\n"
"mov x8, xzr\n"
"mov x9, xzr\n"
"mov x10, xzr\n"
"mov x11, xzr\n"
"mov x12, xzr\n"
"mov x13, xzr\n"
"mov x16, xzr\n"
"mov x18, xzr\n"
"mov x23, xzr\n"
"mov x24, xzr\n"
"mov x25, xzr\n"
"mov x26, xzr\n"
"mov x27, xzr\n"
"mov x28, xzr\n"
"mov x29, xzr\n"
"retr c14\n"
".popsection\n"
);

int cbpf_enter(void *stack_base, u32 stack_size, void *ret_addr,
	       u32 executive_return_size, u64 outer_return_addr, u64 prog_cookie)
{
	struct cbpf_invocation *s = this_cpu_read(cbpf_active);
	void *caller_lr = __builtin_return_address(0);
	void *__capability pcc = cheri_pcc_get();
	void *__capability caller, *__capability rcsp, *__capability code;
	void *__capability exit, *__capability gate, *__capability rddc;
	u64 code_size, pcc_base = cheri_base_get(pcc);
	u64 pcc_length = cheri_length_get(pcc);
	uintcap_t *caller_slot;

	if (!s || s->entered || s->failed || (u64)s->prog != prog_cookie ||
	    stack_size != 16 || !IS_ALIGNED((u64)stack_base, 16) ||
	    (u64)stack_base > U64_MAX - stack_size ||
	    !IS_ALIGNED(outer_return_addr, 4) || outer_return_addr < pcc_base ||
	    outer_return_addr - pcc_base > pcc_length ||
	    pcc_length - (outer_return_addr - pcc_base) < 4 ||
	    (u64)ret_addr <= (u64)caller_lr || !executive_return_size)
		return -EINVAL;
	caller_slot = (uintcap_t *)((u64)stack_base + stack_size);
	caller = cheri_address_set(pcc, outer_return_addr);
	if (!cheri_tag_get(caller) || cheri_address_get(caller) != outer_return_addr ||
	    !(cheri_perms_get(caller) & CHERI_PERM_EXECUTE) ||
	    !(cheri_perms_get(caller) & CBPF_EXEC))
		return -ERANGE;
	caller = cheri_sentry_create(caller);
	code_size = (u64)ret_addr - (u64)caller_lr;
	code = cbpf_exact((u64)caller_lr, code_size,
		CHERI_PERM_EXECUTE | CHERI_PERM_LOAD | CHERI_PERM_GLOBAL);
	exit = cbpf_exact((u64)ret_addr, executive_return_size,
		CHERI_PERM_EXECUTE | CHERI_PERM_LOAD | CHERI_PERM_GLOBAL | CBPF_EXEC);
	rcsp = cbpf_exact((u64)stack_base, stack_size,
		CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP |
		CHERI_PERM_STORE_CAP | CHERI_PERM_GLOBAL);
	if (!cheri_tag_get(code) || !cheri_tag_get(exit) || !cheri_tag_get(rcsp))
		return -ERANGE;
	code = cheri_sentry_create(code);
	exit = cheri_sentry_create(exit);
	/* The sole native sidecar uses [csp] at offset zero. */
	gate = cheri_address_set(pcc, (u64)cbpf_gateway);
	gate = cheri_perms_clear(gate, CHERI_PERMS_WRITE);
	gate = cheri_sentry_create(gate);
	if (!cheri_tag_get(caller) || !cheri_is_sealed(caller) ||
	    !cheri_tag_get(code) || !cheri_is_sealed(code) ||
	    !cheri_tag_get(exit) || !cheri_is_sealed(exit) ||
	    !cheri_tag_get(gate) || !cheri_is_sealed(gate) ||
	    cheri_address_get(gate) != (u64)cbpf_gateway)
		return -ERANGE;
	*caller_slot = (uintcap_t)caller;
	rddc = (void *__capability)0;
	s->entered = true;
	pr_info("CBPF_ENTER restricted_base=0x%llx restricted_size=%llu executive_base=0x%llx executive_size=%u stack_base=0x%llx stack_size=%u rddc_tag=0 gate_sealed=1\n",
		(u64)caller_lr, code_size, (u64)ret_addr, executive_return_size,
		(u64)stack_base, stack_size);
	asm volatile("msr rcsp_el0, %0\nmsr rddc_el0, %1"
		     :: "C" (rcsp), "C" (rddc) : "memory");
	/* Restore the JIT call-entry SP after this C function's compiler frame. */
	asm volatile(
		"mov x15, %[STACK]\n"
		"mov sp, %[STACK]\n"
		"mov c17, %[GATE]\n"
		"mov x0, xzr\n"
		"mov c30, %[EXIT]\n"
		"brr %[CODE]\n"
		:: [STACK] "r" (stack_base), [GATE] "C" (gate),
		   [EXIT] "C" (exit), [CODE] "C" (code)
		: "x0", "x15", "x17", "memory");
	__builtin_unreachable();
}
