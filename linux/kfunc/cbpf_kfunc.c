// SPDX-License-Identifier: GPL-2.0-only
/*
 * CBPF's ordinary Linux kfunc binding control.
 *
 * Every acquisition has a separate allocation, while all acquisitions own a
 * reference to one permanently allocated object.  In the supported programs,
 * handles never escape an invocation; the normal verifier must prove that
 * each is live before use and released on every return path.
 * This module does not provide CHERI protection or tolerate stale native
 * pointers: release frees the handle, so its lifetime relies on that verifier
 * contract.  In particular, this is not the consumed-cell runtime experiment.
 */
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/types.h>

/*
 * The inert NULL pointer makes this BTF type non-scalar.  On the pinned
 * verifier a scalar-only struct can also accept ordinary memory arguments;
 * this layout keeps the accessor on the trusted BTF-object argument path.
 * The reserved member never contains object authority.  The actual object
 * pointer belongs only to the private cell below.
 */
struct cbpf_ref {
	u64 id;
	void *reserved;
};

struct cbpf_object {
	int value;
	refcount_t refs;
};

struct cbpf_cell {
	struct cbpf_ref handle;
	struct cbpf_object *object;
};

static struct cbpf_object cbpf_object = {
	.value = 42,
	.refs = REFCOUNT_INIT(1),
};

static atomic64_t acquisitions = ATOMIC64_INIT(0);
static atomic64_t releases = ATOMIC64_INIT(0);
static atomic64_t live = ATOMIC64_INIT(0);
static atomic64_t reads = ATOMIC64_INIT(0);

/*
 * Individual counters are atomic; reading several files is not one atomic
 * snapshot.  The local runner samples only between synchronous test runs.
 * No setter exists, including for module-load arguments.
 */
static int cbpf_counter_get(char *buffer, const struct kernel_param *param)
{
	const atomic64_t *counter = param->arg;

	return scnprintf(buffer, PAGE_SIZE, "%llu\n",
			 (unsigned long long)atomic64_read(counter));
}

static const struct kernel_param_ops cbpf_counter_ops = {
	.get = cbpf_counter_get,
};

static int cbpf_object_refs_get(char *buffer,
				const struct kernel_param *param)
{
	const refcount_t *refs = param->arg;

	return scnprintf(buffer, PAGE_SIZE, "%u\n", refcount_read(refs));
}

static const struct kernel_param_ops cbpf_object_refs_ops = {
	.get = cbpf_object_refs_get,
};

module_param_cb(acquisitions, &cbpf_counter_ops, &acquisitions, 0444);
MODULE_PARM_DESC(acquisitions, "Successful acquisitions since module load");
module_param_cb(releases, &cbpf_counter_ops, &releases, 0444);
MODULE_PARM_DESC(releases, "Explicit release effects since module load");
module_param_cb(live, &cbpf_counter_ops, &live, 0444);
MODULE_PARM_DESC(live, "Currently live acquisition allocations");
module_param_cb(reads, &cbpf_counter_ops, &reads, 0444);
MODULE_PARM_DESC(reads, "Field accessor calls since module load");
module_param_cb(object_refs, &cbpf_object_refs_ops, &cbpf_object.refs, 0444);
MODULE_PARM_DESC(object_refs, "Shared object references including baseline one");

__bpf_kfunc_start_defs();

__bpf_kfunc struct cbpf_ref *cbpf_ref_acquire(u32 want_null)
{
	struct cbpf_cell *cell;

	/* A deterministic NULL path has no allocation or ownership effect. */
	if (want_null)
		return NULL;
	cell = kzalloc(sizeof(*cell), GFP_ATOMIC);
	if (!cell)
		return NULL;

	cell->object = &cbpf_object;
	cell->handle.reserved = NULL;
	refcount_inc(&cell->object->refs);
	cell->handle.id = (u64)atomic64_inc_return(&acquisitions);
	atomic64_inc(&live);
	return &cell->handle;
}

__bpf_kfunc int cbpf_ref_read(struct cbpf_ref *ref)
{
	struct cbpf_cell *cell = container_of(ref, struct cbpf_cell, handle);

	/* KF_TRUSTED_ARGS requires a live, unmodified acquisition pointer. */
	atomic64_inc(&reads);
	return cell->object->value;
}

__bpf_kfunc void cbpf_ref_release(struct cbpf_ref *ref)
{
	struct cbpf_cell *cell = container_of(ref, struct cbpf_cell, handle);

	/*
	 * KF_RELEASE invalidates all aliases in verifier state.  The baseline
	 * keeps the object alive; only this acquisition allocation is freed.
	 */
	refcount_dec(&cell->object->refs);
	atomic64_inc(&releases);
	atomic64_dec(&live);
	kfree(cell);
}

__bpf_kfunc_end_defs();

BTF_SET8_START(cbpf_kfunc_ids)
BTF_ID_FLAGS(func, cbpf_ref_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, cbpf_ref_read, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, cbpf_ref_release, KF_RELEASE)
BTF_SET8_END(cbpf_kfunc_ids)

static const struct btf_kfunc_id_set cbpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &cbpf_kfunc_ids,
};

static int __init cbpf_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
				       &cbpf_kfunc_set);
}

static void __exit cbpf_kfunc_exit(void)
{
	/*
	 * Owning BPF programs pin this module.  The supported programs do not
	 * export handles, and the normal verifier requires their release on
	 * every return path, so no acquisition survives a supported run.
	 * There is deliberately no reset or fallback freeing of live cells.
	 */
}

module_init(cbpf_kfunc_init);
module_exit(cbpf_kfunc_exit);

MODULE_DESCRIPTION("CBPF normal-verifier kfunc ownership binding control");
MODULE_LICENSE("GPL");
