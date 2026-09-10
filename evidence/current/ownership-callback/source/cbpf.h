/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_CBPF_H
#define _LINUX_CBPF_H

#include <linux/types.h>

struct bpf_prog;

#ifdef CONFIG_CBPF_KFUNC_GATE
/* BTF contract only. Native BPF carries a capability view of a private cell. */
struct cbpf_cap_ref {
	u64 id;
	void *reserved;
};

struct cbpf_cap_ref *cbpf_cap_acquire(u32 want_null);
int cbpf_cap_read(struct cbpf_cap_ref *ref);
void cbpf_cap_release(struct cbpf_cap_ref *ref);
bool cbpf_jit_match(const struct bpf_prog *prog);
struct bpf_prog *cbpf_jit_compile(struct bpf_prog *prog);
u32 cbpf_test_invoke(struct bpf_prog *prog, void *ctx);
int cbpf_enter(void *stack_base, u32 stack_size, void *ret_addr,
	       u32 executive_return_size, u64 outer_return_addr, u64 prog_cookie);
extern char cbpf_gateway[];
#endif

#endif
