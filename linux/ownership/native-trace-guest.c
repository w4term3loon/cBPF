// SPDX-License-Identifier: GPL-2.0-only
/* Load-only verifier controls for the synthetic native ownership trace. */
#ifndef __CHERI_PURE_CAPABILITY__
#error "This loader is only for the isolated Morello purecap guest"
#endif
#include <asm/unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "ownership_ids.h"

#define I(C, D, S, O, V) \
	{ .code = (C), .dst_reg = (D), .src_reg = (S), .off = (O), .imm = (V) }
#define IMM(D, V) I(BPF_ALU64 | BPF_MOV | BPF_K, D, 0, 0, V)
#define COPY(D, S) I(BPF_ALU64 | BPF_MOV | BPF_X, D, S, 0, 0)
#define CALL(ID) I(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, ID)
#define NULL_TO(O) I(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, O, 0)
#define RELOAD I(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_8, BPF_REG_10, -8, 0)
#define EXIT I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

static const struct bpf_insn base_program[] = {
	IMM(1, 0), CALL(CBPF_ACQUIRE_BTF_ID), NULL_TO(21),
	COPY(6, 0), I(BPF_STX | BPF_MEM | BPF_DW, 10, 6, -8, 0),
	IMM(1, 0), CALL(CBPF_ACQUIRE_BTF_ID), NULL_TO(11),
	COPY(7, 0), RELOAD, COPY(1, 8), CALL(CBPF_RELEASE_BTF_ID),
	COPY(1, 7), CALL(CBPF_READ_BTF_ID), COPY(9, 0),
	COPY(1, 7), CALL(CBPF_RELEASE_BTF_ID), COPY(0, 9), EXIT,
	RELOAD, COPY(1, 8), CALL(CBPF_RELEASE_BTF_ID), IMM(0, 7), EXIT,
	IMM(0, 0), EXIT,
};

static char verifier_log[128 * 1024];

static __kernel_aligned_uintptr_t pointer(const void *p)
{
	return (__kernel_aligned_uintptr_t)(uintptr_t)p;
}

static int command(unsigned cmd, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int load_only(const char *name, const struct bpf_insn *insns,
		     unsigned count)
{
	static const char license[] = "GPL";
	union bpf_attr attr = { 0 };
	const char *diagnostic = "other";
	int fd, load_errno;

	printf("CBPF_TRACE_VERIFY case=%s phase=begin expected=reject execution=forbidden\n",
	       name);
	for (unsigned pc = 0; pc < count; ++pc)
		printf("CBPF_TRACE_VERIFY bpf case=%s pc=%u code=%02x dst=%u src=%u off=%d imm=%d\n",
		       name, pc, insns[pc].code, insns[pc].dst_reg,
		       insns[pc].src_reg, insns[pc].off, insns[pc].imm);
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.insn_cnt = count;
	attr.insns = pointer(insns);
	attr.license = pointer(license);
	attr.log_level = 2;
	attr.log_buf = pointer(verifier_log);
	attr.log_size = sizeof(verifier_log);
	memcpy(attr.prog_name, "cbpf_trace_load", sizeof("cbpf_trace_load"));
	memset(verifier_log, 0, sizeof(verifier_log));
	fd = command(BPF_PROG_LOAD, &attr);
	load_errno = fd < 0 ? errno : 0;
	verifier_log[sizeof(verifier_log) - 1] = '\0';
	printf("CBPF_TRACE_VERIFY verifier_begin case=%s\n%sCBPF_TRACE_VERIFY verifier_end case=%s\n",
	       name, verifier_log, name);
	if (strstr(verifier_log, "R1 type=scalar") ||
	    strstr(verifier_log, "R1 !read_ok") ||
	    strstr(verifier_log, "R1 must be referenced") ||
	    strstr(verifier_log,
		   "arg#0 pointer type STRUCT cbpf_cap_ref must point to scalar"))
		diagnostic = "argument_shape";
	/* Unexpected acceptance is closed immediately and is never test-run. */
	if (fd >= 0)
		close(fd);
	printf("CBPF_TRACE_VERIFY case=%s phase=end result=%s loaded=%u executed=0 load_errno=%d diagnostic=%s\n",
	       name, fd < 0 && (load_errno == EACCES || load_errno == EINVAL) ?
	       "PASS" : "FAIL", fd >= 0, load_errno, diagnostic);
	return fd < 0 && (load_errno == EACCES || load_errno == EINVAL) ? 0 : 1;
}

int main(void)
{
	static const char *const names[] = {
		"stale_copy", "stale_spill", "repeated_release"
	};
	struct bpf_insn selected[64];
	struct utsname identity;
	int result = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (getpid() != 1 || uname(&identity) ||
	    strcmp(identity.release, CBPF_EXPECTED_RELEASE)) {
		puts("CBPF_TRACE_VERIFY identity=FAIL executed=0 poweroff=0");
		return 1;
	}
	printf("CBPF_TRACE_VERIFY kernel=%s normal_verifier=1 attached=0\n",
	       identity.release);
	for (unsigned test = 0; test < sizeof(names) / sizeof(names[0]); ++test) {
		memcpy(selected, base_program, sizeof(base_program));
		if (test == 0 || test == 2) {
			selected[12].src_reg = BPF_REG_6;
			if (test == 2)
				selected[13].imm = CBPF_RELEASE_BTF_ID;
		} else {
			selected[12] = (struct bpf_insn)I(
				BPF_LDX | BPF_MEM | BPF_DW, 1, 10, -8, 0);
		}
		if (load_only(names[test], selected,
			      sizeof(base_program) / sizeof(base_program[0]))) {
			result = 1;
			break;
		}
	}
	printf("CBPF_TRACE_VERIFY result=%s rejected=%u executed=0\n",
	       result ? "FAIL" : "PASS", result ? 0U : 3U);
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}
