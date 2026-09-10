// SPDX-License-Identifier: GPL-2.0-only
/* Bounded benign controls and load-only rejections in the offline guest. */
#ifndef __CHERI_PURE_CAPABILITY__
#error "This loader is only for the isolated Morello purecap guest"
#endif
#include <asm/unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "ownership_ids.h"

#define I(C,D,S,O,V) { .code=(C), .dst_reg=(D), .src_reg=(S), .off=(O), .imm=(V) }
#define IMM(D,V) I(BPF_ALU64|BPF_MOV|BPF_K,D,0,0,V)
#define COPY(D,S) I(BPF_ALU64|BPF_MOV|BPF_X,D,S,0,0)
#define CALL(ID) I(BPF_JMP|BPF_CALL,0,BPF_PSEUDO_KFUNC_CALL,0,ID)
#define NULL_TO(O) I(BPF_JMP|BPF_JEQ|BPF_K,BPF_REG_0,0,O,0)
#define RELOAD I(BPF_LDX|BPF_MEM|BPF_DW,BPF_REG_8,BPF_REG_10,-8,0)
#define EXIT I(BPF_JMP|BPF_EXIT,0,0,0,0)

static const struct bpf_insn program[] = {
	IMM(1, 0), CALL(CBPF_ACQUIRE_BTF_ID), NULL_TO(21), /* 0..2 */
	COPY(6, 0), I(BPF_STX|BPF_MEM|BPF_DW,10,6,-8,0),
	IMM(1, 0), CALL(CBPF_ACQUIRE_BTF_ID), NULL_TO(11), /* 5..7 */
	COPY(7, 0), RELOAD, COPY(1, 8), CALL(CBPF_RELEASE_BTF_ID),
	COPY(1, 7), CALL(CBPF_READ_BTF_ID), COPY(9, 0),
	COPY(1, 7), CALL(CBPF_RELEASE_BTF_ID), COPY(0, 9), EXIT,
	RELOAD, COPY(1, 8), CALL(CBPF_RELEASE_BTF_ID), IMM(0, 7), EXIT,
	IMM(0, 0), EXIT,
};
/* NULL refinement uses r8/r6; result transport and branch targets also differ. */
static const struct bpf_insn alternate[] = {
	IMM(1, 0), CALL(CBPF_ACQUIRE_BTF_ID), COPY(8, 0),
	I(BPF_JMP|BPF_JEQ|BPF_K,8,0,21,0),
	I(BPF_STX|BPF_MEM|BPF_DW,10,8,-8,0),
	IMM(1, 0), CALL(CBPF_ACQUIRE_BTF_ID), COPY(6, 0),
	I(BPF_JMP|BPF_JEQ|BPF_K,6,0,11,0),
	I(BPF_LDX|BPF_MEM|BPF_DW,7,10,-8,0), COPY(1, 7),
	CALL(CBPF_RELEASE_BTF_ID), COPY(1, 6), CALL(CBPF_READ_BTF_ID),
	COPY(9, 0), COPY(1, 6), CALL(CBPF_RELEASE_BTF_ID),
	COPY(8, 9), COPY(0, 8), EXIT,
	I(BPF_LDX|BPF_MEM|BPF_DW,7,10,-8,0), COPY(1, 7),
	CALL(CBPF_RELEASE_BTF_ID), IMM(0, 9), EXIT, IMM(0, 0), EXIT,
};
static char verifier_log[128 * 1024];
static uint32_t native_words[2048];

static __kernel_aligned_uintptr_t pointer(const void *p)
{
	return (__kernel_aligned_uintptr_t)(uintptr_t)p;
}

static int command(unsigned cmd, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int run_case(const char *name, const struct bpf_insn *insns,
		    unsigned count, unsigned expected, bool reject)
{
	struct bpf_prog_info info = { 0 };
	union bpf_attr attr = { 0 };
	unsigned char input[64] = { 0 }, output[64] = { 0 };
	static const char license[] = "GPL";
	const char *stage = "load";
	int fd = -1, result = -1, load_errno = 0;
	unsigned executed = 0;

	printf("CBPF_M3 case=%s phase=begin expected=%s\n", name,
	       reject ? "reject" : "execute");
	for (unsigned pc = 0; pc < count; ++pc) {
		const struct bpf_insn *i = &insns[pc];
		printf("CBPF_M3 bpf pc=%u code=%02x dst=%u src=%u off=%d imm=%d\n",
		       pc, i->code, i->dst_reg, i->src_reg, i->off, i->imm);
	}
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.insn_cnt = count;
	attr.insns = pointer(insns);
	attr.license = pointer(license);
	attr.log_level = 2;
	attr.log_buf = pointer(verifier_log);
	attr.log_size = sizeof(verifier_log);
	memcpy(attr.prog_name, "cbpf_m3", sizeof("cbpf_m3"));
	memset(verifier_log, 0, sizeof(verifier_log));
	fd = command(BPF_PROG_LOAD, &attr);
	load_errno = fd < 0 ? errno : 0;
	verifier_log[sizeof(verifier_log) - 1] = '\0';
	printf("CBPF_M3 verifier_begin\n%sCBPF_M3 verifier_end\n", verifier_log);
	/* Unexpected acceptance is terminal and NEVER reaches TEST_RUN. */
	if (reject) {
		if (fd < 0 && (load_errno == EACCES || load_errno == EINVAL) &&
		    (strstr(verifier_log, "R1 type=scalar") ||
		     strstr(verifier_log, "R1 !read_ok") ||
		     strstr(verifier_log, "R1 must be referenced") ||
		     strstr(verifier_log, "arg#0 pointer type STRUCT cbpf_cap_ref must point to scalar")))
			result = 0;
		goto out;
	}
	if (fd < 0)
		goto out;
	stage = "native_image";
	memset(&attr, 0, sizeof(attr));
	info.jited_prog_len = sizeof(native_words);
	info.jited_prog_insns = pointer(native_words);
	attr.info.bpf_fd = fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = pointer(&info);
	if (command(BPF_OBJ_GET_INFO_BY_FD, &attr) || !info.jited_prog_len ||
	    info.jited_prog_len > sizeof(native_words) || info.jited_prog_len % 4)
		goto out;
	for (unsigned n = 0; n < info.jited_prog_len / 4; ++n)
		printf("CBPF_M3 word index=%u value=%08x\n", n, native_words[n]);
	stage = "execute";
	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = fd;
	attr.test.data_in = pointer(input);
	attr.test.data_size_in = sizeof(input);
	attr.test.data_out = pointer(output);
	attr.test.data_size_out = sizeof(output);
	attr.test.repeat = 1;
	executed = 1;
	if (command(BPF_PROG_TEST_RUN, &attr) || attr.test.retval != expected)
		goto out;
	result = 0;
out:
	printf("CBPF_M3 case=%s phase=end loaded=%u executed=%u retval=%u jited_len=%u load_errno=%d stage=%s result=%s\n",
	       name, fd >= 0, executed, executed ? attr.test.retval : 0,
	       info.jited_prog_len, load_errno, stage, result ? "FAIL" : "PASS");
	if (fd >= 0)
		close(fd);
	return result;
}

int main(void)
{
	static const char *const names[] = { "ab_spill", "ab_alternate",
		"null_second", "fail_second", "stale_copy", "stale_spill",
		"duplicate_release" };
	struct bpf_insn selected[64];
	struct utsname identity;
	int result = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	/* Refuse all BPF operations and reboot outside the dedicated PID 1. */
	if (getpid() != 1 || uname(&identity) ||
	    strcmp(identity.release, CBPF_EXPECTED_RELEASE)) {
		puts("CBPF_M3 identity=FAIL executed=0 poweroff=0");
		return 1;
	}
	printf("CBPF_M3 kernel=%s normal_verifier=1 attached=0\n", identity.release);
	for (unsigned test = 0; test < sizeof(names) / sizeof(names[0]); ++test) {
		unsigned count = sizeof(program) / sizeof(program[0]);
		unsigned expected = 42;

		/* Select all fixture instructions before normal verification. */
		memcpy(selected, program, sizeof(program));
		if (test == 1) {
			memcpy(selected, alternate, sizeof(alternate));
			count = sizeof(alternate) / sizeof(alternate[0]);
		} else if (test == 2 || test == 3) {
			selected[5].imm = test == 2 ? 1 : 2;
			expected = test == 2 ? 7 : 0;
		} else if (test == 4 || test == 6) {
			selected[12].src_reg = BPF_REG_6;
			if (test == 6)
				selected[13].imm = CBPF_RELEASE_BTF_ID;
		} else if (test == 5) {
			selected[12] = (struct bpf_insn)I(BPF_LDX|BPF_MEM|BPF_DW,1,10,-8,0);
		}
		if (run_case(names[test], selected, count, expected, test >= 4)) {
			result = 1;
			break;
		}
	}
	printf("CBPF_M3 result=%s\n", result ? "FAIL" : "PASS");
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}
