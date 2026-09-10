// SPDX-License-Identifier: GPL-2.0-only
/* Load-only verifier assessment for the fixed spatial-selectivity matrix. */
#ifndef __CHERI_PURE_CAPABILITY__
#error "spatial selectivity requires the dedicated Morello purecap guest"
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

#define EXPECTED_RELEASE "6.7.0-cbpf-spatial-selectivity"
#define I(C, D, S, O, V) \
	{ .code = (C), .dst_reg = (D), .src_reg = (S), .off = (O), .imm = (V) }

struct admission_case {
	uint32_t offset;
	uint32_t width;
	int expect_admit;
};

static const struct admission_case cases[] = {
	{ 6, 1, 1 },
	{ 7, 1, 0 },
	{ 8, 1, 0 },
	{ 4, 2, 1 },
	{ 6, 2, 0 },
};

static char verifier_log[64 * 1024];
static unsigned map_creates;
static unsigned prog_loads;
static unsigned test_runs;
static int last_errno;

_Static_assert(sizeof(struct bpf_insn) == 8, "Unexpected BPF instruction ABI");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
	       "spatial selectivity requires little endian");

static __kernel_aligned_uintptr_t pointer(const void *p)
{
	return (__kernel_aligned_uintptr_t)(uintptr_t)p;
}

static int command(unsigned command, union bpf_attr *attr)
{
	int result;

	if (command == BPF_MAP_CREATE)
		map_creates++;
	else if (command == BPF_PROG_LOAD)
		prog_loads++;
	else if (command == BPF_PROG_TEST_RUN)
		test_runs++;
	else
		return -1;
	result = (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
	last_errno = result < 0 ? errno : 0;
	return result;
}

static void print_program(unsigned case_index, const struct bpf_insn *program,
			  unsigned count)
{
	unsigned pc;

	for (pc = 0; pc < count; pc++) {
		const struct bpf_insn *insn = &program[pc];

		printf("CBPF_SPATIAL_ADMISSION_BPF case=%u pc=%u code=%02x dst=%u src=%u off=%d imm=%d\n",
		       case_index, pc, (unsigned)insn->code,
		       (unsigned)insn->dst_reg, (unsigned)insn->src_reg,
		       (int)insn->off, (int)insn->imm);
	}
}

static int assess_admission(void)
{
	static const char license[] = "GPL";
	union bpf_attr attr = { 0 };
	uint32_t key = 0;
	unsigned admitted = 0;
	unsigned rejected = 0;
	unsigned failures = 0;
	unsigned case_index;
	int map_fd;

	printf("CBPF_SPATIAL_ADMISSION_BEGIN cases=5 key=0 key_size=4 value_size=7 max_entries=2 execution=0\n");
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(key);
	attr.value_size = 7;
	attr.max_entries = 2;
	memcpy(attr.map_name, "cbpf_select", sizeof("cbpf_select"));
	map_fd = command(BPF_MAP_CREATE, &attr);
	if (map_fd < 0) {
		printf("CBPF_SPATIAL_ADMISSION_SUMMARY result=FAIL stage=map_create errno=%d executions=%u\n",
		       last_errno, test_runs);
		return 1;
	}

	for (case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]);
	     case_index++) {
		const struct admission_case *test = &cases[case_index];
		struct bpf_insn program[] = {
			I(BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, 0),
			I(BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0),
			I(BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4),
			I(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 0),
			I(0, 0, 0, 0, 0),
			I(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			I(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0),
			I(BPF_LDX | BPF_MEM | BPF_B, 1, 0, 0, 0),
			I(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),
			I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
		};
		const unsigned count = sizeof(program) / sizeof(program[0]);
		char name[16];
		int program_fd;
		int observed_admit;
		int saved_errno;
		int pass;

		program[3].imm = map_fd;
		program[7].code = BPF_LDX | BPF_MEM |
			(test->width == 1 ? BPF_B : BPF_H);
		program[7].off = test->offset;
		print_program(case_index, program, count);
		memset(verifier_log, 0, sizeof(verifier_log));
		memset(&attr, 0, sizeof(attr));
		attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
		attr.insn_cnt = count;
		attr.insns = pointer(program);
		attr.license = pointer(license);
		attr.log_level = 2;
		attr.log_buf = pointer(verifier_log);
		attr.log_size = sizeof(verifier_log);
		snprintf(name, sizeof(name), "cbpf_sel%u", case_index);
		memcpy(attr.prog_name, name, strlen(name) + 1);
		program_fd = command(BPF_PROG_LOAD, &attr);
		saved_errno = last_errno;
		verifier_log[sizeof(verifier_log) - 1] = '\0';
		printf("CBPF_SPATIAL_ADMISSION_VERIFIER_BEGIN case=%u\n%sCBPF_SPATIAL_ADMISSION_VERIFIER_END case=%u\n",
		       case_index, verifier_log, case_index);
		observed_admit = program_fd >= 0;
		pass = observed_admit == test->expect_admit;
		admitted += observed_admit;
		rejected += !observed_admit;
		failures += !pass;
		printf("CBPF_SPATIAL_ADMISSION_CASE case=%u offset=%u width=%u expected=%s observed=%s errno=%d executed=0 result=%s\n",
		       case_index, test->offset, test->width,
		       test->expect_admit ? "admit" : "reject",
		       observed_admit ? "admit" : "reject", saved_errno,
		       pass ? "PASS" : "FAIL");
		/* An unexpectedly admitted negative is closed without execution. */
		if (program_fd >= 0)
			close(program_fd);
	}
	close(map_fd);
	if (admitted != 2 || rejected != 3 || map_creates != 1 ||
	    prog_loads != 5 || test_runs || failures)
		failures++;
	printf("CBPF_SPATIAL_ADMISSION_SUMMARY result=%s cases=5 admitted=%u rejected=%u map_create_count=%u prog_load_count=%u executions=%u failures=%u\n",
	       failures ? "FAIL" : "PASS", admitted, rejected, map_creates,
	       prog_loads, test_runs, failures);
	return failures ? 1 : 0;
}

int main(void)
{
	struct utsname identity;
	int result;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (getpid() != 1 || uname(&identity) ||
	    strcmp(identity.release, EXPECTED_RELEASE)) {
		puts("CBPF_SPATIAL_ADMISSION identity=FAIL execution=0 poweroff=0");
		return 1;
	}
	printf("CBPF_SPATIAL_ADMISSION kernel=%s pid=1 normal_verifier=1 execution=0\n",
	       identity.release);
	printf("CBPF_SPATIAL_ADMISSION kernel_version=%s\n", identity.version);
	result = assess_admission();
	printf("CBPF_SPATIAL_ADMISSION poweroff=begin result=%s\n",
	       result ? "FAIL" : "PASS");
	sync();
	if (reboot(RB_POWER_OFF))
		printf("CBPF_SPATIAL_ADMISSION poweroff=FAIL errno=%d\n", errno);
	for (;;)
		pause();
}
