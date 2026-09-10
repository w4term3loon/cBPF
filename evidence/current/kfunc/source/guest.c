// SPDX-License-Identifier: GPL-2.0-only
/* Guest-only normal-verifier kfunc binding checks; no program is attached. */
#ifndef __CHERI_PURE_CAPABILITY__
#error "CBPF kfunc loader is only for the isolated purecap guest"
#endif
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "kfunc_ids.h"

#ifndef SYS_bpf
#define SYS_bpf __NR_bpf
#endif
#ifndef SYS_finit_module
#define SYS_finit_module __NR_finit_module
#endif

#define MAX_INSNS 64
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define INS(C, D, S, O, I) ((struct bpf_insn) { \
	.code = (C), .dst_reg = (D), .src_reg = (S), .off = (O), .imm = (I) })

struct program {
	struct bpf_insn insns[MAX_INSNS];
	size_t count;
	int invalid;
};

struct counters {
	uint64_t acquisitions, releases, live, reads, object_refs;
};

struct totals {
	unsigned positive_cases, rejected_cases, repeated_runs, executions;
	uint64_t acquisitions, reads;
};

static char verifier_log[128 * 1024];

static __kernel_aligned_uintptr_t user_pointer(const void *pointer)
{
	return (__kernel_aligned_uintptr_t)(uintptr_t)pointer;
}

static int bpf_command(unsigned command, union bpf_attr *attr)
{
	return (int)syscall(SYS_bpf, command, attr, sizeof(*attr));
}

static size_t emit(struct program *p, struct bpf_insn insn)
{
	size_t pc = p->count;

	if (pc == MAX_INSNS) {
		p->invalid = 1;
		return 0;
	}
	p->insns[p->count++] = insn;
	return pc;
}

static void mov(struct program *p, unsigned dst, unsigned src)
{
	emit(p, INS(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0));
}

static void imm(struct program *p, unsigned dst, int value)
{
	emit(p, INS(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, value));
}

static void call(struct program *p, int id)
{
	emit(p, INS(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 1, id));
}

static size_t null_branch(struct program *p)
{
	return emit(p, INS(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 0, 0));
}

static void forward_to(struct program *p, size_t branch, size_t target)
{
	if (branch >= p->count || target <= branch || target > p->count ||
	    target - branch - 1 > INT16_MAX) {
		p->invalid = 1;
		return;
	}
	p->insns[branch].off = (int16_t)(target - branch - 1);
}

static void finish(struct program *p, int result)
{
	imm(p, BPF_REG_0, result);
	emit(p, INS(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
}

static void save_alias(struct program *p, unsigned a, int spill)
{
	if (spill)
		emit(p, INS(BPF_STX | BPF_MEM | BPF_DW,
			    BPF_REG_10, a, spill, 0));
	else
		mov(p, BPF_REG_8, a);
}

static void alias_arg(struct program *p, int spill)
{
	if (spill)
		emit(p, INS(BPF_LDX | BPF_MEM | BPF_DW,
			    BPF_REG_8, BPF_REG_10, spill, 0));
	mov(p, BPF_REG_1, BPF_REG_8);
}

static struct program valid_ab(unsigned a, int spill, int null_b)
{
	struct program p = { 0 };
	unsigned b = a == BPF_REG_6 ? BPF_REG_7 : BPF_REG_6;
	size_t a_null, b_null;

	imm(&p, BPF_REG_1, 0);
	call(&p, CBPF_ACQUIRE_BTF_ID);
	a_null = null_branch(&p);
	mov(&p, a, BPF_REG_0);
	save_alias(&p, a, spill);
	imm(&p, BPF_REG_1, null_b);
	call(&p, CBPF_ACQUIRE_BTF_ID);
	b_null = null_branch(&p);
	mov(&p, b, BPF_REG_0);
	alias_arg(&p, spill);
	call(&p, CBPF_RELEASE_BTF_ID);
	mov(&p, BPF_REG_1, b);
	call(&p, CBPF_READ_BTF_ID);
	mov(&p, BPF_REG_9, BPF_REG_0);
	mov(&p, BPF_REG_1, b);
	call(&p, CBPF_RELEASE_BTF_ID);
	mov(&p, BPF_REG_0, BPF_REG_9);
	emit(&p, INS(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
	forward_to(&p, b_null, p.count);
	alias_arg(&p, spill);
	call(&p, CBPF_RELEASE_BTF_ID);
	finish(&p, 7);
	forward_to(&p, a_null, p.count);
	finish(&p, 0);
	return p;
}

static struct program valid_null(void)
{
	struct program p = { 0 };
	size_t branch;

	imm(&p, BPF_REG_1, 1);
	call(&p, CBPF_ACQUIRE_BTF_ID);
	branch = null_branch(&p);
	/* Even the statically explored non-NULL path releases its ownership. */
	mov(&p, BPF_REG_1, BPF_REG_0);
	call(&p, CBPF_RELEASE_BTF_ID);
	finish(&p, 13);
	forward_to(&p, branch, p.count);
	finish(&p, 0);
	return p;
}

enum rejection { STALE_COPY, STALE_SPILL, DOUBLE_RELEASE, NO_NULL, LEAK };

static struct program rejected_program(enum rejection kind)
{
	struct program p = { 0 };
	size_t branch = 0;

	imm(&p, BPF_REG_1, 0);
	call(&p, CBPF_ACQUIRE_BTF_ID);
	if (kind != NO_NULL)
		branch = null_branch(&p);
	mov(&p, BPF_REG_6, BPF_REG_0);
	if (kind == STALE_COPY || kind == STALE_SPILL || kind == DOUBLE_RELEASE) {
		save_alias(&p, BPF_REG_6, kind == STALE_SPILL ? -8 : 0);
		mov(&p, BPF_REG_1, BPF_REG_6);
		call(&p, CBPF_RELEASE_BTF_ID);
		alias_arg(&p, kind == STALE_SPILL ? -8 : 0);
		call(&p, kind == DOUBLE_RELEASE ? CBPF_RELEASE_BTF_ID : CBPF_READ_BTF_ID);
	} else if (kind == NO_NULL) {
		mov(&p, BPF_REG_1, BPF_REG_6);
		call(&p, CBPF_READ_BTF_ID);
		mov(&p, BPF_REG_1, BPF_REG_6);
		call(&p, CBPF_RELEASE_BTF_ID);
	}
	if (kind != NO_NULL)
		forward_to(&p, branch, p.count);
	finish(&p, 0);
	return p;
}

static int read_counter(const char *name, uint64_t *value)
{
	char path[128], buffer[64], *end;
	unsigned long long parsed;
	ssize_t length;
	int fd;

	if (snprintf(path, sizeof(path), "/sys/module/cbpf_kfunc/parameters/%s",
		     name) >= (int)sizeof(path))
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	length = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (length <= 0 || length == (ssize_t)sizeof(buffer) - 1)
		return -1;
	buffer[length] = '\0';
	if (buffer[0] < '0' || buffer[0] > '9')
		return -1;
	errno = 0;
	parsed = strtoull(buffer, &end, 10);
	if (errno || (*end && strcmp(end, "\n")))
		return -1;
	*value = (uint64_t)parsed;
	return 0;
}

static int snapshot(struct counters *s)
{
	return read_counter("acquisitions", &s->acquisitions) ||
	       read_counter("releases", &s->releases) ||
	       read_counter("live", &s->live) ||
	       read_counter("reads", &s->reads) ||
	       read_counter("object_refs", &s->object_refs);
}

static int balanced(const struct counters *s)
{
	return s->live == 0 && s->object_refs == 1 &&
	       s->acquisitions == s->releases;
}

static int delta(const struct counters *before, const struct counters *after,
		 unsigned acquisitions, unsigned reads)
{
	return balanced(before) && balanced(after) &&
	       after->acquisitions == before->acquisitions + acquisitions &&
	       after->releases == before->releases + acquisitions &&
	       after->reads == before->reads + reads;
}

static void print_log(const char *name)
{
	printf("CBPF_KFUNC verifier_begin case=%s\n", name);
	printf("%s", verifier_log[0] ? verifier_log : "<empty>\n");
	if (verifier_log[0] && verifier_log[strlen(verifier_log) - 1] != '\n')
		putchar('\n');
	printf("CBPF_KFUNC verifier_end case=%s\n", name);
}

static int load_program(const struct program *p, int module_fd)
{
	static const char license[] = "GPL";
	int fd_array[2] = { -1, module_fd };
	union bpf_attr attr = { 0 };
	int fd;

	memset(verifier_log, 0, sizeof(verifier_log));
	if (p->invalid || !p->count || p->count > MAX_INSNS)
		return -1;
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.insn_cnt = (uint32_t)p->count;
	attr.insns = user_pointer(p->insns);
	attr.license = user_pointer(license);
	attr.log_level = 2;
	attr.log_buf = user_pointer(verifier_log);
	attr.log_size = sizeof(verifier_log);
	attr.fd_array = user_pointer(fd_array);
	memcpy(attr.prog_name, "cbpf_binding", sizeof("cbpf_binding"));
	fd = bpf_command(BPF_PROG_LOAD, &attr);
	verifier_log[sizeof(verifier_log) - 1] = '\0';
	return fd;
}

static int jited_length(int fd, uint32_t *length)
{
	struct bpf_prog_info info = { 0 };
	union bpf_attr attr = { 0 };

	attr.info.bpf_fd = (uint32_t)fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = user_pointer(&info);
	if (bpf_command(BPF_OBJ_GET_INFO_BY_FD, &attr))
		return -1;
	*length = info.jited_prog_len;
	return *length ? 0 : -1;
}

/* Only run_valid reaches this function; rejection probes never do. */
static int run_loaded(int fd, uint32_t *retval)
{
	unsigned char input[64] = { 0 }, output[64] = { 0 };
	union bpf_attr attr = { 0 };

	attr.test.prog_fd = (uint32_t)fd;
	attr.test.data_in = user_pointer(input);
	attr.test.data_size_in = sizeof(input);
	attr.test.data_out = user_pointer(output);
	attr.test.data_size_out = sizeof(output);
	attr.test.repeat = 1;
	if (bpf_command(BPF_PROG_TEST_RUN, &attr))
		return -1;
	*retval = attr.test.retval;
	return 0;
}

static void print_program(const struct program *p)
{
	for (size_t pc = 0; pc < p->count; ++pc) {
		const struct bpf_insn *i = &p->insns[pc];

		printf("CBPF_KFUNC trace pc=%zu code=0x%02x dst=%u src=%u off=%d imm=%d\n",
		       pc, i->code, i->dst_reg, i->src_reg, i->off, i->imm);
	}
}

static int run_valid(const char *name, const struct program *p, int module_fd,
		     uint32_t expected, unsigned acquisitions, unsigned reads,
		     unsigned repeats, struct totals *totals)
{
	struct counters before, after;
	uint32_t length = 0, retval = UINT32_MAX;
	unsigned executed = 0;
	int fd = -1, result = -1;
	const char *stage = "snapshot";

	if (snapshot(&before) || !balanced(&before))
		goto out;
	stage = "load";
	fd = load_program(p, module_fd);
	if (fd < 0) {
		print_log(name);
		goto out;
	}
	stage = "jit";
	if (jited_length(fd, &length))
		goto out;
	for (unsigned i = 0; i < repeats; ++i) {
		stage = "run";
		++executed;
		if (run_loaded(fd, &retval))
			goto out;
		stage = "accounting";
		if (retval != expected || snapshot(&after) ||
		    !delta(&before, &after, acquisitions, reads))
			goto out;
		before = after;
	}
	totals->executions += repeats;
	totals->acquisitions += (uint64_t)acquisitions * repeats;
	totals->reads += (uint64_t)reads * repeats;
	if (repeats == 1)
		++totals->positive_cases;
	else
		totals->repeated_runs += repeats;
	printf("CBPF_KFUNC case=%s kind=valid executed=%u retval=%u jited_len=%u acquisitions=%u releases=%u reads=%u live=0 object_refs=1 result=PASS\n",
	       name, executed, retval, length, acquisitions * repeats,
	       acquisitions * repeats, reads * repeats);
	result = 0;
out:
	if (fd >= 0)
		close(fd);
	if (result)
		printf("CBPF_KFUNC case=%s kind=valid executed=%u stage=%s errno=%d result=FAIL\n",
		       name, executed, stage, errno);
	return result;
}

static int attributable_rejection(enum rejection kind)
{
	static const char *const ownership[] = {
		"R1 must be referenced or trusted", "R8 !read_ok",
		"invalid read from stack", "R1 type=scalar expected=",
		"arg#0 pointer type STRUCT cbpf_ref must point to scalar",
	};

	if (!verifier_log[0])
		return 0;
	if (kind == LEAK)
		return strstr(verifier_log, "Unreleased reference") != NULL ||
		       strstr(verifier_log, "unreleased reference") != NULL;
	if (kind == NO_NULL)
		return strstr(verifier_log, "Possibly NULL pointer") != NULL ||
		       strstr(verifier_log, "R1 type=ptr_or_null") != NULL;
	for (size_t i = 0; i < ARRAY_SIZE(ownership); ++i)
		if (strstr(verifier_log, ownership[i]))
			return 1;
	return 0;
}

static int check_rejected(const char *name, enum rejection kind, int module_fd,
			  struct totals *totals)
{
	struct program p = rejected_program(kind);
	struct counters before, after;
	int fd, load_errno;

	if (snapshot(&before) || !balanced(&before))
		return -1;
	fd = load_program(&p, module_fd);
	load_errno = errno;
	print_log(name);
	/* Fail closed: even an unexpectedly accepted probe is never executed. */
	if (fd >= 0) {
		close(fd);
		printf("CBPF_KFUNC case=%s kind=reject executed=0 reason=unexpected_accept result=FAIL\n", name);
		return -1;
	}
	if (p.invalid || !attributable_rejection(kind) || snapshot(&after) ||
	    !delta(&before, &after, 0, 0)) {
		printf("CBPF_KFUNC case=%s kind=reject executed=0 errno=%d reason=unattributed_or_accounting result=FAIL\n",
		       name, load_errno);
		return -1;
	}
	++totals->rejected_cases;
	printf("CBPF_KFUNC case=%s kind=reject executed=0 errno=%d result=PASS\n",
	       name, load_errno);
	return 0;
}

static int module_btf_fd(void)
{
	uint32_t previous = 0;

	for (unsigned attempt = 0; attempt < 128; ++attempt) {
		struct bpf_btf_info info = { 0 };
		union bpf_attr attr = { 0 };
		char name[64] = { 0 };
		int fd;

		attr.start_id = previous;
		if (bpf_command(BPF_BTF_GET_NEXT_ID, &attr))
			return -1;
		previous = attr.next_id;
		memset(&attr, 0, sizeof(attr));
		attr.btf_id = previous;
		fd = bpf_command(BPF_BTF_GET_FD_BY_ID, &attr);
		if (fd < 0)
			return -1;
		info.name = user_pointer(name);
		info.name_len = sizeof(name);
		memset(&attr, 0, sizeof(attr));
		attr.info.bpf_fd = (uint32_t)fd;
		attr.info.info_len = sizeof(info);
		attr.info.info = user_pointer(&info);
		if (bpf_command(BPF_OBJ_GET_INFO_BY_FD, &attr)) {
			close(fd);
			return -1;
		}
		name[sizeof(name) - 1] = '\0';
		if (info.kernel_btf && !strcmp(name, "cbpf_kfunc")) {
			printf("CBPF_KFUNC module_btf_id=%u acquire_id=%u read_id=%u release_id=%u\n",
			       info.id, CBPF_ACQUIRE_BTF_ID, CBPF_READ_BTF_ID,
			       CBPF_RELEASE_BTF_ID);
			return fd;
		}
		close(fd);
	}
	return -1;
}

static int confirm_guest_identity(void)
{
	struct utsname uts;

	if (getpid() != 1 || uname(&uts) || strcmp(uts.release, CBPF_EXPECTED_RELEASE))
		return -1;
	printf("CBPF_KFUNC kernel_release=%s\n", uts.release);
	return 0;
}

static int prepare_guest(void)
{
	int fd, result, saved_errno;

	if ((mkdir("/proc", 0555) && errno != EEXIST) ||
	    (mkdir("/sys", 0555) && errno != EEXIST))
		return -1;
	if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
	    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
		return -1;
	fd = open("/cbpf_kfunc.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	result = (int)syscall(SYS_finit_module, fd, "", 0);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return result;
}

static void poweroff(void)
{
	sync();
	reboot(RB_POWER_OFF);
	/* PID 1 must never return, including if poweroff unexpectedly fails. */
	for (;;)
		pause();
}

int main(void)
{
	static const int spills[] = { 0, -8, -16 };
	static const char *const aliases[] = { "copy", "spill8", "spill16" };
	static const char *const rejections[] = {
		"stale_copy", "stale_spill", "double_release", "missing_null", "leaked_ref",
	};
	struct totals totals = { 0 };
	struct counters final;
	struct program p;
	int module_fd = -1, result = -1;
	const char *stage = "prepare";

	setvbuf(stdout, NULL, _IONBF, 0);
	/* No module operation or reboot is permitted before identity matches. */
	if (confirm_guest_identity()) {
		puts("CBPF_KFUNC stage=identity poweroff=0 result=FAIL");
		return 1;
	}
	printf("CBPF_KFUNC scope=linux_kfunc_binding runtime_cheri=0 normal_verifier=1\n");
	if (prepare_guest())
		goto out;
	stage = "module_btf";
	module_fd = module_btf_fd();
	if (module_fd < 0)
		goto out;
	stage = "initial_accounting";
	if (snapshot(&final) || !balanced(&final) || final.acquisitions || final.reads)
		goto out;
	stage = "valid_cases";
	for (unsigned a = BPF_REG_6; a <= BPF_REG_7; ++a) {
		for (size_t alias = 0; alias < ARRAY_SIZE(spills); ++alias) {
			for (unsigned null_b = 0; null_b < 2; ++null_b) {
				char name[64];

				snprintf(name, sizeof(name), "%s_%s_a%u",
					 null_b ? "null_b" : "ab", aliases[alias], a);
				p = valid_ab(a, spills[alias], null_b);
				if (a == BPF_REG_6 && alias == 0 && !null_b)
					print_program(&p);
				if (run_valid(name, &p, module_fd, null_b ? 7 : 42,
					      null_b ? 1 : 2, null_b ? 0 : 1, 1, &totals))
					goto out;
			}
		}
	}
	p = valid_null();
	if (run_valid("first_null", &p, module_fd, 0, 0, 0, 1, &totals))
		goto out;
	stage = "repeated_runs";
	p = valid_ab(BPF_REG_7, -16, 0);
	if (run_valid("repeat_ab_spill16_a7", &p, module_fd, 42, 2, 1, 32, &totals))
		goto out;
	stage = "rejection_cases";
	for (size_t i = 0; i < ARRAY_SIZE(rejections); ++i)
		if (check_rejected(rejections[i], (enum rejection)i, module_fd, &totals))
			goto out;
	stage = "final_accounting";
	if (snapshot(&final) || !balanced(&final) ||
	    final.acquisitions != totals.acquisitions || final.reads != totals.reads ||
	    totals.positive_cases != 13 || totals.rejected_cases != 5 ||
	    totals.repeated_runs != 32 || totals.executions != 45)
		goto out;
	printf("CBPF_KFUNC positive_cases=%u rejected_cases=%u repeated_runs=%u executed_total=%u acquisitions=%llu releases=%llu reads=%llu live=0 object_refs=1\n",
	       totals.positive_cases, totals.rejected_cases, totals.repeated_runs,
	       totals.executions, (unsigned long long)final.acquisitions,
	       (unsigned long long)final.releases, (unsigned long long)final.reads);
	result = 0;
out:
	if (module_fd >= 0)
		close(module_fd);
	if (result)
		printf("CBPF_KFUNC stage=%s errno=%d result=FAIL\n", stage, errno);
	else
		puts("CBPF_KFUNC result=PASS");
	poweroff();
}
