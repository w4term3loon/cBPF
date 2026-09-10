// SPDX-License-Identifier: GPL-2.0-only
/* Seven-byte logical extent, eight-byte stride; one valid last-byte access. */
#ifndef __CHERI_PURE_CAPABILITY__
#error "spatial native witness requires the dedicated Morello purecap guest"
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

#define EXPECTED_RELEASE "6.7.0-cbpf-spatial-native"
#define PROGRAM_NAME "cbpf_spatial"
#define I(C, D, S, O, V) \
	{ .code = (C), .dst_reg = (D), .src_reg = (S), .off = (O), .imm = (V) }

_Static_assert(sizeof(struct bpf_insn) == 8, "Unexpected BPF instruction ABI");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "spatial native witness requires little endian");

static char verifier_log[128 * 1024];
static uint32_t native_words[2048];
static struct bpf_insn translated[256];
static unsigned map_creates, map_updates, map_lookups, prog_loads, test_runs, infos;
static int last_errno;

/* The matching Morello UAPI carries full purecap pointers in syscall fields. */
static __kernel_aligned_uintptr_t pointer(const void *p)
{
	return (__kernel_aligned_uintptr_t)(uintptr_t)p;
}

static int command(unsigned cmd, union bpf_attr *attr)
{
	int result;

	switch (cmd) {
	case BPF_MAP_CREATE: ++map_creates; break;
	case BPF_MAP_UPDATE_ELEM: ++map_updates; break;
	case BPF_MAP_LOOKUP_ELEM: ++map_lookups; break;
	case BPF_PROG_LOAD: ++prog_loads; break;
	case BPF_PROG_TEST_RUN: ++test_runs; break;
	case BPF_OBJ_GET_INFO_BY_FD: ++infos; break;
	default: return -1;
	}
	result = (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
	last_errno = result < 0 ? errno : 0;
	return result;
}

static int get_info(int fd, void *info, unsigned size)
{
	union bpf_attr attr = { 0 };

	attr.info.bpf_fd = fd;
	attr.info.info_len = size;
	attr.info.info = pointer(info);
	if (command(BPF_OBJ_GET_INFO_BY_FD, &attr) || attr.info.info_len != size)
		return -1;
	return 0;
}

static int read_value(int fd, const uint32_t *key, void *value)
{
	union bpf_attr attr = { 0 };

	attr.map_fd = fd;
	attr.key = pointer(key);
	attr.value = pointer(value);
	return command(BPF_MAP_LOOKUP_ELEM, &attr);
}

static void print_bpf(const char *kind, const struct bpf_insn *insns,
		      unsigned count)
{
	for (unsigned pc = 0; pc < count; ++pc) {
		const struct bpf_insn *i = &insns[pc];

		printf("CBPF_SPATIAL_NATIVE bpf kind=%s pc=%u code=%02x dst=%u src=%u off=%d imm=%d\n",
		       kind, pc, (unsigned)i->code, (unsigned)i->dst_reg,
		       (unsigned)i->src_reg, (int)i->off, (int)i->imm);
	}
}

static int run_control(void)
{
	struct bpf_insn program[] = {
		I(BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, 1),       /* 0: key */
		I(BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0),
		I(BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4),
		I(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 0),
		I(0, 0, 0, 0, 0),
		I(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		I(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5, 0),       /* 6 -> 12 */
		I(BPF_LDX | BPF_MEM | BPF_B, 1, 0, 6, 0),       /* 7: last valid byte */
		I(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 1),
		I(BPF_STX | BPF_MEM | BPF_B, 0, 1, 6, 0),       /* 9: same byte */
		I(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),
		I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
		I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),     /* NULL */
		I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
	};
	const unsigned original_count = sizeof(program) / sizeof(program[0]);
	static const char license[] = "GPL";
	struct bpf_map_info map = { 0 };
	struct bpf_prog_info sizing = { 0 }, info = { 0 };
	union bpf_attr attr = { 0 };
	uint32_t key = 1, map_id = 0, function_length = 0;
	const unsigned char value[7] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 41 };
	unsigned char readback[7] = { 0 };
	uint64_t native_entry = 0;
	unsigned char input[64] = { 0 }, output[64] = { 0 };
	char authorization[32];
	const char *stage = "map_create";
	int map_fd = -1, prog_fd = -1, result = 1;
	unsigned retval = 0;

	puts("CBPF_SPATIAL_NATIVE begin program=" PROGRAM_NAME
	     " prog_flags=0 map_flags=0 key=1 key_size=4 value_size=7 max_entries=2 access_offset=6 access_bytes=1");
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(key);
	attr.value_size = sizeof(value);
	attr.max_entries = 2;
	memcpy(attr.map_name, "cbpf_array", sizeof("cbpf_array"));
	map_fd = command(BPF_MAP_CREATE, &attr);
	if (map_fd < 0)
		goto out;
	stage = "map_info";
	if (get_info(map_fd, &map, sizeof(map)) || !map.id ||
	    map.type != BPF_MAP_TYPE_ARRAY || map.key_size != 4 ||
	    map.value_size != 7 || map.max_entries != 2 || map.map_flags ||
	    map.ifindex || map.btf_id || map.btf_key_type_id ||
	    map.btf_value_type_id || map.btf_vmlinux_value_type_id || map.map_extra)
		goto out;
	stage = "map_initialize";
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = pointer(&key);
	attr.value = pointer(&value);
	attr.flags = BPF_ANY;
	if (command(BPF_MAP_UPDATE_ELEM, &attr) ||
	    read_value(map_fd, &key, readback) || memcmp(readback, value, sizeof(value)))
		goto out;
	printf("CBPF_SPATIAL_NATIVE map map_id=%u map_fd=%d key=1 initial=41 map_readback=%u map_flags=%u btf_id=%u value_bytes=11223344556629\n",
	       map.id, map_fd, (unsigned)readback[6], map.map_flags, map.btf_id);

	/* The sole relocation is fixed before verification and never changed again. */
	program[3].imm = map_fd;
	print_bpf("original", program, original_count);
	stage = "program_load";
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = original_count;
	attr.insns = pointer(program);
	attr.license = pointer(license);
	attr.log_level = 2;
	attr.log_buf = pointer(verifier_log);
	attr.log_size = sizeof(verifier_log);
	memcpy(attr.prog_name, PROGRAM_NAME, sizeof(PROGRAM_NAME));
	prog_fd = command(BPF_PROG_LOAD, &attr);
	verifier_log[sizeof(verifier_log) - 1] = '\0';
	printf("CBPF_SPATIAL_NATIVE verifier_begin\n%s\nCBPF_SPATIAL_NATIVE verifier_end\n", verifier_log);
	if (prog_fd < 0)
		goto out;

	stage = "program_info_size";
	if (get_info(prog_fd, &sizing, sizeof(sizing)) ||
	    sizing.type != BPF_PROG_TYPE_SOCKET_FILTER || !sizing.id ||
	    !sizing.jited_prog_len || sizing.jited_prog_len > sizeof(native_words) ||
	    sizing.jited_prog_len % sizeof(native_words[0]) ||
	    !sizing.xlated_prog_len || sizing.xlated_prog_len > sizeof(translated) ||
	    sizing.xlated_prog_len % sizeof(translated[0]) ||
	    sizing.nr_map_ids != 1 || sizing.nr_jited_ksyms != 1 ||
	    sizing.nr_jited_func_lens != 1 || sizing.ifindex || sizing.btf_id ||
	    memcmp(sizing.name, PROGRAM_NAME, sizeof(PROGRAM_NAME)))
		goto out;
	info.jited_prog_len = sizing.jited_prog_len;
	info.xlated_prog_len = sizing.xlated_prog_len;
	info.jited_prog_insns = pointer(native_words);
	info.xlated_prog_insns = pointer(translated);
	info.nr_map_ids = 1;
	info.map_ids = pointer(&map_id);
	info.nr_jited_ksyms = 1;
	info.jited_ksyms = pointer(&native_entry);
	info.nr_jited_func_lens = 1;
	info.jited_func_lens = pointer(&function_length);
	stage = "program_info_complete";
	if (get_info(prog_fd, &info, sizeof(info)) || info.id != sizing.id ||
	    info.type != sizing.type || info.jited_prog_len != sizing.jited_prog_len ||
	    info.xlated_prog_len != sizing.xlated_prog_len ||
	    info.jited_prog_insns != pointer(native_words) ||
	    info.xlated_prog_insns != pointer(translated) ||
	    info.nr_map_ids != 1 || info.map_ids != pointer(&map_id) || map_id != map.id ||
	    info.nr_jited_ksyms != 1 || info.jited_ksyms != pointer(&native_entry) ||
	    !native_entry || native_entry % 4 || info.nr_jited_func_lens != 1 ||
	    info.jited_func_lens != pointer(&function_length) ||
	    function_length != info.jited_prog_len)
		goto out;
	print_bpf("translated", translated, info.xlated_prog_len / sizeof(translated[0]));
	for (unsigned index = 0; index < info.jited_prog_len / sizeof(native_words[0]); ++index)
		printf("CBPF_SPATIAL_NATIVE word index=%u value=%08x\n", index, native_words[index]);
	printf("CBPF_SPATIAL_NATIVE image prog_id=%u map_id=%u original_count=%u translated_count=%u native_entry=0x%llx jited_len=%u nr_jited_ksyms=%u nr_jited_func_lens=%u func_len=%u\n",
	       info.id, map.id, original_count,
	       (unsigned)(info.xlated_prog_len / sizeof(translated[0])),
	       (unsigned long long)native_entry, info.jited_prog_len,
	       info.nr_jited_ksyms, info.nr_jited_func_lens, function_length);

	/* Hold both FDs and the unchanged map while the host reviews this receipt. */
	stage = "authorization";
	printf("CBPF_SPATIAL_NATIVE_READY map_id=%u prog_id=%u held_map_fd=%d held_prog_fd=%d executed=0\n",
	       map.id, info.id, map_fd, prog_fd);
	if (!fgets(authorization, sizeof(authorization), stdin) ||
	    strcmp(authorization, "CBPF_SPATIAL_NATIVE_EXECUTE\n"))
		goto out;
	puts("CBPF_SPATIAL_NATIVE authorization=accepted test_run_count=0");
	stage = "test_run";
	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = prog_fd;
	attr.test.data_in = pointer(input);
	attr.test.data_size_in = sizeof(input);
	attr.test.data_out = pointer(output);
	attr.test.data_size_out = sizeof(output);
	attr.test.repeat = 1;
	if (command(BPF_PROG_TEST_RUN, &attr))
		goto out;
	retval = attr.test.retval;
	stage = "map_readback";
	if (read_value(map_fd, &key, readback) || retval != 42 || readback[6] != 42 ||
	    memcmp(readback, value, 6) ||
	    map_creates != 1 || map_updates != 1 || prog_loads != 1 || test_runs != 1)
		goto out;
	stage = "complete";
	result = 0;
out:
	printf("CBPF_SPATIAL_NATIVE result=%s stage=%s map_id=%u prog_id=%u loaded=%u map_create_count=%u map_update_count=%u map_lookup_count=%u prog_load_count=%u test_run_count=%u info_count=%u retval=%u readback=%u errno=%d attached=0 unchanged_prefix=%u value_bytes=%02x%02x%02x%02x%02x%02x%02x\n",
	       result ? "FAIL" : "PASS", stage, map.id, info.id, prog_fd >= 0,
	       map_creates, map_updates, map_lookups, prog_loads, test_runs, infos,
	       retval, (unsigned)readback[6], last_errno, !memcmp(readback, value, 6),
	       (unsigned)readback[0], (unsigned)readback[1], (unsigned)readback[2],
	       (unsigned)readback[3], (unsigned)readback[4], (unsigned)readback[5],
	       (unsigned)readback[6]);
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	return result;
}

int main(void)
{
	struct utsname identity;
	int result;

	setvbuf(stdout, NULL, _IONBF, 0);
	/* Outside this exact PID1 guest, refuse both BPF operations and poweroff. */
	if (getpid() != 1 || uname(&identity) || strcmp(identity.release, EXPECTED_RELEASE)) {
		puts("CBPF_SPATIAL_NATIVE identity=FAIL test_run_count=0 poweroff=0");
		return 1;
	}
	printf("CBPF_SPATIAL_NATIVE kernel=%s pid=1 normal_verifier=1 attached=0\n", identity.release);
	printf("CBPF_SPATIAL_NATIVE kernel_version=%s\n", identity.version);
	result = run_control();
	printf("CBPF_SPATIAL_NATIVE poweroff=begin result=%s\n", result ? "FAIL" : "PASS");
	sync();
	if (reboot(RB_POWER_OFF))
		printf("CBPF_SPATIAL_NATIVE poweroff=FAIL errno=%d\n", errno);
	for (;;)
		pause();
}
