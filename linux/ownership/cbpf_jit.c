// SPDX-License-Identifier: GPL-2.0-only
/*
 * CBPF's bounded Morello kfunc compiler. Transition framing follows the
 * Arm/Linaro Morello BPF RFC and CapeBPF's corrected transition patch 0029.
 * This compiler admits a small grammar after Linux's ordinary verifier; it
 * neither changes verified instructions nor falls back for its own programs.
 */
#include <linux/bpf.h>
#include <linux/cbpf.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include "bpf_jit.h"

#define CBPF_MAX_INSNS 64
#define CBPF_MAX_WORDS 1024
#define CAP_MOV       0xc2c1d000U
#define CAP_STR       0x82400000U
#define CAP_LDR       0x82600000U
#define CAP_BLRS      0xc2c23002U
#define CAP_RET_CLR   0xc2c253c0U
#define CAP_LDR_C16_SP 0xc24003f0U
#define CAP_RETR_C16  0xc2c25203U
#define CAP_GCTAG     0xc2c09000U

/* BPF r10 is represented only by the checked, fixed sidecar operations. */
static const u8 native_reg[] = { 7, 0, 1, 2, 3, 4, 19, 20, 21, 22 };
enum { UNINIT = 1, ZERO = 2, SCALAR = 4, HANDLE = 8 };
enum { CBPF_OP_ACQUIRE = 1, CBPF_OP_READ = 2, CBPF_OP_RELEASE = 3 };

struct cbpf_flow {
	u8 reg[10];
	u8 spill;
	bool reached;
};

struct cbpf_compiler {
	struct bpf_prog *prog;
	struct cbpf_flow flow[CBPF_MAX_INSNS + 1];
	u32 offset[CBPF_MAX_INSNS + 1];
	u8 operation[CBPF_MAX_INSNS];
	__le32 *image;
	u32 index, words, restricted_exit, executive_exit, executive_words;
	bool check, failed;
};

static u8 call_operation(const struct bpf_prog *prog,
			 const struct bpf_insn *insn)
{
	u64 address;
	bool fixed;

	if (insn->code != (BPF_JMP | BPF_CALL) ||
	    insn->src_reg != BPF_PSEUDO_KFUNC_CALL || insn->dst_reg ||
	    bpf_jit_get_func_addr(prog, insn, false, &address, &fixed) || !fixed)
		return 0;
	if (address == (unsigned long)cbpf_cap_acquire)
		return CBPF_OP_ACQUIRE;
	if (address == (unsigned long)cbpf_cap_read)
		return CBPF_OP_READ;
	if (address == (unsigned long)cbpf_cap_release)
		return CBPF_OP_RELEASE;
	return 0;
}

bool cbpf_jit_match(const struct bpf_prog *prog)
{
	u32 pc;

	for (pc = 0; pc < prog->len; pc++) {
		if (call_operation(prog, &prog->insnsi[pc])) {
			/* Also marks rejected programs so the caller forbids fallback. */
			prog->aux->cbpf_gate = true;
			return true;
		}
	}
	return prog->aux->cbpf_gate;
}

static bool scalar(u8 kind)
{
	return kind && !(kind & ~(ZERO | SCALAR));
}

static bool defined(u8 kind)
{
	return kind && !(kind & UNINIT);
}

static void join(struct cbpf_flow *destination, const struct cbpf_flow *source)
{
	u32 reg;

	if (!destination->reached) {
		*destination = *source;
		return;
	}
	for (reg = 0; reg < ARRAY_SIZE(source->reg); reg++)
		destination->reg[reg] |= source->reg[reg];
	destination->spill |= source->spill;
}

/* Forward-only control flow makes one increasing-PC pass a fixed point. */
static int admit(struct cbpf_compiler *c)
{
	struct cbpf_flow state, taken;
	u32 pc, reg, acquisitions = 0;
	bool has_exit = false;

	memset(c->flow[0].reg, UNINIT, sizeof(c->flow[0].reg));
	c->flow[0].spill = UNINIT;
	c->flow[0].reached = true;
	for (pc = 0; pc < c->prog->len; pc++) {
		const struct bpf_insn *i = &c->prog->insnsi[pc];
		u8 dst = i->dst_reg, src = i->src_reg;
		bool falls_through = true;

		/* No unreachable native fragments outside the checked grammar. */
		if (!c->flow[pc].reached)
			return -EINVAL;
		state = c->flow[pc];
		switch (i->code) {
		case BPF_ALU64 | BPF_MOV | BPF_X:
			if (dst > 9 || src > 9 || i->off || i->imm ||
			    !defined(state.reg[src]))
				return -EINVAL;
			state.reg[dst] = state.reg[src];
			break;
		case BPF_ALU64 | BPF_MOV | BPF_K:
			if (dst > 9 || src || i->off)
				return -EINVAL;
			state.reg[dst] = i->imm ? SCALAR : ZERO;
			break;
		case BPF_STX | BPF_MEM | BPF_DW:
			if (dst != BPF_REG_10 || src > 9 || i->off != -8 ||
			    i->imm || !defined(state.reg[src]))
				return -EINVAL;
			state.spill = state.reg[src];
			break;
		case BPF_LDX | BPF_MEM | BPF_DW:
			if (dst > 9 || src != BPF_REG_10 || i->off != -8 ||
			    i->imm || !defined(state.spill))
				return -EINVAL;
			state.reg[dst] = state.spill;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			if (dst > 9 || src || i->imm || i->off <= 0 ||
			    pc + 1 + i->off >= c->prog->len ||
			    !defined(state.reg[dst]) ||
			    (state.reg[dst] & ~(ZERO | HANDLE)))
				return -EINVAL;
			if (state.reg[dst] & ZERO) {
				taken = state;
				taken.reg[dst] = ZERO;
				join(&c->flow[pc + 1 + i->off], &taken);
			}
			state.reg[dst] &= ~ZERO;
			falls_through = !!state.reg[dst];
			break;
		case BPF_JMP | BPF_CALL:
			c->operation[pc] = call_operation(c->prog, i);
			if (c->operation[pc] == CBPF_OP_ACQUIRE) {
				if (!scalar(state.reg[1]) || ++acquisitions > 2)
					return -EINVAL;
				state.reg[0] = HANDLE | ZERO;
			} else if (c->operation[pc] == CBPF_OP_READ ||
				   c->operation[pc] == CBPF_OP_RELEASE) {
				if (state.reg[1] != HANDLE)
					return -EINVAL;
				state.reg[0] = c->operation[pc] == CBPF_OP_READ ?
					SCALAR : ZERO;
			} else {
				return -EINVAL;
			}
			for (reg = 1; reg <= 5; reg++)
				state.reg[reg] = UNINIT;
			break;
		case BPF_JMP | BPF_EXIT:
			if (dst || src || i->off || i->imm || !scalar(state.reg[0]))
				return -EINVAL;
			has_exit = true;
			falls_through = false;
			break;
		default:
			return -EOPNOTSUPP;
		}
		if (falls_through)
			join(&c->flow[pc + 1], &state);
	}
	return has_exit && acquisitions && !c->flow[c->prog->len].reached ?
		0 : -EINVAL;
}

static void word(struct cbpf_compiler *c, u32 instruction)
{
	if (c->index >= CBPF_MAX_WORDS ||
	    (c->image && c->index >= c->words) ||
	    instruction == AARCH64_BREAK_FAULT) {
		c->failed = true;
		return;
	}
	if (c->image) {
		if (c->check) {
			if (le32_to_cpu(c->image[c->index]) != instruction)
				c->failed = true;
		} else {
			c->image[c->index] = cpu_to_le32(instruction);
		}
	}
	c->index++;
}

static void immediate(struct cbpf_compiler *c, u8 reg, u64 value)
{
	u32 shift;

	word(c, A64_MOVZ(1, reg, value & 0xffff, 0));
	for (shift = 16; shift < 64; shift += 16)
		word(c, A64_MOVK(1, reg, (value >> shift) & 0xffff, shift));
}

static void clear_registers(struct cbpf_compiler *c, bool entering)
{
	u32 reg;

	for (reg = 0; reg < 30; reg++) {
		if (entering ? (reg == 15 || reg == 17) : reg == 7)
			continue;
		word(c, A64_MOVZ(1, reg, 0, 0));
	}
}

static void prologue(struct cbpf_compiler *c)
{
	u32 reg;

	if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL))
		word(c, A64_BTI_JC);
	word(c, A64_MOV(1, A64_R(9), A64_LR));
	word(c, A64_NOP); /* Preserve the stock entry layout; attachment forbidden. */
	if (IS_ENABLED(CONFIG_ARM64_PTR_AUTH_KERNEL))
		word(c, A64_PACIASP);
	word(c, A64_PUSH(A64_FP, A64_LR, A64_SP));
	word(c, A64_MOV(1, A64_FP, A64_SP));
	for (reg = 19; reg < 29; reg += 2)
		word(c, A64_PUSH(reg, reg + 1, A64_SP));
	word(c, A64_PUSH(A64_ZR, A64_ZR, A64_SP)); /* Sealed caller slot. */
	word(c, A64_SUB_I(1, A64_SP, A64_SP, 16)); /* Private spill sidecar. */
	word(c, A64_MOV(1, A64_R(0), A64_SP));
	word(c, A64_MOVZ(1, A64_R(1), 16, 0));
	word(c, A64_ADR(A64_R(2), ((s32)c->executive_exit - (s32)c->index) * 4));
	word(c, A64_MOVZ(1, A64_R(3), c->executive_words * 4, 0));
	word(c, A64_MOV(1, A64_R(4), A64_R(9)));
	immediate(c, 5, (unsigned long)c->prog);
	immediate(c, 10, (unsigned long)cbpf_enter);
	word(c, A64_BLR(A64_R(10)));
	/* Successful entry resumes here with x0=0 in restricted mode. */
	word(c, A64_CBZ(1, A64_R(0), 3));
	word(c, A64_MOVZ(1, A64_R(7), 0, 0));
	word(c, A64_B((s32)c->executive_exit - (s32)c->index));
	clear_registers(c, true);
}

static void body(struct cbpf_compiler *c)
{
	u32 pc;

	for (pc = 0; pc < c->prog->len; pc++) {
		const struct bpf_insn *i = &c->prog->insnsi[pc];

		if (!c->image)
			c->offset[pc] = c->index;
		else if (c->offset[pc] != c->index)
			c->failed = true;
		switch (i->code) {
		case BPF_ALU64 | BPF_MOV | BPF_X:
			word(c, CAP_MOV | (native_reg[i->src_reg] << 5) |
			     native_reg[i->dst_reg]);
			break;
		case BPF_ALU64 | BPF_MOV | BPF_K:
			immediate(c, native_reg[i->dst_reg], (s64)i->imm);
			break;
		case BPF_STX | BPF_MEM | BPF_DW:
			word(c, CAP_STR | (31 << 5) | native_reg[i->src_reg]);
			break;
		case BPF_LDX | BPF_MEM | BPF_DW:
			word(c, CAP_LDR | (31 << 5) | native_reg[i->dst_reg]);
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			word(c, A64_CBZ(1, native_reg[i->dst_reg],
			     (s32)c->offset[pc + 1 + i->off] - (s32)c->index));
			break;
		case BPF_JMP | BPF_CALL:
			word(c, A64_MOVZ(1, A64_R(4), c->operation[pc], 0));
			word(c, A64_MOVZ(1, A64_R(5), pc, 0));
			word(c, CAP_MOV | (30 << 5) | 13);
			word(c, CAP_BLRS | (17 << 5));
			word(c, CAP_MOV | (0 << 5) | 7);
			break;
		case BPF_JMP | BPF_EXIT:
			word(c, A64_B((s32)c->restricted_exit - (s32)c->index));
			break;
		default:
			c->failed = true;
		}
	}
	if (!c->image)
		c->offset[pc] = c->index;
	else if (c->offset[pc] != c->index)
		c->failed = true;
}

static void epilogue(struct cbpf_compiler *c)
{
	int reg;
	u32 start;

	if (!c->image)
		c->restricted_exit = c->index;
	else if (c->restricted_exit != c->index)
		c->failed = true;
	word(c, CAP_RET_CLR);
	if (!c->image)
		c->executive_exit = c->index;
	else if (c->executive_exit != c->index)
		c->failed = true;
	start = c->index;
	/* Normal return, entry rejection and terminal gate abort share scrub. */
	word(c, A64_STR64I(A64_ZR, A64_SP, 0));
	word(c, A64_STR64I(A64_ZR, A64_SP, 8));
	word(c, A64_MOV(1, A64_R(7), A64_R(7))); /* Scalarize result. */
	clear_registers(c, false);
	word(c, A64_ADD_I(1, A64_SP, A64_SP, 16));
	word(c, CAP_LDR_C16_SP);
	word(c, A64_ADD_I(1, A64_SP, A64_SP, 16));
	for (reg = 27; reg >= 19; reg -= 2)
		word(c, A64_POP(reg, reg + 1, A64_SP));
	word(c, A64_POP(A64_FP, A64_LR, A64_SP));
	word(c, A64_MOV(1, A64_R(0), A64_R(7)));
	if (IS_ENABLED(CONFIG_ARM64_PTR_AUTH_KERNEL))
		word(c, A64_AUTIASP);
	word(c, CAP_GCTAG | (16 << 5) | 10);
	word(c, A64_CBZ(1, A64_R(10), 2));
	word(c, CAP_RETR_C16);
	word(c, A64_RET(A64_LR)); /* Only the executive entry-error path. */
	if (!c->image)
		c->executive_words = c->index - start;
	else if (c->executive_words != c->index - start)
		c->failed = true;
}

static void generate(struct cbpf_compiler *c)
{
	c->index = 0;
	prologue(c);
	body(c);
	epilogue(c);
}

static void fill_hole(void *area, unsigned int size)
{
	__le32 *words = area;
	u32 i;

	for (i = 0; i < size / sizeof(*words); i++)
		words[i] = cpu_to_le32(AARCH64_BREAK_FAULT);
}

struct bpf_prog *cbpf_jit_compile(struct bpf_prog *prog)
{
	struct cbpf_compiler *c;
	struct bpf_binary_header *header = NULL;
	u8 *image;
	u32 pc;
	int error = -EOPNOTSUPP;

	prog->aux->cbpf_gate = true;
	if (!prog->jit_requested || bpf_jit_blinding_enabled(prog) ||
	    prog->type != BPF_PROG_TYPE_SCHED_CLS || prog->is_func ||
	    prog->aux->func_cnt || prog->aux->func_info_cnt || prog->aux->used_map_cnt ||
	    !prog->len || prog->len > CBPF_MAX_INSNS)
		goto rejected;
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		error = -ENOMEM;
		goto rejected;
	}
	c->prog = prog;
	error = admit(c);
	if (error)
		goto free_context;
	generate(c); /* Layout only; instruction and branch lengths are fixed. */
	c->words = c->index;
	if (c->failed || !c->words) {
		error = -EINVAL;
		goto free_context;
	}
	header = bpf_jit_binary_alloc(c->words * 4, &image, 4, fill_hole);
	if (!header) {
		error = -ENOMEM;
		goto free_context;
	}
	c->image = (__le32 *)image;
	generate(c);
	/*
	 * Check every final word against the admitted instruction templates and
	 * fixed transition envelope. Branch operands are derived only from the
	 * recorded starts of admitted BPF instructions or the two fixed exits.
	 * This shares the encoder with generation: it is not an independent
	 * decoder or a proof of compiler correctness.
	 */
	c->check = true;
	generate(c);
	if (c->failed || c->index != c->words) {
		error = -EINVAL;
		bpf_jit_binary_free(header);
		goto free_context;
	}
	pr_info("CBPF_NATIVE accepted insns=%u words=%u entry=%px restricted_exit=%u executive_exit=%u template_check=pass\n",
		prog->len, c->words, image, c->restricted_exit, c->executive_exit);
	for (pc = 0; pc < prog->len; pc++)
		pr_info("CBPF_NATIVE map pc=%u begin=%u end=%u code=%02x op=%u\n",
			pc, c->offset[pc], c->offset[pc + 1],
			prog->insnsi[pc].code, c->operation[pc]);
	for (pc = 0; pc < c->words; pc++)
		pr_info("CBPF_NATIVE word index=%u value=%08x\n", pc,
			le32_to_cpu(c->image[pc]));
	flush_icache_range((unsigned long)header,
			   (unsigned long)(c->image + c->words));
	bpf_jit_binary_lock_ro(header);
	prog->bpf_func = (void *)image;
	prog->jited_len = c->words * 4;
	prog->jited = 1;
	for (pc = 0; pc <= prog->len; pc++)
		c->offset[pc] *= 4;
	bpf_prog_fill_jited_linfo(prog, c->offset + 1);
	kfree(c);
	return prog;

free_context:
	kfree(c);
rejected:
	pr_info("CBPF_NATIVE rejected error=%d fallback=forbidden\n", error);
	return prog;
}
