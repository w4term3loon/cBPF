	.text
	.file	"gate.c"
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3, 0x0                          // -- Begin function cbpf_gate_run
.LCPI0_0:
	.word	42                              // 0x2a
	.word	1                               // 0x1
	.size	.LCPI0_0, 8
.LCPI0_1:
	.word	0                               // 0x0
	.word	7                               // 0x7
	.size	.LCPI0_1, 8
.LCPI0_2:
	.word	2                               // 0x2
	.word	5                               // 0x5
	.size	.LCPI0_2, 8
	.text
	.globl	cbpf_gate_run
	.p2align	2
	.type	cbpf_gate_run,@function
cbpf_gate_run:                          // @cbpf_gate_run
.Lfunc_begin0:
	.cfi_startproc
// %bb.0:                               // %entry
	sub	csp, csp, #368
	.cfi_def_cfa csp, -368
	stp	c29, c30, [csp, #224]           // 32-byte Folded Spill
	str	c28, [csp, #256]                // 16-byte Folded Spill
	stp	c24, c23, [csp, #272]           // 32-byte Folded Spill
	stp	c22, c21, [csp, #304]           // 32-byte Folded Spill
	stp	c20, c19, [csp, #336]           // 32-byte Folded Spill
	add	c29, csp, #224
	.cfi_def_cfa c29, 144
	.cfi_offset c19, -16
	.cfi_offset c20, -32
	.cfi_offset c21, -48
	.cfi_offset c22, -64
	.cfi_offset c23, -80
	.cfi_offset c24, -96
	.cfi_offset c28, -112
	.cfi_offset c30, -128
	.cfi_offset c29, -144
	.cfi_remember_state
	movi	v0.2d, #0000000000000000
	mov	c20, c3
	mov	c22, c0
	sub	c0, c29, #48
	mov	w8, #16                         // =0x10
	mov	w23, #1                         // =0x1
	mov	x21, x1
	scbnds	c1, c0, #48                     // =48
	cmp	x20, #0
	mov	c19, c2
	csel	c24, c1, c3, eq
	csel	c0, c0, c3, eq
	stp	q0, q0, [c24, #16]
	mov	w1, wzr
	str	q0, [c24]
	stp	x8, x8, [c0, #24]
	str	w23, [c0, #40]
	mov	c0, c2
	mov	w2, #1656                       // =0x678
	bl	memset
	mov	x1, x21
	str	w23, [c19, #44]
	add	c23, c19, #8
	mov	c0, c22
	mov	c2, c23
	bl	cbpf_validate
	cbz	w0, .LBB0_53
// %bb.1:                               // %if.end
	movi	v1.2d, #0000000000000000
	adrp	c1, .LCPI0_0
	ldr	d0, [c1, :lo12:.LCPI0_0]
	add	c0, csp, #96
	add	c1, csp, #32
	mov	c2, csp
	scbnds	c0, c0, #5, lsl #4              // =80
	scbnds	c1, c1, #4, lsl #4              // =64
	scbnds	c2, c2, #32                     // =32
	stp	q1, q1, [c0, #48]
	stp	q1, q1, [c0, #16]
	str	q1, [c0]
	str	d0, [csp, #96]
	stp	q1, q1, [c1, #32]
	stp	q1, q1, [c1]
	stp	q1, q1, [c2]
	cbz	x21, .LBB0_55
// %bb.2:                               // %for.body.lr.ph
	mov	x10, #-2                        // =0xfffffffffffffffe
	mov	w11, #1                         // =0x1
	mov	x8, xzr
	movk	x10, #65533, lsl #16
	movk	w11, #2, lsl #16
	mov	w12, #24                        // =0x18
	cmp	x20, #0
	sub	c3, c29, #48
	csel	c3, c3, c20, eq
	adrp	c4, .LJTI0_0
	add	c4, c4, :lo12:.LJTI0_0
.LBB0_3:                                // %for.body
                                        // =>This Loop Header: Depth=1
                                        //     Child Loop BB0_39 Depth 2
                                        //     Child Loop BB0_34 Depth 2
                                        //     Child Loop BB0_29 Depth 2
                                        //     Child Loop BB0_43 Depth 2
                                        //     Child Loop BB0_22 Depth 2
                                        //     Child Loop BB0_17 Depth 2
	add	x9, x8, x8, lsl #1
	add	c5, c22, x9, uxtx #3
	ldp	w9, w14, [c5]
	ldr	w16, [c5, #8]
	ldr	x15, [c5, #16]
	cmp	w9, #7
	str	x8, [c23]
	b.hi	.LBB0_63
// %bb.4:                               // %for.body
                                        //   in Loop: Header=BB0_3 Depth=1
	adr	c5, .LBB0_5
	ldrh	w17, [c4, x9, lsl #1]
	add	c5, c5, x17, uxtx #2
	add	x13, x8, #1
	cvtp	x17, c5
	br	x17
.LBB0_5:                                // %sw.bb
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w16, [c24]
	add	w16, w16, #1
	str	w16, [c24]
	cbz	w15, .LBB0_52
// %bb.6:                               // %if.end.i
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w17, [c19, #24]
	cmp	w17, #2
	b.eq	.LBB0_66
// %bb.7:                               // %if.end2.i
                                        //   in Loop: Header=BB0_3 Depth=1
	add	c5, c0, x17, uxtx #4
	add	c6, c5, #16
	scbnds	c5, c6, #16                     // =16
	clrperm	c5, c5, x10
	gctag	x15, c5
	cbz	x15, .LBB0_54
// %bb.8:                               // %lor.lhs.false.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	gcseal	x15, c5
	cbnz	x15, .LBB0_54
// %bb.9:                               // %lor.lhs.false1.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	cmp	x5, x6
	b.ne	.LBB0_54
// %bb.10:                              // %lor.lhs.false2.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	gcbase	x15, c5
	cmp	x15, x5
	b.ne	.LBB0_54
// %bb.11:                              // %lor.lhs.false4.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	gclen	x15, c5
	cmp	x15, #16
	b.ne	.LBB0_54
// %bb.12:                              // %lor.lhs.false6.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	gcperm	x15, c5
	cmp	w15, w11
	b.ne	.LBB0_54
// %bb.13:                              // %if.end6.i
                                        //   in Loop: Header=BB0_3 Depth=1
	str	c0, [c6, #0]
	add	w16, w17, #1
	ldr	w15, [csp, #100]
	add	c6, c0, #48
	add	w15, w15, #1
	str	w15, [csp, #100]
	ldr	w15, [csp, #100]
	str	w16, [c19, #24]
	str	c5, [c6, x17, lsl #4]
	str	c5, [c1, x14, lsl #4]
	str	w15, [c19, #44]
	ldr	w15, [c3, #16]
	add	w18, w15, #1
	mov	x15, x13
	str	w18, [c3, #16]
	b	.LBB0_47
.LBB0_14:                               // %sw.bb7
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	c5, [c1, x16, lsl #4]
	chkeq	c5, czr
	str	c5, [c1, x14, lsl #4]
	cset	w15, eq
	tbnz	w15, #0, .LBB0_25
// %bb.15:                              // %for.cond.preheader.i
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w14, [c19, #24]
	cbz	w14, .LBB0_54
// %bb.16:                              // %for.body.preheader.i
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x15, xzr
.LBB0_17:                               // %for.body.i
                                        //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	lsl	x16, x15, #4
	add	x16, x16, #48
	ldr	c6, [c0, x16]
	chkeq	c5, c6
	cset	w16, eq
	cmp	w16, #1
	b.eq	.LBB0_45
// %bb.18:                              // %for.inc.i
                                        //   in Loop: Header=BB0_17 Depth=2
	add	x15, x15, #1
	cmp	x14, x15
	b.ne	.LBB0_17
	b	.LBB0_54
.LBB0_19:                               // %sw.bb17
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	c5, [c1, x16, lsl #4]
	chkeq	c5, czr
	str	c5, [c2, x14, lsl #4]
	cset	w15, eq
	tbnz	w15, #0, .LBB0_25
// %bb.20:                              // %for.cond.preheader.i191
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w14, [c19, #24]
	cbz	w14, .LBB0_54
// %bb.21:                              // %for.body.preheader.i193
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x15, xzr
.LBB0_22:                               // %for.body.i195
                                        //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	lsl	x16, x15, #4
	add	x16, x16, #48
	ldr	c6, [c0, x16]
	chkeq	c5, c6
	cset	w16, eq
	cmp	w16, #1
	b.eq	.LBB0_45
// %bb.23:                              // %for.inc.i198
                                        //   in Loop: Header=BB0_22 Depth=2
	add	x15, x15, #1
	cmp	x14, x15
	b.ne	.LBB0_22
	b	.LBB0_54
.LBB0_24:                               // %sw.bb29
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	c5, [c2, x16, lsl #4]
	chkeq	c5, czr
	str	c5, [c1, x14, lsl #4]
	cset	w15, eq
	tbz	w15, #0, .LBB0_41
.LBB0_25:                               //   in Loop: Header=BB0_3 Depth=1
	mov	w16, wzr
	b	.LBB0_46
.LBB0_26:                               // %sw.bb41
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	c5, [c1, x14, lsl #4]
	ldr	w14, [c3, #4]
	add	w14, w14, #1
	chkeq	c5, czr
	cset	w15, eq
	str	w14, [c3, #4]
	tbnz	w15, #0, .LBB0_62
// %bb.27:                              // %for.cond.preheader.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w15, [c19, #24]
	cbz	w15, .LBB0_54
// %bb.28:                              // %for.body.preheader.i.i
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x14, xzr
.LBB0_29:                               // %for.body.i.i
                                        //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	lsl	x16, x14, #4
	add	x17, x16, #48
	ldr	c6, [c0, x17]
	chkeq	c5, c6
	cset	w17, eq
	tbnz	w17, #0, .LBB0_48
// %bb.30:                              // %for.inc.i.i
                                        //   in Loop: Header=BB0_29 Depth=2
	add	x14, x14, #1
	cmp	x15, x14
	b.ne	.LBB0_29
	b	.LBB0_54
.LBB0_31:                               // %sw.bb46
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	c5, [c1, x14, lsl #4]
	ldr	w14, [c3, #8]
	add	w14, w14, #1
	chkeq	c5, czr
	cset	w15, eq
	str	w14, [c3, #8]
	tbnz	w15, #0, .LBB0_62
// %bb.32:                              // %for.cond.preheader.i.i228
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w15, [c19, #24]
	cbz	w15, .LBB0_54
// %bb.33:                              // %for.body.preheader.i.i230
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x14, xzr
.LBB0_34:                               // %for.body.i.i232
                                        //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	lsl	x16, x14, #4
	add	x17, x16, #48
	ldr	c6, [c0, x17]
	chkeq	c5, c6
	cset	w17, eq
	tbnz	w17, #0, .LBB0_50
// %bb.35:                              // %for.inc.i.i235
                                        //   in Loop: Header=BB0_34 Depth=2
	add	x14, x14, #1
	cmp	x15, x14
	b.ne	.LBB0_34
	b	.LBB0_54
.LBB0_36:                               // %sw.bb51
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	c5, [c1, x14, lsl #4]
	mov	w16, wzr
	chkeq	c5, czr
	cset	w14, eq
	tbnz	w14, #0, .LBB0_47
// %bb.37:                              // %for.cond.preheader.i242
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w14, [c19, #24]
	cbz	w14, .LBB0_54
// %bb.38:                              // %for.body.preheader.i244
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x15, xzr
.LBB0_39:                               // %for.body.i246
                                        //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	lsl	x16, x15, #4
	add	x16, x16, #48
	ldr	c6, [c0, x16]
	chkeq	c5, c6
	cset	w16, eq
	tbnz	w16, #0, .LBB0_45
// %bb.40:                              // %for.inc.i249
                                        //   in Loop: Header=BB0_39 Depth=2
	add	x15, x15, #1
	cmp	x14, x15
	b.ne	.LBB0_39
	b	.LBB0_54
.LBB0_41:                               // %for.cond.preheader.i205
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w14, [c19, #24]
	cbz	w14, .LBB0_54
// %bb.42:                              // %for.body.preheader.i207
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x15, xzr
.LBB0_43:                               // %for.body.i209
                                        //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	lsl	x16, x15, #4
	add	x16, x16, #48
	ldr	c6, [c0, x16]
	chkeq	c5, c6
	cset	w16, eq
	cmp	w16, #1
	b.eq	.LBB0_45
// %bb.44:                              // %for.inc.i212
                                        //   in Loop: Header=BB0_43 Depth=2
	add	x15, x15, #1
	cmp	x14, x15
	b.ne	.LBB0_43
	b	.LBB0_54
.LBB0_45:                               // %if.end4.i
                                        //   in Loop: Header=BB0_3 Depth=1
	add	w16, w15, #1
.LBB0_46:                               // %cleanup
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	x15, x13
.LBB0_47:                               // %cleanup
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	x13, [c19, #64]
	mov	x14, #72                        // =0x48
	cmp	x15, x21
	madd	x14, x13, x12, x14
	add	x13, x13, #1
	str	x13, [c19, #64]
	ldr	w13, [c19, #44]
	add	c5, c19, x14, uxtx
	str	x8, [c5, #8]
	mov	x8, x15
	stp	wzr, w9, [c5]
	stp	w16, w13, [c5, #16]
	b.lo	.LBB0_3
	b	.LBB0_55
.LBB0_48:                               // %if.end.i222
                                        //   in Loop: Header=BB0_3 Depth=1
	add	x15, x16, #16
	ldr	c5, [c0, x15]
	gctag	x15, c5
	cbz	x15, .LBB0_65
// %bb.49:                              // %if.end7.i
                                        //   in Loop: Header=BB0_3 Depth=1
	ldr	w17, [c5]
	add	x16, x14, #1
	ldr	w15, [c19, #28]
	str	w17, [c19, #40]
	add	w18, w15, #1
	mov	x15, x13
	str	w18, [c19, #28]
	b	.LBB0_47
.LBB0_50:                               // %if.end.i238
                                        //   in Loop: Header=BB0_3 Depth=1
	add	x15, x16, #16
	ldr	c5, [c0, x15]
	gctag	x16, c5
	cbz	x16, .LBB0_65
// %bb.51:                              // %consume.exit.i
                                        //   in Loop: Header=BB0_3 Depth=1
	clrtag	c6, c5
	lsl	x16, x14, #2
	str	c6, [c0, x15]
	add	x17, x16, #48
	ldr	w15, [c3, #20]
	add	x16, x14, #1
                                        // kill: def $w16 killed $w16 killed $x16 def $x16
	add	w15, w15, #1
	str	w15, [c3, #20]
	ldr	w15, [c5, #4]
	sub	w15, w15, #1
	str	w15, [c5, #4]
	ldr	w18, [c5, #4]
	ldr	w15, [c19, #32]
	ldr	w14, [c19, x17]
	str	w18, [c19, #44]
	add	w5, w15, #1
	mov	x15, x13
	add	w13, w14, #1
	str	w5, [c19, #32]
	str	w13, [c19, x17]
	b	.LBB0_47
.LBB0_52:                               // %if.then.i
                                        //   in Loop: Header=BB0_3 Depth=1
	mov	w16, wzr
	mov	x15, x13
	str	czr, [c1, x14, lsl #4]
	b	.LBB0_47
.LBB0_53:                               // %if.then
	mov	w0, #2                          // =0x2
	str	w0, [c19]
	b	.LBB0_61
.LBB0_54:                               // %if.then70
	cmp	x20, #0
	sub	c1, c29, #48
	csel	c1, c1, c20, eq
	mov	w9, #2                          // =0x2
	ldr	w8, [c1, #44]
	add	w8, w8, #1
	str	w8, [c1, #44]
	str	w9, [c19]
.LBB0_55:                               // %finish
	ldr	w11, [c19, #24]
	cbz	w11, .LBB0_60
// %bb.56:                              // %for.body99.lr.ph
	adrp	c1, .LCPI0_2
	mov	x8, xzr
	mov	w9, #24                         // =0x18
	mov	x10, #72                        // =0x48
	ldr	d0, [c1, :lo12:.LCPI0_2]
	cmp	x20, #0
	sub	c1, c29, #48
	csel	c1, c1, c20, eq
	b	.LBB0_58
.LBB0_57:                               // %for.inc
                                        //   in Loop: Header=BB0_58 Depth=1
	add	x8, x8, #1
	cmp	x8, x11
	b.hs	.LBB0_60
.LBB0_58:                               // %for.body99
                                        // =>This Inner Loop Header: Depth=1
	lsl	x12, x8, #4
	add	x12, x12, #16
	ldr	c2, [c0, x12]
	gctag	x13, c2
	cbz	x13, .LBB0_57
// %bb.59:                              // %if.then105
                                        //   in Loop: Header=BB0_58 Depth=1
	clrtag	c3, c2
	lsl	x13, x8, #2
	str	c3, [c0, x12]
	add	x13, x13, #56
	ldr	w11, [c1, #20]
	add	w11, w11, #1
	str	w11, [c1, #20]
	ldr	w11, [c2, #4]
	sub	w11, w11, #1
	str	w11, [c2, #4]
	ldr	w12, [c2, #4]
	str	w12, [c19, #44]
	ldr	w11, [c1, #12]
	add	w11, w11, #1
	str	w11, [c1, #12]
	ldr	w11, [c19, x13]
	ldr	w14, [c19, #36]
	add	w11, w11, #1
	str	w11, [c19, x13]
	add	w13, w14, #1
	ldr	x11, [c19, #64]
	str	w13, [c19, #36]
	ldr	x13, [c19, #8]
	add	x14, x11, #1
	madd	x11, x11, x9, x10
	str	x14, [c19, #64]
	add	w14, w8, #1
	add	c2, c19, x11, uxtx
	str	d0, [c2]
	ldr	w11, [c19, #24]
	str	x13, [c2, #8]
	stp	w14, w12, [c2, #16]
	b	.LBB0_57
.LBB0_60:                               // %cleanup113
	ldr	w0, [c19]
.LBB0_61:                               // %cleanup116
	.cfi_def_cfa csp, 368
	ldp	c20, c19, [csp, #336]           // 32-byte Folded Reload
	ldp	c22, c21, [csp, #304]           // 32-byte Folded Reload
	ldp	c24, c23, [csp, #272]           // 32-byte Folded Reload
	ldr	c28, [csp, #256]                // 16-byte Folded Reload
	ldp	c29, c30, [csp, #224]           // 32-byte Folded Reload
	add	csp, csp, #368
	.cfi_def_cfa csp, 0
	.cfi_restore c19
	.cfi_restore c20
	.cfi_restore c21
	.cfi_restore c22
	.cfi_restore c23
	.cfi_restore c24
	.cfi_restore c28
	.cfi_restore c30
	.cfi_restore c29
	ret	c30
.LBB0_62:
	.cfi_restore_state
	mov	w10, wzr
	mov	w11, #1                         // =0x1
	b	.LBB0_67
.LBB0_63:                               // %sw.default
	mov	w8, #2                          // =0x2
	str	w8, [c19]
	b	.LBB0_55
.LBB0_64:                               // %sw.bb63
	ldr	x9, [c19, #64]
	mov	w10, #24                        // =0x18
	mov	x11, #72                        // =0x48
	adrp	c1, .LCPI0_1
	ldr	d0, [c1, :lo12:.LCPI0_1]
	str	x15, [c19, #16]
	madd	x10, x9, x10, x11
	add	x9, x9, #1
	str	wzr, [c19]
	str	x9, [c19, #64]
	ldr	w9, [c19, #44]
	add	c1, c19, x10, uxtx
	str	d0, [c1]
	str	x8, [c1, #8]
	stp	wzr, w9, [c1, #16]
	b	.LBB0_55
.LBB0_65:                               // %if.end.i222.if.then75.threadsplit_crit_edge
	add	w10, w14, #1
	mov	w11, #2                         // =0x2
	b	.LBB0_67
.LBB0_66:
	mov	w10, wzr
	mov	w11, #3                         // =0x3
.LBB0_67:                               // %if.then75.thread
	ldr	x12, [c19, #64]
	mov	w13, #24                        // =0x18
	mov	w14, #1                         // =0x1
	mov	x15, #72                        // =0x48
	madd	x13, x12, x13, x15
	add	x12, x12, #1
	stp	w14, w11, [c19]
	ldr	w11, [c19, #44]
	str	x12, [c19, #64]
	add	c1, c19, x13, uxtx
	stp	w14, w9, [c1]
	str	x8, [c1, #8]
	stp	w10, w11, [c1, #16]
	b	.LBB0_55
.Lfunc_end0:
	.size	cbpf_gate_run, .Lfunc_end0-.Lfunc_begin0
	.cfi_endproc
	.section	.rodata,"a",@progbits
	.p2align	1, 0x0
.LJTI0_0:
	.hword	(.LBB0_5-.LBB0_5)>>2
	.hword	(.LBB0_14-.LBB0_5)>>2
	.hword	(.LBB0_19-.LBB0_5)>>2
	.hword	(.LBB0_24-.LBB0_5)>>2
	.hword	(.LBB0_26-.LBB0_5)>>2
	.hword	(.LBB0_31-.LBB0_5)>>2
	.hword	(.LBB0_36-.LBB0_5)>>2
	.hword	(.LBB0_64-.LBB0_5)>>2
                                        // -- End function
	.ident	"clang version 17.0.0 (https://git.morello-project.org/morello/llvm-project.git 7956a8d20652883f845a41094645174eb92d1960)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
