# Spatial native witness preparation and native admission procedure

The bounded spatial native witness procedure connects a selected array value to the authority
used by one native read/write control. The [logical extent discriminator](logical-extent.md)
passed; the earlier eight-byte witness retains its separate receipt. This document states the preparation, admission and reconciliation
conditions for the recorded execution.

## Fixed control and substrate

The inherited spatial tree is `e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`.
The frozen reduced patch plus a separately hashed observation overlay adds
two logging sites: the selected capability immediately before provider return,
and the constructed helper gateway. The overlay adds no enforcement rule.
The inherited verifier source is unchanged, and spatial offload and historical
test modes remain disabled.

The sole control is a normally verified SOCKET_FILTER program using a plain
ARRAY with four-byte key, seven-byte value, two entries and zero flags.
Key 1 starts with logical bytes `11 22 33 44 55 66 29` (hex). The program initializes its stack key, looks up the value,
checks NULL, loads byte six, adds one, stores at byte six through the same returned capability,
and returns the computed value. No other helper, packet access, loop,
subprogram, pointer spill, direct-value relocation or atomic operation occurs.

## Admission before execution

1. Bind the fresh source/configuration/toolchain to the linked Image and
   vmlinux, matching purecap headers, exact initramfs and offline QEMU command.
   Keep configuration and input hashes. Account for actual relocation; this
   recorded guest had no firmware KASLR seed and used relocation zero.
2. Load through the ordinary verifier and retain the map/program FDs. Require
   nonzero complete native bytes and entry information from that program FD.
   Match every byte and the entry/length to the complete accepted certificate
   decision. Interpreter fallback or suppressed native information stops the
   procedure before TEST_RUN.
3. Decode the full native program with the Morello disassembler. Inspect its
   prologue, returns, lookup dispatch, full-capability return transport and
   selected load/store. Inspect complete linked function ranges, including
   ELF mapping-label continuations in the allocator and exception handler.
4. Derive the expected code roots before execution. If `I` is the native entry,
   `R` the instruction after the call to sandbox entry, `E` the epilogue word
   and `P` the PLT word, restricted length is `I + 4*(E+1) - R`, and executive
   length is `4*(P-E-1)`. The restricted range starts at `R`, not body start.
5. Confirm one lookup, no intervening rewrite of the returned selected
   capability, no alternate selected-value write, no scalar/DDC selected-value
   body access and no reachable PLT/attachment path. Record the manual review
   and its artifact hashes while execution count is still zero.

## One invocation and reconciliation

The loader remains paused with the same FDs and unchanged map until the
execution token follows successful admission and manual review. It then makes
one normal TEST_RUN with repeat 1, a fixed inert input, zero flags/CPU/batch
and no supplied context or attachment.

Postflight requires exactly one reduced-provider observation matching map ID
and key. Capability base/cursor must equal the computed selected address,
length 7, logical size 7, stride 8, tag 1, unsealed state and permissions `LOAD | STORE | GLOBAL`.
Restricted/executive construction records must match the prior predictions;
the gateway cursor must match the linked symbol. Return and byte-six readback must both be 42 after initial 41; the other
six logical bytes must remain unchanged. Failure, missing telemetry or a
mismatch prevents a runtime correspondence claim.

The [current receipt](../../evidence/current/logical-extent/README.md) retains
the executed fixture, preflight, pre-execution review and postflight. Earlier
preparation attempts remain in the separate eight-byte witness archive.

## Interpretation

Provider observations are source-backed construction records; some getter
values can be constant-folded after successful checks. They are not independent
hardware attestation. The helper sentry retains DDC bounds and inherited
RDDC remains vmalloc-wide. This control establishes correspondence for its
selected accesses under trusted provider, image and architecture assumptions.
It does not establish complete mediation for every accepted program, executed
padding accesses, out-of-bounds faults, a new CVE result or composition
with ownership.
