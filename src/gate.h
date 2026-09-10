/* CBPF trusted-gate experiment: purecap cells, with a software host control.
 * This C interpreter is not Linux eBPF or isolation from arbitrary native C. */
#ifndef CBPF_GATE_H
#define CBPF_GATE_H

#include "cbpf.h"

struct cbpf_gate_metrics {
    /* Attempts include NULL acquisition and failed read/release operations. */
    unsigned acquisitions, reads, releases;
    unsigned cleanups; /* Cells actually consumed by terminal cleanup. */
    /* Actual capability operations: both remain zero in the host control. */
    unsigned restricted_handles, tag_clears;
    size_t cell_bytes, handle_bytes; /* Size of one cell and one alias. */
    int purecap, representation_errors;
};

/* Same structurally checked IR, result observations, and result non-NULL /
 * non-overlap premises as cbpf_run. All cells and aliases belong to this call;
 * cells are never reused. Semantic violations terminate and run cleanup.
 * metrics may be NULL; otherwise it must not overlap program or result.
 * A capability-representation failure returns INVALID after cleaning up any
 * earlier acquisitions, with representation_errors set. It is not an IR trap.
 * The purecap path restricts public views to exactly one cell and LOAD|GLOBAL;
 * only trusted gates resolve those views to private object authority. */
enum cbpf_status cbpf_gate_run(const struct cbpf_insn *program, size_t count,
                              struct cbpf_result *result,
                              struct cbpf_gate_metrics *metrics);

#endif
