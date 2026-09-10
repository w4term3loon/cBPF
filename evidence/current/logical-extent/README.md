# Logical extent discriminator evidence

**PASS, 7 September 2026.** Exact length seven with stride eight, one native
byte-six increment from 41 to 42, unchanged six-byte prefix and clean guest exit.
See the [research account](../../../docs/logical-extent.md).

- [Result and source identities](results.json).
- [Console](run/boot.log), [input identities](run/inputs.sha256),
  [executed fixture](run/guest.c) and [fixed checker](run/check_spatial_native.executed.py).
- [Preflight](review/pre.json), [pre-execution manual review](review/manual-review.json),
  [native instructions](review/jit-disassembly.txt) and [postflight](review/post.json).
- [Complete linked ranges](review/complete-linked-disassembly.txt),
  [reused kernel review](review/prior-kernel-review.json) and
  [native-image differences](review/native-differences.json).
- [Length-eight counterfactual checker result](discriminator-check.json).

The verified kernel is reused from the [native replay](../native-replay/README.md);
there was no new kernel build or enforcement change. Full raw evidence remains
private. Publication paths use role markers, and the publication manifest keeps
original and distributed identities distinct. Embedded hashes identify their
original inputs, not necessarily editorially redacted copies.

The manual review was written before execution. Its original prose incorrectly
counted 19 input hashes; the inventory contains 18, all verified. The public
copy corrects that count, with the original hash retained in the manifest.

No padding access, original CVE trigger, invalid BPF execution, ownership
fault injection or independent reproduction is claimed. The counterfactual
is an offline telemetry edit for checker sensitivity, not a kernel experiment.
