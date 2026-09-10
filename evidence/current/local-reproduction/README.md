# Historical local reproduction records

On 6 September 2026, local reproduction rebuilt the frozen provider/ownership
implementation and repeated its existing benign controls on the same
host/toolchain. It covered ownership execution and boundary controls, three
spatial object builds and default checks. It did not run the later spatial
native witness.

The [source freeze](m1-m3-freeze.json) identifies 234 selected original files;
the [reproduction receipt](reproduction/reproduction.json) records matching
ownership outputs and spatial objects/configuration. Earlier preparation in
`source-freeze.json` identifies 175 files; its interrupted build is not a
passing reproduction.

The two source tarballs and the [final edition archive](../../history/README.md)
are privately preserved and withheld from publication. Original `manifest.json`
and `SHA256SUMS` digests remain historical metadata. The [publication manifest](../../publication-manifest.json)
verifies the sanitized files; it does not reconstruct the original archives.

[Dependency identities](dependency-inventory.json), [host requirements](host-requirements.txt)
and [historical restoration instructions](dependency-README.md) describe the
recorded substrate with host locations redacted. They do not establish
external reproduction or portability. Current interpretation
is in the [research overview](../../../docs/research-overview.md),
[claim map](../../../docs/claim-evidence.md) and [reproduction guide](../../../docs/reproduction.md).
The [spatial native witness](../spatial-native/README.md) remains a separate experiment.
