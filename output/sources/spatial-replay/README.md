# Eight-byte spatial replay sources

These byte-identical source files match the [7 September native-replay receipt](../../../evidence/current/native-replay/results.json). [manifest.json](manifest.json) records their original paths, byte counts, SHA-256 hashes and source commit.

- [Eight-byte guest fixture](linux/spatial/native-guest.c)
- [Matching native checker](tools/check_spatial_native.py)

The active spatial fixture uses a seven-byte value. These retained inputs identify the earlier experiment; they are supporting sources rather than a standalone kernel/toolchain bundle. See the [replay account](../../../docs/reproduction/native-replay.md) and [dependency guide](../../../docs/reproduction/native-dependencies.md) for the other required inputs. Historical outcomes belong to their recorded binaries.
