# Multi-architecture fixtures

Run fixture commands from the repository root. Regeneration requires LLVM Clang and
LLD 21; the checked binaries were produced with the exact versions recorded in
`tests/fixtures/multiarch.provenance`.

```sh
tests/fixtures/build_multiarch.sh
pytest tests/test_multiarch_e2e.py::test_checked_in_fixture_hashes_and_provenance
```

The script compiles all six architectures in a temporary staging directory. It only
replaces the checked binaries, checksum manifest, and provenance after every compile
and link succeeds. Outputs are mode `0644`. Debug and file paths are mapped to the
logical `/fixture-src` root so builds do not depend on the repository location.

The defaults are `clang-21` and `ld.lld-21`. Set `CC` or `LD` to select another
executable. A non-LLVM-21 version is rejected unless the deliberate opt-out
`ALLOW_UNSUPPORTED_LLVM=1` is set; outputs from an unvalidated toolchain should not be
committed without reviewing binary differences and updating provenance.

To verify path-independent reproducibility with the same toolchain, copy the repository
to two different absolute paths, run `tests/fixtures/build_multiarch.sh` in each copy,
then compare the manifests and binaries:

```sh
cmp /path/one/tests/fixtures/multiarch.sha256 /path/two/tests/fixtures/multiarch.sha256
cmp /path/one/tests/fixtures/multiarch.provenance /path/two/tests/fixtures/multiarch.provenance
for name in aarch64 armv7 mipsel ppc32 riscv64 x86_32; do
    cmp "/path/one/tests/fixtures/multiarch_$name" \
        "/path/two/tests/fixtures/multiarch_$name"
done
```

`multiarch.provenance` records source and script hashes, tool versions, complete common
flags, per-output target and linker emulation, and architecture-specific flags.
