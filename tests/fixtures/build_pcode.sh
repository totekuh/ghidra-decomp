#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

CC=${CC:-clang-21}
LD=${LD:-ld.lld-21}
PYTHON=${PYTHON:-python3}
ALLOW_UNSUPPORTED_LLVM=${ALLOW_UNSUPPORTED_LLVM:-0}
COMMON_FLAGS="-O0 -g -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -ffile-prefix-map=$SCRIPT_DIR=/fixture-src -fdebug-prefix-map=$SCRIPT_DIR=/fixture-src -fmacro-prefix-map=$SCRIPT_DIR=/fixture-src"
RECORDED_COMMON_FLAGS="-O0 -g -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -ffile-prefix-map=<fixture-dir>=/fixture-src -fdebug-prefix-map=<fixture-dir>=/fixture-src -fmacro-prefix-map=<fixture-dir>=/fixture-src"
OUTPUTS="pcode_aarch64 pcode_armv7 pcode_mipsel pcode_ppc32 pcode_riscv64 pcode_x86_32"
STAGING=$(mktemp -d "$SCRIPT_DIR/.pcode-build.XXXXXX")
trap 'rm -rf "$STAGING"' EXIT HUP INT TERM

cc_version=$($CC --version | { IFS= read -r line; printf '%s\n' "$line"; })
ld_version=$($LD --version | { IFS= read -r line; printf '%s\n' "$line"; })

case "$cc_version" in
    *"clang version 21."*) ;;
    *)
        if [ "$ALLOW_UNSUPPORTED_LLVM" != 1 ]; then
            printf '%s\n' "error: LLVM Clang 21 is required (found: $cc_version)" >&2
            printf '%s\n' "set ALLOW_UNSUPPORTED_LLVM=1 to build with an unvalidated toolchain" >&2
            exit 1
        fi
        ;;
esac
case "$ld_version" in
    *"LLD 21."*) ;;
    *)
        if [ "$ALLOW_UNSUPPORTED_LLVM" != 1 ]; then
            printf '%s\n' "error: LLVM LLD 21 is required (found: $ld_version)" >&2
            printf '%s\n' "set ALLOW_UNSUPPORTED_LLVM=1 to build with an unvalidated toolchain" >&2
            exit 1
        fi
        ;;
esac

build() {
    target=$1
    emulation=$2
    output=$3
    shift 3
    object="$STAGING/$output.o"
    $CC --target="$target" $COMMON_FLAGS "$@" -c "$SCRIPT_DIR/pcode_test.c" -o "$object"
    $LD -m "$emulation" -e entry --build-id=none "$object" -o "$STAGING/$output"
    chmod 0644 "$STAGING/$output"
}

sha256() {
    $PYTHON -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

build i386-none-elf elf_i386 pcode_x86_32
build armv7-none-eabi armelf pcode_armv7 -mfloat-abi=soft
build aarch64-none-elf aarch64elf pcode_aarch64
build mipsel-none-elf elf32ltsmip pcode_mipsel
build powerpc-none-elf elf32ppc pcode_ppc32
build riscv64-none-elf elf64lriscv pcode_riscv64

(
    cd "$STAGING"
    for output in $OUTPUTS; do
        printf '%s  %s\n' "$(sha256 "$output")" "$output"
    done > pcode.sha256
)

source_sha256=$(sha256 pcode_test.c)
script_sha256=$(sha256 build_pcode.sh)
cat > "$STAGING/pcode.provenance" <<EOF
format: 1
source: tests/fixtures/pcode_test.c
build_script: tests/fixtures/build_pcode.sh
source_sha256: $source_sha256
build_script_sha256: $script_sha256
compiler: $cc_version
linker: $ld_version
common_compile_flags: $RECORDED_COMMON_FLAGS
common_link_flags: -e entry --build-id=none
path_mapping: <fixture-dir>=/fixture-src
targets:
  pcode_x86_32: target=i386-none-elf; emulation=elf_i386; extra_flags=
  pcode_armv7: target=armv7-none-eabi; emulation=armelf; extra_flags=-mfloat-abi=soft
  pcode_aarch64: target=aarch64-none-elf; emulation=aarch64elf; extra_flags=
  pcode_mipsel: target=mipsel-none-elf; emulation=elf32ltsmip; extra_flags=
  pcode_ppc32: target=powerpc-none-elf; emulation=elf32ppc; extra_flags=
  pcode_riscv64: target=riscv64-none-elf; emulation=elf64lriscv; extra_flags=
EOF
chmod 0644 "$STAGING/pcode.sha256" "$STAGING/pcode.provenance"

for output in $OUTPUTS; do
    mv "$STAGING/$output" "$SCRIPT_DIR/$output"
done
mv "$STAGING/pcode.sha256" "$SCRIPT_DIR/pcode.sha256"
mv "$STAGING/pcode.provenance" "$SCRIPT_DIR/pcode.provenance"
