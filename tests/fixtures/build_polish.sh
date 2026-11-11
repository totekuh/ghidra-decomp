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
OUTPUTS="polish_aarch64 polish_armv7 polish_mipsel polish_ppc32 polish_riscv64 polish_x86_32"
STAGING=$(mktemp -d "$SCRIPT_DIR/.polish-build.XXXXXX")
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
    $CC --target="$target" $COMMON_FLAGS "$@" -c "$SCRIPT_DIR/polish_test.c" -o "$object"
    $LD -m "$emulation" -e entry --build-id=none "$object" -o "$STAGING/$output"
    chmod 0644 "$STAGING/$output"
}

sha256() {
    $PYTHON -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

build i386-none-elf elf_i386 polish_x86_32
build armv7-none-eabi armelf polish_armv7 -mfloat-abi=soft
build aarch64-none-elf aarch64elf polish_aarch64
build mipsel-none-elf elf32ltsmip polish_mipsel
build powerpc-none-elf elf32ppc polish_ppc32
build riscv64-none-elf elf64lriscv polish_riscv64

(
    cd "$STAGING"
    for output in $OUTPUTS; do
        printf '%s  %s\n' "$(sha256 "$output")" "$output"
    done > polish.sha256
)

source_sha256=$(sha256 polish_test.c)
script_sha256=$(sha256 build_polish.sh)
cat > "$STAGING/polish.provenance" <<EOF
format: 1
source: tests/fixtures/polish_test.c
build_script: tests/fixtures/build_polish.sh
source_sha256: $source_sha256
build_script_sha256: $script_sha256
compiler: $cc_version
linker: $ld_version
common_compile_flags: $RECORDED_COMMON_FLAGS
common_link_flags: -e entry --build-id=none
path_mapping: <fixture-dir>=/fixture-src
targets:
  polish_x86_32: target=i386-none-elf; emulation=elf_i386; extra_flags=
  polish_armv7: target=armv7-none-eabi; emulation=armelf; extra_flags=-mfloat-abi=soft
  polish_aarch64: target=aarch64-none-elf; emulation=aarch64elf; extra_flags=
  polish_mipsel: target=mipsel-none-elf; emulation=elf32ltsmip; extra_flags=
  polish_ppc32: target=powerpc-none-elf; emulation=elf32ppc; extra_flags=
  polish_riscv64: target=riscv64-none-elf; emulation=elf64lriscv; extra_flags=
EOF
chmod 0644 "$STAGING/polish.sha256" "$STAGING/polish.provenance"

for output in $OUTPUTS; do
    mv "$STAGING/$output" "$SCRIPT_DIR/$output"
done
mv "$STAGING/polish.sha256" "$SCRIPT_DIR/polish.sha256"
mv "$STAGING/polish.provenance" "$SCRIPT_DIR/polish.provenance"
