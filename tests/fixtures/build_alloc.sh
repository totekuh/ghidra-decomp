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
SOURCES="alloc_basic alloc_xfunc alloc_complex alloc_complex2 alloc_wrapper"
OUTPUTS=""
for src in $SOURCES; do
    for arch in x86_32 armv7 aarch64 mipsel ppc32 riscv64; do
        OUTPUTS="$OUTPUTS ${src}_${arch}"
    done
done
STAGING=$(mktemp -d "$SCRIPT_DIR/.alloc-build.XXXXXX")
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
    arch_suffix=$3
    shift 3
    for src_base in $SOURCES; do
        output="${src_base}_${arch_suffix}"
        object="$STAGING/$output.o"
        $CC --target="$target" $COMMON_FLAGS "$@" -c "$SCRIPT_DIR/${src_base}.c" -o "$object"
        $LD -m "$emulation" -e entry --build-id=none "$object" -o "$STAGING/$output"
        chmod 0644 "$STAGING/$output"
    done
}

sha256() {
    $PYTHON -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

build i386-none-elf elf_i386 x86_32
build armv7-none-eabi armelf armv7 -mfloat-abi=soft
build aarch64-none-elf aarch64elf aarch64
build mipsel-none-elf elf32ltsmip mipsel
build powerpc-none-elf elf32ppc ppc32
build riscv64-none-elf elf64lriscv riscv64

(
    cd "$STAGING"
    for output in $OUTPUTS; do
        printf '%s  %s\n' "$(sha256 "$output")" "$output"
    done > alloc.sha256
)

source_sha256=""
for src_base in $SOURCES; do
    source_sha256="$source_sha256 ${src_base}.c:$(sha256 "${src_base}.c")"
done
script_sha256=$(sha256 build_alloc.sh)
cat > "$STAGING/alloc.provenance" <<EOF
format: 1
sources:$source_sha256
build_script: tests/fixtures/build_alloc.sh
build_script_sha256: $script_sha256
compiler: $cc_version
linker: $ld_version
common_compile_flags: $RECORDED_COMMON_FLAGS
common_link_flags: -e entry --build-id=none
path_mapping: <fixture-dir>=/fixture-src
targets:
  x86_32: target=i386-none-elf; emulation=elf_i386; extra_flags=
  armv7: target=armv7-none-eabi; emulation=armelf; extra_flags=-mfloat-abi=soft
  aarch64: target=aarch64-none-elf; emulation=aarch64elf; extra_flags=
  mipsel: target=mipsel-none-elf; emulation=elf32ltsmip; extra_flags=
  ppc32: target=powerpc-none-elf; emulation=elf32ppc; extra_flags=
  riscv64: target=riscv64-none-elf; emulation=elf64lriscv; extra_flags=
EOF
chmod 0644 "$STAGING/alloc.sha256" "$STAGING/alloc.provenance"

for output in $OUTPUTS; do
    mv "$STAGING/$output" "$SCRIPT_DIR/$output"
done
mv "$STAGING/alloc.sha256" "$SCRIPT_DIR/alloc.sha256"
mv "$STAGING/alloc.provenance" "$SCRIPT_DIR/alloc.provenance"
