"""Build Ghidra .gdt type archives from Linux kernel source trees.

Takes a kernel source tree and target architecture, discovers headers,
preprocesses them with gcc -E, feeds them to Ghidra's CParser, and
exports the resulting types as a .gdt archive.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import click

log = logging.getLogger(__name__)


class KernelGdtError(Exception):
    """Raised when a stage of the kernel GDT pipeline fails."""


ARCH_DEFINES: dict[str, dict[str, Any]] = {
    "x86_64": {
        "gcc_defines": ["__x86_64__", "__LP64__"],
        "kernel_arch": "x86",
        "pointer_size": 8,
    },
    "x86": {
        "gcc_defines": ["__i386__"],
        "kernel_arch": "x86",
        "pointer_size": 4,
    },
    "arm": {
        "gcc_defines": ["__arm__"],
        "kernel_arch": "arm",
        "pointer_size": 4,
    },
    "arm64": {
        "gcc_defines": ["__aarch64__", "__LP64__"],
        "kernel_arch": "arm64",
        "pointer_size": 8,
    },
    "mips": {
        "gcc_defines": ["__mips__"],
        "kernel_arch": "mips",
        "pointer_size": 4,
    },
    "riscv64": {
        "gcc_defines": ["__riscv", "__riscv_xlen=64", "__LP64__"],
        "kernel_arch": "riscv",
        "pointer_size": 8,
    },
    "ppc": {
        "gcc_defines": ["__powerpc__"],
        "kernel_arch": "powerpc",
        "pointer_size": 4,
    },
}

PRIORITY_HEADERS = [
    "linux/types.h",
    "linux/stddef.h",
    "linux/compiler.h",
    "linux/list.h",
    "linux/rbtree.h",
    "linux/spinlock_types.h",
    "linux/atomic.h",
    "linux/skbuff.h",
    "linux/netdevice.h",
    "linux/net.h",
    "linux/socket.h",
    "linux/fs.h",
    "linux/mm_types.h",
    "linux/sched.h",
    "linux/device.h",
    "linux/pci.h",
    "linux/usb.h",
    "linux/workqueue.h",
    "linux/timer.h",
    "linux/interrupt.h",
    "linux/mutex.h",
    "linux/completion.h",
    "linux/wait.h",
    "linux/kref.h",
    "linux/kobject.h",
    "linux/slab.h",
    "linux/gfp.h",
    "linux/dma-mapping.h",
    "linux/scatterlist.h",
    "linux/io.h",
    "linux/ioctl.h",
    "linux/idr.h",
    "linux/notifier.h",
    "linux/rwsem.h",
    "linux/semaphore.h",
    "linux/firmware.h",
    "linux/platform_device.h",
    "linux/of.h",
    "linux/etherdevice.h",
    "linux/ethtool.h",
    "linux/if_ether.h",
    "linux/ip.h",
    "linux/tcp.h",
    "linux/udp.h",
    "net/cfg80211.h",
    "net/mac80211.h",
    "net/sock.h",
    "net/tcp.h",
    "net/ip.h",
    "net/netlink.h",
    "net/genetlink.h",
    "linux/nl80211.h",
    "linux/ieee80211.h",
    "net/bluetooth/bluetooth.h",
    "net/bluetooth/hci_core.h",
    "linux/hid.h",
    "linux/input.h",
    "linux/tty.h",
    "linux/serial_core.h",
    "linux/block_devices.h",
    "linux/blkdev.h",
    "linux/bio.h",
    "linux/scsi/scsi.h",
    "scsi/scsi_host.h",
    "scsi/scsi_device.h",
    "scsi/scsi_cmnd.h",
    "linux/crypto.h",
    "crypto/hash.h",
    "crypto/skcipher.h",
    "linux/key.h",
]

COMPAT_SHIM = """\
/* ghidra_compat.h -- stubs for GCC extensions Ghidra's CParser cannot handle */
#ifndef _GHIDRA_COMPAT_H
#define _GHIDRA_COMPAT_H

#define __attribute__(x)
#define __aligned(x)
#define __packed
#define __section(x)
#define __used
#define __cold
#define __hot
#define __init
#define __exit
#define __initdata
#define __exitdata
#define __read_mostly
#define __percpu
#define __rcu
#define __user
#define __kernel
#define __iomem
#define __force
#define __bitwise
#define __acquires(x)
#define __releases(x)
#define __must_hold(x)
#define __maybe_unused
#define __always_unused
#define __deprecated
#define __weak
#define __alias(x)
#define __pure
#define __always_inline inline
#define __noinline
#define __noreturn
#define __visible
#define __noclone
#define __printf(a, b)
#define __scanf(a, b)
#define __latent_entropy
#define __randomize_layout
#define __no_randomize_layout
#define __designated_init
#define __counted_by(x)
#define noinline
#define notrace
#define likely(x) (x)
#define unlikely(x) (x)

#define asm(...)
#define __asm__(...)
#define __asm(...)
#define __extension__
#define __typeof__(x) int
#define typeof(x) int
#define __typeof_unqual__(x) int
#define __auto_type int
#define __signed__ signed
#define __volatile__ volatile
#define __int128 long long
#define __int128_t long long
#define __uint128_t unsigned long long

#define __alignof__(x) 8
#define __alignof(x) 8
#define __builtin_offsetof(t, m) ((unsigned long)&((t *)0)->m)
#define __builtin_va_list void *
#define __builtin_va_start(v, l)
#define __builtin_va_end(v)
#define __builtin_va_arg(v, t) (*(t *)0)
#define __builtin_va_copy(d, s)
#define __builtin_types_compatible_p(a, b) 0
#define __builtin_constant_p(x) 0
#define __builtin_expect(x, v) (x)
#define __builtin_choose_expr(c, t, f) (t)
#define __builtin_clz(x) 0
#define __builtin_clzl(x) 0
#define __builtin_clzll(x) 0
#define __builtin_ctz(x) 0
#define __builtin_ctzl(x) 0
#define __builtin_ctzll(x) 0
#define __builtin_ffs(x) 0
#define __builtin_ffsl(x) 0
#define __builtin_ffsll(x) 0
#define __builtin_popcount(x) 0
#define __builtin_popcountl(x) 0
#define __builtin_popcountll(x) 0
#define __builtin_bswap16(x) 0
#define __builtin_bswap32(x) 0
#define __builtin_bswap64(x) 0
#define __builtin_unreachable()
#define __builtin_trap()
#define __builtin_prefetch(addr, ...)
#define __builtin_object_size(ptr, type) ((unsigned long)-1)
#define __builtin_frame_address(x) ((void *)0)
#define __builtin_return_address(x) ((void *)0)
#define __same_type(a, b) 0

#define IS_ENABLED(option) option
#define IS_BUILTIN(option) option
#define IS_MODULE(option) 0
#define IS_REACHABLE(option) option

#define static_assert(expr, ...)
#define _Static_assert(expr, ...)
#define BUILD_BUG_ON(condition)
#define BUILD_BUG_ON_ZERO(e) 0
#define BUILD_BUG_ON_MSG(cond, msg)

#define DECLARE_BITMAP(name, bits) unsigned long name[1]
#define DECLARE_HASHTABLE(name, bits) unsigned long name[1]

#define __CHECKER__

#endif /* _GHIDRA_COMPAT_H */
"""

# ── Stage 1: Header Discovery ────────────────────────────────────────


def discover_headers(kernel_src: Path, arch: str) -> list[str]:
    """Return headers from PRIORITY_HEADERS that exist in the kernel tree.

    Only includes curated headers known to work with standalone gcc -E.
    """
    arch_info = ARCH_DEFINES.get(arch)
    if arch_info is None:
        supported = ", ".join(sorted(ARCH_DEFINES))
        raise KernelGdtError(
            f"Unsupported architecture: {arch}. Supported: {supported}"
        )

    kernel_arch = arch_info["kernel_arch"]
    include_base = kernel_src / "include"
    arch_base = kernel_src / "arch" / kernel_arch / "include"

    found: list[str] = []
    for header in PRIORITY_HEADERS:
        if (include_base / header).is_file() or (arch_base / header).is_file():
            found.append(header)

    return found


def parse_kconfig(config_path: Path) -> list[str]:
    """Parse a .config or autoconf.h and return CONFIG_* define names.

    For .config: extracts CONFIG_* from lines matching ``CONFIG_*=y`` or
    ``CONFIG_*=m``.
    For autoconf.h: extracts CONFIG_* from ``#define CONFIG_*`` lines.
    """
    text = config_path.read_text(encoding="utf-8", errors="replace")
    defines: list[str] = []

    if config_path.name.endswith(".h"):
        for match in re.finditer(r"^#define\s+(CONFIG_\w+)", text, re.MULTILINE):
            defines.append(match.group(1))
    else:
        for match in re.finditer(r"^(CONFIG_\w+)=[ym]", text, re.MULTILINE):
            defines.append(match.group(1))

    return defines


def build_amalgamation(
    kernel_src: Path,
    arch: str,
    headers: list[str],
    config_defines: list[str] | None = None,
    config_path: Path | None = None,
) -> str:
    """Build the kernel_types.h amalgamation content."""
    arch_info = ARCH_DEFINES[arch]
    lines = [
        "/* Auto-generated kernel type amalgamation for Ghidra CParser */",
        "",
        "#define __KERNEL__",
        "#define MODULE",
    ]

    for define in arch_info["gcc_defines"]:
        if "=" in define:
            name, value = define.split("=", 1)
            lines.append(f"#define {name} {value}")
        else:
            lines.append(f"#define {define}")

    if config_path is not None and config_path.name.endswith(".h"):
        lines.append("")
        lines.append(f'#include "{config_path}"')
    elif config_defines:
        lines.append("")
        for config in config_defines:
            lines.append(f"#define {config} 1")

    lines.append("")
    for header in headers:
        lines.append(f"#include <{header}>")

    lines.append("")
    return "\n".join(lines)


# ── Stage 2: Preprocessing ───────────────────────────────────────────


def build_gcc_command(
    kernel_src: Path,
    arch: str,
    amalgamation_path: Path,
    compat_shim_path: Path,
) -> list[str]:
    """Build the gcc -E command line for preprocessing kernel headers."""
    arch_info = ARCH_DEFINES[arch]
    kernel_arch = arch_info["kernel_arch"]

    arch_base = kernel_src / "arch" / kernel_arch / "include"

    include_dirs = [
        kernel_src / "include",
        kernel_src / "include" / "uapi",
        arch_base,
        arch_base / "uapi",
        arch_base / "generated",
        arch_base / "generated" / "uapi",
        kernel_src / "include" / "generated",
        kernel_src / "include" / "generated" / "uapi",
        kernel_src / "include" / "asm-generic",
    ]

    cmd = ["gcc", "-E", "-nostdinc", "-P", "-w"]

    for inc in include_dirs:
        cmd.extend(["-I", str(inc)])

    cmd.extend(["-include", str(compat_shim_path)])
    cmd.append(str(amalgamation_path))

    return cmd


def preprocess_headers(
    kernel_src: Path,
    arch: str,
    amalgamation: str,
    work_dir: Path,
) -> Path:
    """Run gcc -E on the amalgamation and return path to preprocessed output.

    Writes the amalgamation and compat shim to work_dir, invokes gcc -E,
    and writes the output to ``preprocessed.h`` in work_dir.
    """
    amalgamation_path = work_dir / "kernel_types.h"
    amalgamation_path.write_text(amalgamation, encoding="utf-8")

    compat_path = work_dir / "ghidra_compat.h"
    compat_path.write_text(COMPAT_SHIM, encoding="utf-8")

    preprocessed_path = work_dir / "preprocessed.h"

    cmd = build_gcc_command(kernel_src, arch, amalgamation_path, compat_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except FileNotFoundError:
        raise KernelGdtError("gcc not found. Install gcc to preprocess kernel headers.")

    if result.returncode != 0:
        stderr_tail = result.stderr.strip()[-500:] if result.stderr else "(no output)"
        raise KernelGdtError(f"gcc preprocessing failed:\n{stderr_tail}")

    cleaned = _strip_function_bodies(result.stdout)
    cleaned = _simplify_complex_exprs(cleaned)
    preprocessed_path.write_text(cleaned, encoding="utf-8")
    return preprocessed_path


def _strip_function_bodies(text: str) -> str:
    """Remove function bodies (balanced {...} blocks) from preprocessed C.

    CParser only handles declarations; inline function bodies from kernel
    headers cause parse errors.  Replaces top-level ``{ ... }`` with ``;``
    while preserving struct/union/enum bodies.
    """
    out: list[str] = []
    depth = 0
    i = 0
    in_struct = False
    length = len(text)

    while i < length:
        ch = text[i]

        if ch == "{":
            if depth == 0:
                # Preserve struct/union/enum bodies and initializers
                preceding = text[max(0, i - 200) : i].rstrip()
                if re.search(
                    r"\b(struct|union|enum)\s*(\w+\s*)?\Z",
                    preceding,
                ):
                    in_struct = True
                    out.append(ch)
                else:
                    in_struct = False
            else:
                if in_struct:
                    out.append(ch)
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                if in_struct:
                    out.append(ch)
                else:
                    out.append(";")
                in_struct = False
            elif in_struct:
                out.append(ch)
        elif depth == 0 or in_struct:
            out.append(ch)

        i += 1

    return "".join(out)


def _simplify_complex_exprs(text: str) -> str:
    """Clean up expressions CParser can't handle.

    - Strip static variable declarations (CParser only needs type defs)
    - Replace complex array dimensions (containing function calls) with [1]
    - Normalize integer literal suffixes (1LU -> 1UL, etc.)
    - Strip lines with bare = ; left by body stripping
    """
    lines = text.split("\n")
    out: list[str] = []
    skip_until_semi = False

    for line in lines:
        stripped = line.strip()

        if skip_until_semi:
            if ";" in stripped:
                skip_until_semi = False
            continue

        # Skip static variable/function declarations
        if stripped.startswith("static ") and "struct " not in stripped[:30]:
            if ";" not in stripped:
                skip_until_semi = True
            continue

        # Strip extern declarations with initializers (can't happen but be safe)
        if "= ;" in stripped:
            continue

        out.append(line)

    text = "\n".join(out)
    # Replace complex array dims
    text = re.sub(
        r"\[([^\[\]]*\([^\[\]]*\)[^\[\]]*)\]",
        "[1]",
        text,
    )
    # CParser doesn't understand LU suffix — normalize to UL
    text = re.sub(r"\b(\d+)LU\b", r"\1UL", text)
    text = re.sub(r"\b(\d+)LLU\b", r"\1ULL", text)
    return text


# ── Stage 3+4: Parse with CParser and export .gdt ────────────────────


def parse_and_export_gdt(
    preprocessed_path: Path,
    output_path: Path,
    ghidra_path: Path | None = None,
    max_ram_percent: float = 50.0,
) -> dict[str, int]:
    """Feed preprocessed C to Ghidra's CParser and export as .gdt.

    Uses CParserUtils.parseHeaderFiles which parses the header files and
    writes the result directly to a .gdt archive in one step.
    """
    import jpype

    from .decompiler import _build_vm_args, _start_pyghidra

    vm_args = _build_vm_args(max_ram_percent=max_ram_percent)
    _start_pyghidra(ghidra_path, vm_args=vm_args)

    from ghidra.app.util.cparser.C import CParserUtils
    from ghidra.program.model.data import Enum as GhidraEnum
    from ghidra.program.model.data import Structure, Union
    from ghidra.util.task import ConsoleTaskMonitor

    output_path.parent.mkdir(parents=True, exist_ok=True)
    gdt_file = output_path.with_suffix(".gdt")
    if gdt_file.exists():
        gdt_file.unlink()

    click.echo(f"Parsing types and exporting to {gdt_file}...")

    monitor = ConsoleTaskMonitor()
    JString = jpype.JClass("java.lang.String")
    JStringArray = jpype.JArray(JString)
    DTMArray = jpype.JArray(jpype.JClass("ghidra.program.model.data.DataTypeManager"))

    filenames = JStringArray([str(preprocessed_path)])
    include_dirs = JStringArray([])
    open_archives = DTMArray([])

    try:
        fdtm = CParserUtils.parseHeaderFiles(
            open_archives, filenames, include_dirs, str(gdt_file), monitor
        )
    except Exception as exc:
        raise KernelGdtError(f"CParser failed: {exc}") from exc

    if fdtm is None:
        raise KernelGdtError("CParser returned no results")

    stats = {"types_count": 0, "structs": 0, "unions": 0, "enums": 0}
    try:
        for dt in fdtm.getAllDataTypes():
            stats["types_count"] += 1
            if isinstance(dt, Structure):
                stats["structs"] += 1
            elif isinstance(dt, Union):
                stats["unions"] += 1
            elif isinstance(dt, GhidraEnum):
                stats["enums"] += 1
        fdtm.save()
    finally:
        fdtm.close()

    return stats


# ── Orchestrator ──────────────────────────────────────────────────────


def build_kernel_gdt(
    kernel_src: Path,
    arch: str,
    output: Path,
    *,
    config: Path | None = None,
    ghidra_path: Path | None = None,
    max_ram_percent: float = 50.0,
) -> dict[str, int]:
    """Full pipeline: discover headers, preprocess, parse, export."""
    if arch not in ARCH_DEFINES:
        supported = ", ".join(sorted(ARCH_DEFINES))
        raise KernelGdtError(
            f"Unsupported architecture: {arch}. Supported: {supported}"
        )

    kernel_src = kernel_src.resolve()
    output = output.resolve()

    click.echo(f"Kernel source: {kernel_src}")
    click.echo(f"Architecture:  {arch}")
    click.echo(f"Output:        {output}")

    click.echo("Discovering kernel headers...")
    headers = discover_headers(kernel_src, arch)
    click.echo(f"Found {len(headers)} headers")

    config_defines = None
    config_path = config
    if config_path is None:
        autoconf = kernel_src / "include" / "generated" / "autoconf.h"
        if autoconf.is_file():
            config_path = autoconf
            click.echo(f"Auto-detected kernel config: {config_path}")

    if config_path is not None and not config_path.name.endswith(".h"):
        click.echo(f"Parsing kernel config: {config_path}")
        config_defines = parse_kconfig(config_path)
        click.echo(f"Found {len(config_defines)} CONFIG defines")
    elif config_path is not None:
        click.echo(f"Using kernel config header: {config_path}")

    amalgamation = build_amalgamation(
        kernel_src, arch, headers, config_defines, config_path
    )

    with tempfile.TemporaryDirectory(prefix="ghidra-kernel-gdt-") as work_dir:
        work_path = Path(work_dir)

        click.echo("Preprocessing headers with gcc...")
        preprocessed_path = preprocess_headers(
            kernel_src, arch, amalgamation, work_path
        )
        size_mb = preprocessed_path.stat().st_size / (1024 * 1024)
        click.echo(f"Preprocessed output: {size_mb:.1f} MB")

        stats = parse_and_export_gdt(
            preprocessed_path, output, ghidra_path, max_ram_percent
        )

    click.echo(
        f"Exported {stats['types_count']} types "
        f"({stats['structs']} structs, {stats['unions']} unions, "
        f"{stats['enums']} enums)"
    )

    return stats
