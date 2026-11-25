"""End-to-end tests for --build-kernel-gdt (needs Ghidra + gcc)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import require_ghidra

# ── Skip guards ───────────────────────────────────────────────────────


def require_gcc() -> None:
    if shutil.which("gcc") is None:
        pytest.skip("gcc not installed")


# ── Fixtures ──────────────────────────────────────────────────────────

MINIMAL_TYPES_H = """\
#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef unsigned long size_t;

#endif
"""

MINIMAL_LIST_H = """\
#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

#endif
"""

MINIMAL_SKBUFF_H = """\
#ifndef _LINUX_SKBUFF_H
#define _LINUX_SKBUFF_H

#include <linux/types.h>

struct sk_buff {
    unsigned int len;
    unsigned int data_len;
    unsigned short protocol;
    unsigned char *data;
    unsigned char *head;
    unsigned char *tail;
    unsigned char *end;
};

#endif
"""

MINIMAL_NETDEVICE_H = """\
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/types.h>

struct net_device {
    char name[16];
    unsigned int mtu;
    unsigned int flags;
    unsigned char addr_len;
};

#endif
"""


@pytest.fixture(scope="module")
def fake_kernel_tree(tmp_path_factory) -> Path:
    """Create a minimal fake kernel source tree for the full pipeline."""
    root = tmp_path_factory.mktemp("kernel_src")

    (root / "include" / "linux").mkdir(parents=True)
    (root / "include" / "linux" / "types.h").write_text(MINIMAL_TYPES_H)
    (root / "include" / "linux" / "list.h").write_text(MINIMAL_LIST_H)
    (root / "include" / "linux" / "skbuff.h").write_text(MINIMAL_SKBUFF_H)
    (root / "include" / "linux" / "netdevice.h").write_text(MINIMAL_NETDEVICE_H)

    (root / "include" / "uapi" / "linux").mkdir(parents=True)
    (root / "include" / "uapi" / "linux" / "types.h").write_text(
        "#ifndef _UAPI_LINUX_TYPES_H\n#define _UAPI_LINUX_TYPES_H\n#endif\n"
    )

    (root / "arch" / "x86" / "include" / "asm").mkdir(parents=True)
    (root / "arch" / "x86" / "include" / "asm" / "types.h").write_text(
        "/* x86 asm types stub */\n"
    )

    (root / "arch" / "x86" / "include" / "generated").mkdir(parents=True)
    (root / "include" / "generated").mkdir(parents=True)

    return root


@pytest.fixture(scope="module")
def built_gdt(fake_kernel_tree, tmp_path_factory) -> Path:
    """Run the full build_kernel_gdt pipeline once."""
    require_ghidra()
    require_gcc()

    output = tmp_path_factory.mktemp("gdt_out") / "linux-test-x86_64.gdt"

    from ghidra_decomp.kernel_gdt import build_kernel_gdt

    build_kernel_gdt(
        fake_kernel_tree,
        "x86_64",
        output,
        ghidra_path=require_ghidra(),
    )
    return output


# ── Tests ─────────────────────────────────────────────────────────────


class TestGdtCreation:
    def test_gdt_file_created(self, built_gdt: Path):
        assert built_gdt.is_file()
        assert built_gdt.stat().st_size > 0

    def test_gdt_has_gdt_extension(self, built_gdt: Path):
        assert built_gdt.suffix == ".gdt"


class TestGdtContents:
    def test_gdt_contains_list_head(self, built_gdt: Path):
        require_ghidra()
        names = _list_type_names(built_gdt)
        assert "list_head" in names

    def test_gdt_contains_sk_buff(self, built_gdt: Path):
        require_ghidra()
        names = _list_type_names(built_gdt)
        assert "sk_buff" in names

    def test_gdt_contains_net_device(self, built_gdt: Path):
        require_ghidra()
        names = _list_type_names(built_gdt)
        assert "net_device" in names

    def test_gdt_sk_buff_has_fields(self, built_gdt: Path):
        require_ghidra()
        fields = _get_struct_field_names(built_gdt, "sk_buff")
        assert "len" in fields
        assert "data_len" in fields
        assert "data" in fields

    def test_gdt_has_multiple_types(self, built_gdt: Path):
        require_ghidra()
        names = _list_type_names(built_gdt)
        assert len(names) >= 4


class TestGdtRoundtrip:
    def test_gdt_loadable_by_apply_gdts(self, built_gdt: Path):
        """Verify the .gdt can be opened with the same API _apply_gdts uses."""
        require_ghidra()

        from ghidra_decomp.decompiler import _start_pyghidra

        _start_pyghidra(require_ghidra())

        from ghidra.program.model.data import FileDataTypeManager
        from java.io import File as JavaFile

        archive = FileDataTypeManager.openFileArchive(JavaFile(str(built_gdt)), False)
        try:
            types = list(archive.getAllDataTypes())
            assert len(types) > 0
        finally:
            archive.close()


class TestCliSubprocess:
    def test_cli_full_pipeline(self, fake_kernel_tree: Path, tmp_path: Path):
        require_ghidra()
        require_gcc()

        output = tmp_path / "cli_test.gdt"
        ghidra_path = require_ghidra()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ghidra_decomp",
                "--build-kernel-gdt",
                str(fake_kernel_tree),
                "--arch",
                "x86_64",
                "-o",
                str(output),
                "--ghidra-path",
                str(ghidra_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert result.returncode == 0, (
            f"CLI failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert output.is_file()

    def test_cli_missing_arch_fails(self, fake_kernel_tree: Path, tmp_path: Path):
        output = tmp_path / "test.gdt"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ghidra_decomp",
                "--build-kernel-gdt",
                str(fake_kernel_tree),
                "-o",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode != 0

    def test_cli_reports_type_count(self, fake_kernel_tree: Path, tmp_path: Path):
        require_ghidra()
        require_gcc()

        output = tmp_path / "count_test.gdt"
        ghidra_path = require_ghidra()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ghidra_decomp",
                "--build-kernel-gdt",
                str(fake_kernel_tree),
                "--arch",
                "x86_64",
                "-o",
                str(output),
                "--ghidra-path",
                str(ghidra_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert result.returncode == 0
        assert "types exported" in result.stdout

    def test_cli_with_kernel_config(self, fake_kernel_tree: Path, tmp_path: Path):
        require_ghidra()
        require_gcc()

        config = tmp_path / ".config"
        config.write_text("CONFIG_SMP=y\nCONFIG_NET=m\n")
        output = tmp_path / "config_test.gdt"
        ghidra_path = require_ghidra()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ghidra_decomp",
                "--build-kernel-gdt",
                str(fake_kernel_tree),
                "--arch",
                "x86_64",
                "-o",
                str(output),
                "--ghidra-path",
                str(ghidra_path),
                "--kernel-config",
                str(config),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert result.returncode == 0, (
            f"CLI failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert output.is_file()


# ── Real kernel source tree tests ────────────────────────────────────

KERNEL_CACHE_DIR = Path("/tmp/kernel-source-cache")
KERNEL_DOWNLOAD_VER = "6.1.119"
KERNEL_DOWNLOAD_URL = (
    f"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-{KERNEL_DOWNLOAD_VER}.tar.xz"
)


def _find_local_tarball() -> Path | None:
    """Find a linux-source tarball under /usr/src (Debian/Kali)."""
    import glob

    hits = sorted(glob.glob("/usr/src/linux-source-*.tar.xz"))
    return Path(hits[-1]) if hits else None


def _ensure_real_kernel_tree() -> Path:
    """Return path to a prepared kernel source tree, downloading if needed.

    Checks for already-prepared cached tree first, then local Debian/Kali
    tarball, then downloads from kernel.org. Never skips.
    """
    # Check for any already-prepared tree in cache
    if KERNEL_CACHE_DIR.is_dir():
        for child in sorted(KERNEL_CACHE_DIR.iterdir()):
            if child.is_dir() and (child / ".prepared").is_file():
                return child

    KERNEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    local = _find_local_tarball()
    if local is not None:
        tarball = local
    else:
        tarball = KERNEL_CACHE_DIR / f"linux-{KERNEL_DOWNLOAD_VER}.tar.xz"
        if not tarball.is_file():
            subprocess.run(
                ["curl", "-fSL", "-o", str(tarball), KERNEL_DOWNLOAD_URL],
                check=True,
                timeout=600,
            )

    subprocess.run(
        ["tar", "xf", str(tarball), "-C", str(KERNEL_CACHE_DIR)],
        check=True,
        timeout=300,
    )

    # Find the extracted directory (name varies by distro tarball vs kernel.org)
    dirs = [
        d
        for d in sorted(KERNEL_CACHE_DIR.iterdir())
        if d.is_dir() and (d / "include" / "linux").is_dir()
    ]
    assert dirs, f"No kernel source directory found after extracting {tarball}"
    kernel_dir = dirs[-1]

    subprocess.run(
        ["make", "defconfig"],
        cwd=str(kernel_dir),
        check=True,
        capture_output=True,
        timeout=300,
    )
    subprocess.run(
        ["make", "prepare"],
        cwd=str(kernel_dir),
        check=True,
        capture_output=True,
        timeout=300,
    )

    (kernel_dir / ".prepared").touch()
    return kernel_dir


@pytest.fixture(scope="module")
def real_kernel_tree() -> Path:
    return _ensure_real_kernel_tree()


@pytest.fixture(scope="module")
def real_kernel_gdt(real_kernel_tree, tmp_path_factory) -> Path:
    require_ghidra()
    require_gcc()

    output = tmp_path_factory.mktemp("real_gdt") / "linux-7.2-x86_64.gdt"

    from ghidra_decomp.kernel_gdt import build_kernel_gdt

    stats = build_kernel_gdt(
        real_kernel_tree,
        "x86_64",
        output,
        ghidra_path=require_ghidra(),
    )
    assert stats["types_count"] > 0
    return output


class TestRealKernelGdt:
    """E2E tests against a real kernel source tree."""

    def test_gdt_created(self, real_kernel_gdt: Path):
        assert real_kernel_gdt.is_file()
        assert real_kernel_gdt.stat().st_size > 10000

    def test_has_many_types(self, real_kernel_gdt: Path):
        require_ghidra()
        names = _list_type_names(real_kernel_gdt)
        assert len(names) > 1000

    def test_has_core_structs(self, real_kernel_gdt: Path):
        require_ghidra()
        names = _list_type_names(real_kernel_gdt)
        for expected in ["list_head", "sk_buff", "task_struct", "inode", "file"]:
            assert expected in names, f"missing core struct: {expected}"

    def test_task_struct_has_fields(self, real_kernel_gdt: Path):
        require_ghidra()
        fields = _get_struct_field_names(real_kernel_gdt, "task_struct")
        assert "pid" in fields
        assert "comm" in fields

    def test_sk_buff_has_fields(self, real_kernel_gdt: Path):
        require_ghidra()
        fields = _get_struct_field_names(real_kernel_gdt, "sk_buff")
        assert len(fields) > 10

    def test_cli_full_pipeline(self, real_kernel_tree: Path, tmp_path: Path):
        require_ghidra()
        require_gcc()

        output = tmp_path / "cli_real.gdt"
        ghidra_path = require_ghidra()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ghidra_decomp",
                "--build-kernel-gdt",
                str(real_kernel_tree),
                "--arch",
                "x86_64",
                "-o",
                str(output),
                "--ghidra-path",
                str(ghidra_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, (
            f"CLI failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "types exported" in result.stdout


# ── Helpers ───────────────────────────────────────────────────────────


def _list_type_names(gdt_path: Path) -> set[str]:
    """Open a .gdt and return all type names."""
    from ghidra_decomp.decompiler import _start_pyghidra

    _start_pyghidra(require_ghidra())

    from ghidra.program.model.data import FileDataTypeManager
    from java.io import File as JavaFile

    archive = FileDataTypeManager.openFileArchive(JavaFile(str(gdt_path)), False)
    try:
        return {str(dt.getName()) for dt in archive.getAllDataTypes()}
    finally:
        archive.close()


def _get_struct_field_names(gdt_path: Path, struct_name: str) -> set[str]:
    """Open a .gdt and return field names for a named struct."""
    from ghidra_decomp.decompiler import _start_pyghidra

    _start_pyghidra(require_ghidra())

    from ghidra.program.model.data import FileDataTypeManager, Structure
    from java.io import File as JavaFile

    archive = FileDataTypeManager.openFileArchive(JavaFile(str(gdt_path)), False)
    try:
        for dt in archive.getAllDataTypes():
            if str(dt.getName()) == struct_name and isinstance(dt, Structure):
                return {
                    str(comp.getFieldName() or f"field_0x{comp.getOffset():x}")
                    for comp in dt.getComponents()
                }
    finally:
        archive.close()
    return set()
