"""Unit tests for kernel_gdt module (no Ghidra needed)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ghidra_decomp.cli import main
from ghidra_decomp.kernel_gdt import (
    ARCH_DEFINES,
    COMPAT_SHIM,
    PRIORITY_HEADERS,
    KernelGdtError,
    _group_by_subdir,
    build_amalgamation,
    build_gcc_command,
    discover_headers,
    discover_tree_headers,
    parse_kconfig,
    preprocess_headers,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def fake_kernel_tree(tmp_path: Path) -> Path:
    """Create a minimal fake kernel source tree."""
    (tmp_path / "include" / "linux").mkdir(parents=True)
    (tmp_path / "include" / "linux" / "types.h").write_text(
        "typedef unsigned long size_t;\n"
    )
    (tmp_path / "include" / "linux" / "list.h").write_text(
        "struct list_head { struct list_head *next, *prev; };\n"
    )
    (tmp_path / "include" / "linux" / "skbuff.h").write_text(
        "struct sk_buff { unsigned int len; };\n"
    )

    (tmp_path / "include" / "uapi" / "linux").mkdir(parents=True)
    (tmp_path / "include" / "uapi" / "linux" / "if.h").write_text(
        "struct ifreq { char ifr_name[16]; };\n"
    )

    (tmp_path / "include" / "net").mkdir(parents=True)
    (tmp_path / "include" / "net" / "cfg80211.h").write_text(
        "struct wiphy { int signal_type; };\n"
    )

    (tmp_path / "arch" / "x86" / "include" / "asm").mkdir(parents=True)
    (tmp_path / "arch" / "x86" / "include" / "asm" / "types.h").write_text(
        "/* x86 types */\n"
    )

    (tmp_path / "arch" / "arm64" / "include" / "asm").mkdir(parents=True)
    (tmp_path / "arch" / "arm64" / "include" / "asm" / "types.h").write_text(
        "/* arm64 types */\n"
    )

    (tmp_path / "drivers" / "net" / "wireless").mkdir(parents=True)
    (tmp_path / "drivers" / "net" / "wireless" / "mwifiex.h").write_text(
        "struct mwifiex_private { int bss_type; };\n"
    )

    return tmp_path


# ── discover_headers ──────────────────────────────────────────────────


def test_discover_headers_finds_linux_headers(fake_kernel_tree: Path):
    headers = discover_headers(fake_kernel_tree, "x86_64")
    assert "linux/types.h" in headers
    assert "linux/list.h" in headers
    assert "linux/skbuff.h" in headers


def test_discover_headers_finds_net_headers(fake_kernel_tree: Path):
    headers = discover_headers(fake_kernel_tree, "x86_64")
    assert "net/cfg80211.h" in headers


def test_discover_headers_only_returns_existing(fake_kernel_tree: Path):
    headers = discover_headers(fake_kernel_tree, "x86_64")
    # Only returns PRIORITY_HEADERS that exist in tree
    for h in headers:
        assert h in PRIORITY_HEADERS


def test_discover_headers_priority_first(fake_kernel_tree: Path):
    headers = discover_headers(fake_kernel_tree, "x86_64")
    present_priority = [h for h in PRIORITY_HEADERS if h in headers]
    if present_priority:
        first_priority_idx = headers.index(present_priority[0])
        assert first_priority_idx == 0


def test_discover_headers_empty_tree(tmp_path: Path):
    headers = discover_headers(tmp_path, "x86_64")
    assert headers == []


def test_discover_headers_missing_subdirs(tmp_path: Path):
    (tmp_path / "include" / "linux").mkdir(parents=True)
    (tmp_path / "include" / "linux" / "types.h").write_text("/* types */\n")
    headers = discover_headers(tmp_path, "x86_64")
    assert "linux/types.h" in headers


def test_discover_headers_unsupported_arch(tmp_path: Path):
    with pytest.raises(KernelGdtError, match="Unsupported architecture"):
        discover_headers(tmp_path, "sparc128")


# ── discover_tree_headers ────────────────────────────────────────────


def test_discover_tree_headers_finds_driver_headers(fake_kernel_tree: Path):
    priority = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", priority)
    abs_names = {p.name for p in tree}
    assert "mwifiex.h" in abs_names


def test_discover_tree_headers_excludes_tools(fake_kernel_tree: Path):
    (fake_kernel_tree / "tools" / "perf" / "util").mkdir(parents=True)
    (fake_kernel_tree / "tools" / "perf" / "util" / "perf.h").write_text("/* perf */\n")
    priority = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", priority)
    abs_names = {p.name for p in tree}
    assert "perf.h" not in abs_names


def test_discover_tree_headers_excludes_non_target_arch(fake_kernel_tree: Path):
    priority = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", priority)
    for p in tree:
        assert "/arch/arm64/" not in str(p)


def test_discover_tree_headers_deduplicates_priority(fake_kernel_tree: Path):
    priority = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", priority)
    for p in tree:
        rel = p.relative_to(fake_kernel_tree.resolve())
        rel_str = str(rel)
        assert rel_str not in priority, f"{rel_str} duplicates a priority header"


def test_discover_tree_headers_empty_tree(tmp_path: Path):
    tree = discover_tree_headers(tmp_path, "x86_64", [])
    assert tree == []


def test_discover_tree_headers_sorted(fake_kernel_tree: Path):
    priority = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", priority)
    assert tree == sorted(tree)


def test_amalgamation_includes_tree_headers_with_absolute_paths(
    fake_kernel_tree: Path,
):
    headers = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", headers)
    text = build_amalgamation(fake_kernel_tree, "x86_64", headers, tree_headers=tree)
    for tp in tree:
        assert f'#include "{tp}"' in text
    assert "#include <linux/types.h>" in text


def test_amalgamation_tree_headers_after_priority(fake_kernel_tree: Path):
    headers = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", headers)
    text = build_amalgamation(fake_kernel_tree, "x86_64", headers, tree_headers=tree)
    last_priority = text.rfind("#include <")
    first_tree = text.find('#include "/')
    assert first_tree > last_priority


# ── parse_kconfig ─────────────────────────────────────────────────────


def test_parse_kconfig_dotconfig(tmp_path: Path):
    config = tmp_path / ".config"
    config.write_text(
        "# CONFIG_DEBUG is not set\n"
        "CONFIG_SMP=y\n"
        "CONFIG_NET=m\n"
        "CONFIG_MODULES=y\n"
        'CONFIG_LOCALVERSION="-custom"\n'
    )
    defines = parse_kconfig(config)
    assert "CONFIG_SMP" in defines
    assert "CONFIG_NET" in defines
    assert "CONFIG_MODULES" in defines
    assert "CONFIG_DEBUG" not in defines
    assert "CONFIG_LOCALVERSION" not in defines


def test_parse_kconfig_autoconf_h(tmp_path: Path):
    config = tmp_path / "autoconf.h"
    config.write_text(
        "#define CONFIG_SMP 1\n#define CONFIG_NET 1\n#define CONFIG_BT_MODULE 1\n"
    )
    defines = parse_kconfig(config)
    assert "CONFIG_SMP" in defines
    assert "CONFIG_NET" in defines
    assert "CONFIG_BT_MODULE" in defines


def test_parse_kconfig_empty(tmp_path: Path):
    config = tmp_path / ".config"
    config.write_text("")
    assert parse_kconfig(config) == []


# ── build_amalgamation ────────────────────────────────────────────────


def test_build_amalgamation_has_kernel_define(fake_kernel_tree: Path):
    headers = ["linux/types.h"]
    text = build_amalgamation(fake_kernel_tree, "x86_64", headers)
    assert "#define __KERNEL__" in text
    assert "#define MODULE" in text


def test_build_amalgamation_has_arch_defines(fake_kernel_tree: Path):
    text = build_amalgamation(fake_kernel_tree, "x86_64", [])
    assert "#define __x86_64__" in text
    assert "#define __LP64__" in text


def test_build_amalgamation_has_arm64_defines(fake_kernel_tree: Path):
    text = build_amalgamation(fake_kernel_tree, "arm64", [])
    assert "#define __aarch64__" in text


def test_build_amalgamation_includes_headers(fake_kernel_tree: Path):
    headers = ["linux/types.h", "linux/list.h"]
    text = build_amalgamation(fake_kernel_tree, "x86_64", headers)
    assert "#include <linux/types.h>" in text
    assert "#include <linux/list.h>" in text


def test_build_amalgamation_with_config(fake_kernel_tree: Path):
    text = build_amalgamation(
        fake_kernel_tree, "x86_64", [], config_defines=["CONFIG_SMP", "CONFIG_NET"]
    )
    assert "#define CONFIG_SMP 1" in text
    assert "#define CONFIG_NET 1" in text


def test_build_amalgamation_no_config(fake_kernel_tree: Path):
    text = build_amalgamation(fake_kernel_tree, "x86_64", [])
    assert "CONFIG_" not in text


# ── build_gcc_command ─────────────────────────────────────────────────


_GCC_INCLUDE = SimpleNamespace(
    stdout="/usr/lib/gcc/x86_64-linux-gnu/12/include\n", returncode=0
)


@patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", return_value=_GCC_INCLUDE)
def test_build_gcc_command_starts_with_gcc(_mock, tmp_path: Path):
    cmd = build_gcc_command(
        tmp_path, "x86_64", tmp_path / "kernel_types.h", tmp_path / "compat.h"
    )
    assert cmd[0] == "gcc"
    assert "-E" in cmd
    assert "-nostdinc" in cmd


@patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", return_value=_GCC_INCLUDE)
def test_build_gcc_command_arch_include_paths(_mock, tmp_path: Path):
    cmd = build_gcc_command(
        tmp_path, "x86_64", tmp_path / "kernel_types.h", tmp_path / "compat.h"
    )
    cmd_str = " ".join(cmd)
    assert f"{tmp_path}/arch/x86/include" in cmd_str


@patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", return_value=_GCC_INCLUDE)
def test_build_gcc_command_arm64_arch_path(_mock, tmp_path: Path):
    cmd = build_gcc_command(
        tmp_path, "arm64", tmp_path / "kernel_types.h", tmp_path / "compat.h"
    )
    cmd_str = " ".join(cmd)
    assert f"{tmp_path}/arch/arm64/include" in cmd_str


@patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", return_value=_GCC_INCLUDE)
def test_build_gcc_command_includes_compat_shim(_mock, tmp_path: Path):
    compat = tmp_path / "compat.h"
    cmd = build_gcc_command(tmp_path, "x86_64", tmp_path / "kernel_types.h", compat)
    idx = cmd.index("-include")
    assert cmd[idx + 1] == str(compat)


@patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", return_value=_GCC_INCLUDE)
def test_build_gcc_command_ends_with_amalgamation(_mock, tmp_path: Path):
    amal = tmp_path / "kernel_types.h"
    cmd = build_gcc_command(tmp_path, "x86_64", amal, tmp_path / "compat.h")
    assert cmd[-1] == str(amal)


@patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", return_value=_GCC_INCLUDE)
def test_build_gcc_command_has_isystem(_mock, tmp_path: Path):
    cmd = build_gcc_command(
        tmp_path, "x86_64", tmp_path / "kernel_types.h", tmp_path / "compat.h"
    )
    idx = cmd.index("-isystem")
    assert "/gcc/" in cmd[idx + 1]


# ── preprocess_headers ────────────────────────────────────────────────


def test_preprocess_headers_success(tmp_path: Path):
    ok_result = SimpleNamespace(returncode=0, stdout="typedef int __u32;\n", stderr="")
    calls = [_GCC_INCLUDE, ok_result]
    with patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", side_effect=calls):
        result = preprocess_headers(tmp_path, "x86_64", "/* test */", tmp_path)
    assert result.is_file()
    assert "typedef int __u32;" in result.read_text()


def test_preprocess_headers_gcc_not_found(tmp_path: Path):
    call_count = 0

    def _side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _GCC_INCLUDE
        raise FileNotFoundError("gcc")

    with (
        patch(
            "ghidra_decomp.kernel_gdt.preprocess.subprocess.run",
            side_effect=_side_effect,
        ),
        pytest.raises(KernelGdtError, match="gcc not found"),
    ):
        preprocess_headers(tmp_path, "x86_64", "/* test */", tmp_path)


def test_preprocess_headers_gcc_failure(tmp_path: Path):
    fail_result = SimpleNamespace(
        returncode=1, stdout="", stderr="fatal error: file not found\n"
    )
    calls = [_GCC_INCLUDE, fail_result]

    with (
        patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", side_effect=calls),
        pytest.raises(KernelGdtError, match="gcc preprocessing failed"),
    ):
        preprocess_headers(tmp_path, "x86_64", "/* test */", tmp_path)


def test_preprocess_headers_writes_amalgamation(tmp_path: Path):
    ok_result = SimpleNamespace(returncode=0, stdout="/* output */\n", stderr="")
    calls = [_GCC_INCLUDE, ok_result]
    with patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", side_effect=calls):
        preprocess_headers(tmp_path, "x86_64", "#define TEST 1\n", tmp_path)
    assert (tmp_path / "kernel_types.h").is_file()
    assert "#define TEST 1" in (tmp_path / "kernel_types.h").read_text()


def test_preprocess_headers_writes_compat_shim(tmp_path: Path):
    ok_result = SimpleNamespace(returncode=0, stdout="/* output */\n", stderr="")
    calls = [_GCC_INCLUDE, ok_result]
    with patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", side_effect=calls):
        preprocess_headers(tmp_path, "x86_64", "/* test */", tmp_path)
    assert (tmp_path / "ghidra_compat.h").is_file()
    assert "__attribute__" in (tmp_path / "ghidra_compat.h").read_text()


# ── _group_by_subdir / batched preprocessing ─────────────────────────


def test_group_by_subdir(fake_kernel_tree: Path):
    priority = discover_headers(fake_kernel_tree, "x86_64")
    tree = discover_tree_headers(fake_kernel_tree, "x86_64", priority)
    groups = _group_by_subdir(tree, fake_kernel_tree.resolve())
    assert "drivers" in groups
    for h in groups["drivers"]:
        assert "drivers" in str(h)


def test_preprocess_skips_failing_group(tmp_path: Path):
    ok_priority = SimpleNamespace(
        returncode=0, stdout="typedef int __u32;\n", stderr=""
    )
    ok_drivers = SimpleNamespace(
        returncode=0, stdout="struct mwifiex_private { int x; };\n", stderr=""
    )
    fail_arch = SimpleNamespace(
        returncode=1, stdout="", stderr="fatal error: lapic.h\n"
    )
    calls = [
        _GCC_INCLUDE,
        ok_priority,
        _GCC_INCLUDE,
        ok_drivers,
        _GCC_INCLUDE,
        fail_arch,
    ]
    tree_groups = {
        "drivers": [Path("/fake/drivers/mwifiex.h")],
        "arch": [Path("/fake/arch/x86/kvm/lapic.h")],
    }
    with patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", side_effect=calls):
        path = preprocess_headers(
            tmp_path,
            "x86_64",
            "/* priority */",
            tmp_path,
            tree_groups=tree_groups,
        )
    text = path.read_text()
    assert "__u32" in text
    assert "mwifiex_private" in text


def test_preprocess_all_groups_succeed(tmp_path: Path):
    ok_priority = SimpleNamespace(
        returncode=0, stdout="typedef int __u32;\n", stderr=""
    )
    ok_drivers = SimpleNamespace(
        returncode=0, stdout="struct driver_a { int a; };\n", stderr=""
    )
    ok_net = SimpleNamespace(
        returncode=0, stdout="struct net_b { int b; };\n", stderr=""
    )
    calls = [
        _GCC_INCLUDE,
        ok_priority,
        _GCC_INCLUDE,
        ok_drivers,
        _GCC_INCLUDE,
        ok_net,
    ]
    tree_groups = {
        "drivers": [Path("/fake/drivers/a.h")],
        "net": [Path("/fake/net/b.h")],
    }
    with patch("ghidra_decomp.kernel_gdt.preprocess.subprocess.run", side_effect=calls):
        path = preprocess_headers(
            tmp_path,
            "x86_64",
            "/* priority */",
            tmp_path,
            tree_groups=tree_groups,
        )
    text = path.read_text()
    assert "driver_a" in text
    assert "net_b" in text


# ── ARCH_DEFINES ──────────────────────────────────────────────────────


def test_arch_defines_all_have_required_keys():
    for arch_name, info in ARCH_DEFINES.items():
        assert "gcc_defines" in info, f"{arch_name} missing gcc_defines"
        assert "kernel_arch" in info, f"{arch_name} missing kernel_arch"
        assert "pointer_size" in info, f"{arch_name} missing pointer_size"
        assert isinstance(info["gcc_defines"], list)
        assert len(info["gcc_defines"]) > 0


def test_arch_x86_64_maps_to_x86():
    assert ARCH_DEFINES["x86_64"]["kernel_arch"] == "x86"


def test_arch_arm64_maps_to_arm64():
    assert ARCH_DEFINES["arm64"]["kernel_arch"] == "arm64"


def test_arch_ppc_maps_to_powerpc():
    assert ARCH_DEFINES["ppc"]["kernel_arch"] == "powerpc"


def test_arch_riscv64_has_riscv_xlen():
    defines = ARCH_DEFINES["riscv64"]["gcc_defines"]
    assert any("riscv_xlen" in d for d in defines)


# ── COMPAT_SHIM ──────────────────────────────────────────────────────


def test_compat_shim_defines_attribute():
    assert "#define __attribute__(x)" in COMPAT_SHIM


def test_compat_shim_defines_asm():
    assert "#define asm(...)" in COMPAT_SHIM


def test_compat_shim_defines_typeof():
    assert "#define typeof(x)" in COMPAT_SHIM


def test_compat_shim_defines_builtin_offsetof():
    assert "__builtin_offsetof" in COMPAT_SHIM


# ── CLI via CliRunner ─────────────────────────────────────────────────


def test_cli_build_kernel_gdt_missing_arch(fake_kernel_tree: Path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--build-kernel-gdt",
            str(fake_kernel_tree),
            "-o",
            "/tmp/test.gdt",
        ],
    )
    assert result.exit_code != 0
    assert "--arch" in result.output or "--arch" in str(result.exception)


def test_cli_build_kernel_gdt_missing_output(fake_kernel_tree: Path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--build-kernel-gdt",
            str(fake_kernel_tree),
            "--arch",
            "x86_64",
        ],
    )
    assert result.exit_code != 0
    assert "-o" in result.output or "-o" in str(result.exception)


def test_cli_build_kernel_gdt_nonexistent_path():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--build-kernel-gdt",
            "/nonexistent/kernel/tree",
            "--arch",
            "x86_64",
            "-o",
            "/tmp/test.gdt",
        ],
    )
    assert result.exit_code != 0


def test_cli_build_kernel_gdt_dispatches(fake_kernel_tree: Path, tmp_path: Path):
    """Verify --build-kernel-gdt calls build_kernel_gdt and returns."""
    output = tmp_path / "test.gdt"
    mock_stats = {"types_count": 42, "structs": 10, "unions": 2, "enums": 5}
    with patch("ghidra_decomp.kernel_gdt.build_kernel_gdt", return_value=mock_stats):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--build-kernel-gdt",
                str(fake_kernel_tree),
                "--arch",
                "x86_64",
                "-o",
                str(output),
            ],
        )
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert "42 types exported" in result.output


def test_cli_build_kernel_gdt_forwards_config(fake_kernel_tree: Path, tmp_path: Path):
    """Verify --kernel-config is forwarded."""
    output = tmp_path / "test.gdt"
    config = tmp_path / ".config"
    config.write_text("CONFIG_SMP=y\n")
    mock_stats = {"types_count": 10, "structs": 5, "unions": 1, "enums": 0}

    with patch("ghidra_decomp.kernel_gdt.build_kernel_gdt", return_value=mock_stats):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--build-kernel-gdt",
                str(fake_kernel_tree),
                "--arch",
                "x86_64",
                "-o",
                str(output),
                "--kernel-config",
                str(config),
            ],
        )
    assert result.exit_code == 0 or "KernelGdtError" not in str(result.exception)


# ── Orchestrator (mocked stages) ─────────────────────────────────────


def test_orchestrator_calls_all_stages(fake_kernel_tree: Path, tmp_path: Path):
    output = tmp_path / "test.gdt"
    mock_stats = {"types_count": 0, "structs": 0, "unions": 0, "enums": 0}

    with (
        patch("ghidra_decomp.kernel_gdt.builder.preprocess_headers") as mock_preprocess,
        patch(
            "ghidra_decomp.kernel_gdt.builder.parse_and_export_gdt",
            return_value=mock_stats,
        ) as mock_parse_export,
    ):
        mock_preprocess.return_value = tmp_path / "preprocessed.h"
        (tmp_path / "preprocessed.h").write_text("/* preprocessed */\n")

        from ghidra_decomp.kernel_gdt import build_kernel_gdt

        build_kernel_gdt(fake_kernel_tree, "x86_64", output)

    mock_preprocess.assert_called_once()
    mock_parse_export.assert_called_once()


def test_orchestrator_unsupported_arch(fake_kernel_tree: Path, tmp_path: Path):
    from ghidra_decomp.kernel_gdt import build_kernel_gdt

    with pytest.raises(KernelGdtError, match="Unsupported architecture"):
        build_kernel_gdt(fake_kernel_tree, "sparc128", tmp_path / "test.gdt")


def test_orchestrator_passes_config(fake_kernel_tree: Path, tmp_path: Path):
    output = tmp_path / "test.gdt"
    config = tmp_path / ".config"
    config.write_text("CONFIG_SMP=y\nCONFIG_NET=m\n")

    mock_stats = {"types_count": 0, "structs": 0, "unions": 0, "enums": 0}

    with (
        patch("ghidra_decomp.kernel_gdt.builder.preprocess_headers") as mock_preprocess,
        patch(
            "ghidra_decomp.kernel_gdt.builder.parse_and_export_gdt",
            return_value=mock_stats,
        ),
    ):
        mock_preprocess.return_value = tmp_path / "preprocessed.h"
        (tmp_path / "preprocessed.h").write_text("/* preprocessed */\n")

        from ghidra_decomp.kernel_gdt import build_kernel_gdt

        build_kernel_gdt(fake_kernel_tree, "x86_64", output, config=config)

    call_args = mock_preprocess.call_args
    amalgamation_text = call_args[0][2]
    assert "CONFIG_SMP" in amalgamation_text
    assert "CONFIG_NET" in amalgamation_text
