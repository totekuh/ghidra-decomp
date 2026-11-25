"""Constants and configuration for the kernel GDT pipeline."""

from __future__ import annotations

import logging
from typing import Any

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

TREE_EXCLUDE_DIRS: set[str] = {
    "tools",
    "samples",
    "Documentation",
    "scripts",
    "usr",
    ".git",
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
