/*
 * Fixture for the --pcode export end-to-end test.
 *
 * Freestanding and libc-free on purpose: every call resolves to a function
 * defined in this translation unit, so callee names and argument varnodes are
 * present on every target architecture. The shape deliberately exercises each
 * fact the pcode export is supposed to emit:
 *
 *   - an open-coded copy loop (a STORE sink inside a loop -> back-edge),
 *   - a stack buffer of known size (stack-capacity extent),
 *   - a constant allocation size reaching a call as a const argument,
 *   - a length guard that dominates a bounded copy (comparison + CBRANCH),
 *   - calls whose arguments are recovered positionally.
 *
 * It is never executed; the bodies exist only to be decompiled.
 */

#define POOL_CAP 0x800

static char g_pool[POOL_CAP];
static volatile unsigned g_sink;

/* A stand-in allocator. The constant POOL_CAP reaches it as a CALL argument. */
__attribute__((noinline)) char *reserve(unsigned size) {
    volatile unsigned requested = size;
    (void)requested;
    return g_pool;
}

/* An open-coded byte copy: the STORE lives inside a loop, so the pcode CFG
 * must carry a back-edge for a consumer to recognise the copy-loop sink. */
__attribute__((noinline)) void copy_bytes(char *dst, const char *src, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

/* The length guard `n < sizeof(buf)` must dominate the bounded copy; the
 * unguarded copy into the heap pool is the overflow shape. */
__attribute__((noinline)) int bounded_copy(const char *src, unsigned n) {
    char buf[64];
    char *heap = reserve(POOL_CAP);
    if (n < sizeof(buf)) {
        copy_bytes(buf, src, n);
    }
    copy_bytes(heap, src, n);
    return buf[0];
}

void entry(void) {
    static const char src[80];
    volatile unsigned n = 72;
    g_sink = (unsigned)bounded_copy(src, n);
}
