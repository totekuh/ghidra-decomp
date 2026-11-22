/*
 * Fixture for --alloc-map edge-case tests (complex structures, part 2).
 *
 * Covers patterns the first complex fixture does not:
 *   - deeply nested structs (3 levels)
 *   - double pointer (void **pp)
 *   - alloc in a loop (same call site, conceptually repeated)
 *   - conditional allocation (only one branch allocates)
 *   - zero-size allocation
 *   - chained realloc of a malloc'd pointer in the same function
 *   - alloc stored through an intermediate local before struct field
 *   - array-of-structs with per-element allocation
 *   - non-allocator calls interleaved with allocator calls (negative)
 *   - function whose name contains "alloc" but is not a real allocator
 *
 * Freestanding; never executed.
 */

typedef unsigned long size_t;

static char g_pool[8192];
static volatile unsigned g_sink;

/* ── fake allocators ───────────────────────────────────────────────── */

__attribute__((noinline)) void *malloc(size_t size) {
    volatile size_t s = size;
    (void)s;
    return g_pool;
}

__attribute__((noinline)) void *realloc(void *ptr, size_t size) {
    volatile size_t s = size;
    (void)s;
    (void)ptr;
    return g_pool;
}

/* ── NOT an allocator despite the name ─────────────────────────────── */

__attribute__((noinline)) void dealloc(void *ptr) {
    volatile unsigned v = (unsigned)(size_t)ptr;
    (void)v;
}

__attribute__((noinline)) unsigned count_alloc_failures(void) {
    return 0;
}

/* ── non-allocator helpers ─────────────────────────────────────────── */

__attribute__((noinline)) void memset_fake(void *dst, int val, size_t n) {
    volatile size_t len = n;
    (void)dst;
    (void)val;
    (void)len;
}

__attribute__((noinline)) void consume(void *p) {
    volatile unsigned v = (unsigned)(size_t)p;
    (void)v;
}

/* ── test structs ──────────────────────────────────────────────────── */

struct level3 {
    int tag;
    char pad[4];
    void *payload;      /* offset 8 */
};

struct level2 {
    int flags;
    char pad[4];
    struct level3 deep; /* offset 8 */
};

struct level1 {
    int id;
    char pad[28];
    void *buf;          /* offset 32 */
    struct level2 mid;  /* offset 32 + ptr_size */
};

struct item {
    int key;
    void *data;         /* offset ptr_size (or 8 with padding) */
};

/* ── test functions ────────────────────────────────────────────────── */

/* 3-level deep nested struct field store */
__attribute__((noinline)) void alloc_deep_nested(struct level1 *l) {
    l->mid.deep.payload = malloc(48);
}

/* double pointer: *pp = malloc(N) */
__attribute__((noinline)) void alloc_double_ptr(void **pp) {
    *pp = malloc(72);
}

/* alloc in a loop body — Ghidra sees one CALL site, but it's inside a loop */
__attribute__((noinline)) void alloc_in_loop(struct item *arr, int count) {
    for (int i = 0; i < count; i++) {
        arr[i].data = malloc(100);
    }
}

/* conditional allocation — only one branch allocates */
__attribute__((noinline)) void alloc_conditional(struct level1 *l, int flag) {
    if (flag) {
        l->buf = malloc(200);
    }
}

/* zero-size allocation */
__attribute__((noinline)) void *alloc_zero(void) {
    return malloc(0);
}

/* chained: malloc then realloc in the same function */
__attribute__((noinline)) void alloc_chain(struct level1 *l) {
    void *p = malloc(16);
    p = realloc(p, 256);
    l->buf = p;
}

/* alloc stored to local first, then to struct field */
__attribute__((noinline)) void alloc_via_local(struct level1 *l) {
    void *tmp = malloc(512);
    memset_fake(tmp, 0, 512);
    l->buf = tmp;
}

/* alloc passed to two different consumers (fan-out) */
__attribute__((noinline)) void alloc_fanout(void) {
    void *p = malloc(300);
    consume(p);
    memset_fake(p, 0, 300);
}

/* ── negative: these must NOT produce alloc entries ────────────────── */

/* only calls non-allocators */
__attribute__((noinline)) void no_alloc_at_all(struct level1 *l) {
    memset_fake(l->buf, 0, 64);
    consume(l->buf);
    dealloc(l->buf);
}

/* "alloc" in name but returns unsigned, not pointer — heuristic edge case.
 * The heuristic checks name contains "alloc" so this WILL match, but it
 * is a valid test: it should produce an entry with size_expr "unknown". */
__attribute__((noinline)) void calls_count_alloc(void) {
    unsigned n = count_alloc_failures();
    g_sink = n;
}

void entry(void) {
    struct level1 l;
    l.id = 1;
    alloc_deep_nested(&l);

    void *pp;
    alloc_double_ptr(&pp);

    struct item arr[4];
    alloc_in_loop(arr, 4);

    alloc_conditional(&l, 1);

    void *z = alloc_zero();
    g_sink = (unsigned)(size_t)z;

    alloc_chain(&l);
    alloc_via_local(&l);
    alloc_fanout();

    no_alloc_at_all(&l);
    calls_count_alloc();

    g_sink = (unsigned)(size_t)l.buf;
    g_sink = (unsigned)(size_t)pp;
}
