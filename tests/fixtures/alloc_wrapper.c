/*
 * Fixture for --alloc-map wrapper unwrapping tests.
 *
 * Tests detection and resolution of simple allocator wrappers: functions
 * that call exactly one known allocator, return its result, and pass a
 * parameter as the size without arithmetic.
 *
 * Freestanding; never executed.
 */

typedef unsigned long size_t;

static char g_pool[4096];
static volatile unsigned g_sink;

/* ── fake allocators ───────────────────────────────────────────────── */

__attribute__((noinline)) void *malloc(size_t size) {
    volatile size_t s = size;
    (void)s;
    return g_pool;
}

__attribute__((noinline)) void *calloc(size_t count, size_t size) {
    volatile size_t c = count, s = size;
    (void)c;
    (void)s;
    return g_pool;
}

/* ── fake abort (never called, exists for Ghidra to see the branch) ── */

__attribute__((noinline, noreturn)) void fake_abort(void) {
    for (;;) {}
}

/* ── wrapper functions ────────────────────────────────────────────── */

/* Simple wrapper: calloc(1, n) with null check */
__attribute__((noinline)) void *safe_malloc(size_t n) {
    void *p = calloc(1, n);
    if (!p) fake_abort();
    return p;
}

/* Calloc wrapper: passes both args through */
__attribute__((noinline)) void *safe_calloc(size_t count, size_t size) {
    void *p = calloc(count, size);
    if (!p) fake_abort();
    return p;
}

/* Two-level chain: calls safe_malloc, which calls calloc */
__attribute__((noinline)) void *opt_malloc(size_t n) {
    return safe_malloc(n);
}

/* Logged wrapper: second calloc-based leaf, same size param as safe_malloc */
__attribute__((noinline)) void *logged_malloc(size_t n) {
    void *p = calloc(1, n);
    if (!p) fake_abort();
    return p;
}

/* Multi-path wrapper: two store-free allocator calls with the same size
 * param (dnsmasq opt_malloc shape: mem_recover picks the branch) */
static volatile unsigned g_pick;

__attribute__((noinline)) void *two_path_alloc(size_t n) {
    if (g_pick) return safe_malloc(n);
    return logged_malloc(n);
}

/* NOT a wrapper: two allocs with different size params */
__attribute__((noinline)) void *pick_alloc(size_t n, size_t m) {
    if (g_pick) return malloc(n);
    return malloc(m);
}

/* 5-level deep chain: w1 -> w2 -> w3 -> w4 -> w5 -> malloc */
__attribute__((noinline)) void *w5_alloc(size_t n) { return malloc(n); }
__attribute__((noinline)) void *w4_alloc(size_t n) { return w5_alloc(n); }
__attribute__((noinline)) void *w3_alloc(size_t n) { return w4_alloc(n); }
__attribute__((noinline)) void *w2_alloc(size_t n) { return w3_alloc(n); }
__attribute__((noinline)) void *w1_alloc(size_t n) { return w2_alloc(n); }

/* ── NOT wrappers ─────────────────────────────────────────────────── */

/* Calls malloc twice (fallback pattern) — not a simple wrapper */
__attribute__((noinline)) void *tricky_alloc(size_t n) {
    void *p = malloc(n);
    if (!p) p = malloc(n / 2);
    return p;
}

/* Arithmetic on size arg — not a simple wrapper */
__attribute__((noinline)) void *header_alloc(size_t payload) {
    return malloc(payload + 16);
}

/* ── test structs ─────────────────────────────────────────────────── */

struct ctx {
    int state;
    char pad[28];
    void *buf;    /* offset 32 */
};

/* ── helper (consumer, not an allocator) ──────────────────────────── */

__attribute__((noinline)) void memcpy_fake(void *dst, void *src, size_t n) {
    volatile size_t len = n;
    (void)len;
    (void)dst;
    (void)src;
}

/* ── test functions (callers) ─────────────────────────────────────── */

/* Fixture 1: simple wrapper, constant size */
__attribute__((noinline)) void use_buffer(void) {
    char *buf = safe_malloc(256);
    buf[0] = 'x';
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 2: simple wrapper, variable size */
__attribute__((noinline)) void copy_data(void *src, size_t len) {
    char *buf = safe_malloc(len);
    memcpy_fake(buf, src, len);
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 3: two-level wrapper chain */
__attribute__((noinline)) void use_opt(void) {
    char *buf = opt_malloc(128);
    buf[0] = 'y';
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 4: wrapper with field store */
__attribute__((noinline)) void wrapper_init_ctx(struct ctx *c) {
    c->buf = safe_malloc(64);
}

/* Fixture 7: calloc wrapper with product */
__attribute__((noinline)) void use_safe_calloc(void) {
    int *arr = safe_calloc(10, 4);
    arr[0] = 42;
    g_sink = (unsigned)(size_t)arr;
}

/* Fixture 5: NOT a wrapper — multiple allocators */
__attribute__((noinline)) void use_tricky(void) {
    char *buf = tricky_alloc(512);
    buf[0] = 'z';
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 6: NOT a wrapper — arithmetic on size */
__attribute__((noinline)) void use_header(void) {
    char *buf = header_alloc(100);
    buf[0] = 'a';
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 9: multi-path wrapper (two allocator calls, same size param) */
__attribute__((noinline)) void use_two_path(void) {
    char *buf = two_path_alloc(200);
    buf[0] = 'p';
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 10: NOT a wrapper — different size params on the two paths */
__attribute__((noinline)) void use_pick(void) {
    char *buf = pick_alloc(7, 9);
    buf[0] = 'q';
    g_sink = (unsigned)(size_t)buf;
}

/* Fixture 8: 5-level deep wrapper chain */
__attribute__((noinline)) void use_deep(void) {
    char *buf = w1_alloc(77);
    buf[0] = 'd';
    g_sink = (unsigned)(size_t)buf;
}

void entry(void) {
    struct ctx c;
    c.state = 0;
    use_buffer();
    copy_data(&c, 10);
    use_opt();
    wrapper_init_ctx(&c);
    use_safe_calloc();
    use_tricky();
    use_header();
    use_deep();
    use_two_path();
    use_pick();
    g_sink = (unsigned)(size_t)c.buf;
}
