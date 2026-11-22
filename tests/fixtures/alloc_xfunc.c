/*
 * Fixture for --alloc-map cross-function pointer flow tests.
 *
 * Tests the patterns that matter for cross-function overflow detection:
 * alloc in one function, use in another, linked through struct fields or
 * direct argument passing.
 *
 * Freestanding; never executed.
 */

typedef unsigned long size_t;

static char g_pool[4096];
static volatile unsigned g_sink;

__attribute__((noinline)) void *malloc(size_t size) {
    volatile size_t s = size;
    (void)s;
    return g_pool;
}

/* ── test structs ──────────────────────────────────────────────────── */

struct ctx {
    int state;
    char pad[28];
    void *buf;      /* offset 32 */
    void *extra;    /* offset 32 + ptr_size */
};

/* ── helper (not an allocator, just a consumer) ────────────────────── */

__attribute__((noinline)) void use_buffer(void *buf, unsigned len) {
    volatile unsigned l = len;
    (void)l;
    (void)buf;
}

/* ── test functions ────────────────────────────────────────────────── */

/* Classic CVE pattern: alloc to struct field, used by a different function */
__attribute__((noinline)) void init_ctx(struct ctx *c) {
    c->buf = malloc(64);
}

/* Alloc result passed directly as argument to another function */
__attribute__((noinline)) void alloc_and_pass(unsigned len) {
    void *p = malloc(256);
    use_buffer(p, len);
}

/* Alloc result returned from function */
__attribute__((noinline)) void *alloc_and_return(size_t sz) {
    return malloc(sz);
}

/* Multiple struct fields allocated in same function */
__attribute__((noinline)) void init_full(struct ctx *c) {
    c->buf = malloc(64);
    c->extra = malloc(128);
}

/* Chain: caller gets returned pointer, stores it to struct field */
__attribute__((noinline)) void caller_stores(struct ctx *c, size_t sz) {
    c->buf = alloc_and_return(sz);
}

void entry(void) {
    struct ctx c;
    c.state = 0;
    init_ctx(&c);
    alloc_and_pass(10);
    void *r = alloc_and_return(32);
    init_full(&c);
    caller_stores(&c, 48);
    g_sink = (unsigned)(size_t)r;
    g_sink = (unsigned)(size_t)c.buf;
}
