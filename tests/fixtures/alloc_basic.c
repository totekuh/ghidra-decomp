/*
 * Fixture for --alloc-map basic allocation tests.
 *
 * Freestanding and libc-free: allocators are defined as noinline stubs so
 * Ghidra sees named CALL targets with the right signatures.  Each test
 * function exercises one allocation pattern and one store target kind.
 *
 * Never executed; bodies exist only to be decompiled.
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

__attribute__((noinline)) void *realloc(void *ptr, size_t size) {
    volatile size_t s = size;
    (void)s;
    (void)ptr;
    return g_pool;
}

/* ── test structs ──────────────────────────────────────────────────── */

struct node {
    int id;
    char pad[28];
    void *buf;    /* offset 32 on most architectures */
};

static void *g_ptr;
static void *g_array[4];

/* ── test functions ────────────────────────────────────────────────── */

/* malloc with constant size, store to struct field */
__attribute__((noinline)) void alloc_to_field(struct node *n) {
    n->buf = malloc(64);
}

/* calloc with constant count * size (product) */
__attribute__((noinline)) void alloc_calloc(struct node *n) {
    n->buf = calloc(16, 4);
}

/* realloc with old pointer + new size */
__attribute__((noinline)) void alloc_realloc(struct node *n) {
    n->buf = realloc(n->buf, 128);
}

/* variable-size malloc (size from parameter) */
__attribute__((noinline)) void alloc_variable(struct node *n, size_t sz) {
    n->buf = malloc(sz);
}

/* store to global pointer */
__attribute__((noinline)) void alloc_to_global(void) {
    g_ptr = malloc(256);
}

/* store to array element */
__attribute__((noinline)) void alloc_to_array(int idx) {
    g_array[idx] = malloc(512);
}

void entry(void) {
    struct node n;
    n.id = 1;
    alloc_to_field(&n);
    alloc_calloc(&n);
    alloc_realloc(&n);
    alloc_variable(&n, 100);
    alloc_to_global();
    alloc_to_array(0);
    g_sink = (unsigned)(size_t)n.buf;
}
