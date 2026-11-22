/*
 * Fixture for --alloc-map complex pointer movement tests.
 *
 * Exercises nested struct stores, multiple allocations in one function
 * with different destinations, and struct-forwarding patterns.
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

struct inner {
    int tag;
    char pad[4];
    void *data;     /* offset 8 */
};

struct outer {
    int id;
    char pad[28];
    void *buf;              /* offset 32 */
    struct inner sub;       /* offset 32 + ptr_size */
};

/* ── helper (consumer, not allocator) ──────────────────────────────── */

__attribute__((noinline)) void process_outer(struct outer *o) {
    volatile unsigned v = (unsigned)(size_t)o->buf;
    (void)v;
}

/* ── test functions ────────────────────────────────────────────────── */

/* Alloc stored to nested struct field */
__attribute__((noinline)) void alloc_nested(struct outer *o) {
    o->sub.data = malloc(96);
}

/* Two allocations in same function, different destinations */
__attribute__((noinline)) void alloc_two(struct outer *o) {
    o->buf = malloc(64);
    o->sub.data = malloc(128);
}

/* Alloc stored to struct field, then struct passed to another function */
__attribute__((noinline)) void alloc_and_forward(struct outer *o) {
    o->buf = malloc(256);
    process_outer(o);
}

/* Multiple allocations across two struct parameters */
__attribute__((noinline)) void multi_alloc(struct outer *a, struct outer *b) {
    a->buf = malloc(32);
    b->buf = malloc(64);
    a->sub.data = malloc(128);
}

void entry(void) {
    struct outer o;
    o.id = 0;
    alloc_nested(&o);
    alloc_two(&o);
    alloc_and_forward(&o);
    struct outer o2;
    o2.id = 1;
    multi_alloc(&o, &o2);
    g_sink = (unsigned)(size_t)o.buf;
    g_sink = (unsigned)(size_t)o2.sub.data;
}
