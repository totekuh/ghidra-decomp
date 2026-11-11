/* Callgraph test fixture: deep chains, diamonds, mutual recursion.
   Designed for verifying reachability, all-paths, endpoints, and condensation. */

typedef unsigned int u32;

volatile u32 sink = 0;

/* --- Leaf functions (no outgoing calls) --- */

__attribute__((noinline, used)) u32 leaf_hash(u32 x) {
    return (x ^ (x >> 16)) * 0x45d9f3bU;
}

__attribute__((noinline, used)) u32 leaf_add(u32 a, u32 b) {
    return a + b;
}

__attribute__((noinline, used)) u32 leaf_xor(u32 a, u32 b) {
    return a ^ b;
}

/* --- Mid-level: diamond pattern (both call the same leaves) --- */

__attribute__((noinline, used)) u32 mid_alpha(u32 x) {
    return leaf_hash(x) + leaf_add(x, 1);
}

__attribute__((noinline, used)) u32 mid_beta(u32 x) {
    return leaf_hash(x) ^ leaf_xor(x, 0xff);
}

/* --- Diamond merge point --- */

__attribute__((noinline, used)) u32 merge_point(u32 x) {
    return mid_alpha(x) + mid_beta(x);
}

/* --- Deep chain: 4 levels deep --- */

__attribute__((noinline, used)) u32 chain_d(u32 x) {
    return leaf_add(x, x);
}

__attribute__((noinline, used)) u32 chain_c(u32 x) {
    return chain_d(x + 1);
}

__attribute__((noinline, used)) u32 chain_b(u32 x) {
    return chain_c(x + 2);
}

__attribute__((noinline, used)) u32 chain_a(u32 x) {
    return chain_b(x + 3);
}

/* --- Mutual recursion (cycle) --- */

__attribute__((noinline, used)) u32 ping(u32 x);
__attribute__((noinline, used)) u32 pong(u32 x);

__attribute__((noinline, used)) u32 ping(u32 x) {
    if (x == 0) return leaf_xor(x, 42);
    return pong(x - 1);
}

__attribute__((noinline, used)) u32 pong(u32 x) {
    if (x == 0) return leaf_add(x, 99);
    return ping(x - 1);
}

/* --- Isolated function (no callers, no callees in this graph) --- */

__attribute__((noinline, used)) u32 isolated_node(u32 x) {
    return x * 7;
}

/* --- Root: calls into diamond, chain, and cycle --- */

__attribute__((used)) u32 entry(void) {
    u32 r = 0;
    r += merge_point(10);
    r += chain_a(20);
    r += ping(5);
    r += isolated_node(r);
    sink = r;
    return r;
}
