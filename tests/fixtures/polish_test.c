/* Fixture for decompilation polish e2e tests.
 *
 * Compiled at -O0 with no optimizations. Written to produce maximally
 * verbose Ghidra decompiler output: dead stack variables, redundant casts,
 * explicit zero comparisons, and unnecessary temporaries. */

typedef unsigned int u32;
typedef unsigned char u8;

volatile u32 sink = 0;
volatile u32 source = 0x41414141U;

/* Force dead variables onto the stack where Ghidra will see them.
 * volatile reads prevent the compiler from folding anything. */
__attribute__((noinline, used)) u32 dead_var_test(u32 input) {
    volatile u32 scratch1 = input * 3;
    volatile u32 scratch2 = input + 7;
    volatile u32 scratch3 = input - 1;
    u32 temp1 = scratch1;
    u32 temp2 = scratch2;
    u32 temp3 = scratch3;
    u32 live = input ^ 0xdeadbeefU;
    /* temp1/temp2/temp3 are assigned from volatiles but never used after.
     * Ghidra sees the stack slots and emits declarations + assignments
     * for all of them, producing dead variables in the decompiled output. */
    (void)temp1;
    (void)temp2;
    (void)temp3;
    return live;
}

/* Boolean verbosity through flag variables and nested conditions. */
__attribute__((noinline, used)) u32 bool_test(u32 a, u32 b, u32 c) {
    u32 result = 0;
    u32 flag = 0;

    if (a != 0) {
        result = a;
        flag = 1;
    }
    if (b == 0) {
        result = result + 1;
    }
    if (flag != 0 && c != 0) {
        result = result + c;
    }
    while (a != 0) {
        a = a - 1;
        result = result + a;
    }
    if (!(a == b)) {
        result = result ^ 0xff;
    }
    return result;
}

/* Force casts by moving data through different-width intermediaries.
 * At -O0 the compiler keeps every cast on the stack. */
__attribute__((noinline, used)) u32 cast_test(u32 value, const u8 *data, u32 len) {
    u32 i;
    u32 accum = 0;
    for (i = 0; i < len; i = i + 1) {
        u8 byte_val = data[i];
        u32 wide = (u32)byte_val;
        u32 shifted = wide << 8;
        u32 mixed = shifted ^ value;
        accum = accum + mixed;
    }
    /* Redundant same-type assignment chain */
    u32 final_val = accum;
    u32 ret_val = final_val;
    return ret_val;
}

/* Struct-like access through pointer arithmetic — Ghidra emits casts. */
__attribute__((noinline, used)) u32 ptr_cast_test(void *obj) {
    u32 field1 = *(u32 *)obj;
    u32 field2 = *(u32 *)((u8 *)obj + 4);
    u32 field3 = *(u32 *)((u8 *)obj + 8);
    if (field1 != 0) {
        return field1 + field2;
    }
    return field3;
}

/* Nested boolean expressions that Ghidra keeps verbose. */
__attribute__((noinline, used)) u32 nested_bool_test(u32 x, u32 y, u32 z) {
    u32 result = 0;
    if (x != 0 && y != 0) {
        result = x + y;
    }
    if (x == 0 || y == 0) {
        result = result + z;
    }
    if (!(x != y)) {
        result = result * 2;
    }
    return result;
}

/* Combined: all patterns in one function for max transform coverage. */
__attribute__((noinline, used)) u32 combined_test(u32 x, u32 y) {
    volatile u32 scratch = x * y;
    u32 dead = scratch;
    u32 result = 0;
    (void)dead;

    if (x != 0) {
        u32 cast_x = (u32)x;
        u32 cast_y = (u32)y;
        result = cast_x + cast_y;
    }
    if (y == 0) {
        result = result + 1;
    }
    while (result != 0 && x != 0) {
        result = result - 1;
        x = x - 1;
    }
    return result;
}

/* Entry point. */
__attribute__((used)) u32 entry(void) {
    u32 r1 = dead_var_test(42);
    u32 r2 = bool_test(r1, 0, source);
    u8 buf[] = {0x41, 0x42, 0x43, 0x44};
    u32 r3 = cast_test(r2, buf, 4);
    u32 data[3] = {r1, r2, r3};
    u32 r4 = ptr_cast_test(data);
    u32 r5 = nested_bool_test(r3, r4, r1);
    u32 r6 = combined_test(r5, r1);
    sink = r6;
    return r6;
}
