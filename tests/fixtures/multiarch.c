/* Freestanding source used to build deterministic cross-architecture fixtures. */

typedef unsigned int u32;

volatile u32 global_state = 0x13579bdfU;
const char *const fixture_marker = "ghidra-decomp multiarch fixture";

__attribute__((noinline, used)) u32 rotate_mix(u32 value, u32 key) {
    u32 mixed = value ^ key;
    return (mixed << 7) | (mixed >> 25);
}

__attribute__((noinline, used)) u32 sum_positive(const int *values, u32 count) {
    u32 total = 0;
    u32 index;

    for (index = 0; index < count; index++) {
        if (values[index] > 0) {
            total += (u32)values[index];
        }
    }
    return total;
}

__attribute__((noinline, used)) u32 marker_checksum(const char *text) {
    u32 checksum = 0;

    while (*text != '\0') {
        checksum = (checksum * 33U) ^ (u32)(unsigned char)*text;
        text++;
    }
    return checksum;
}

__attribute__((noinline, used)) u32 dispatch(u32 operation, u32 value) {
    switch (operation) {
    case 0:
        return rotate_mix(value, 0xa5a5a5a5U);
    case 1:
        return value + global_state;
    case 2:
        return value * 17U;
    default:
        return 0xffffffffU;
    }
}

__attribute__((used)) u32 entry(void) {
    static const int values[] = {3, -5, 8, 13};
    u32 result = dispatch(0, (u32)sum_positive(values, 4));

    result ^= marker_checksum(fixture_marker);
    global_state = result;
    return result;
}
