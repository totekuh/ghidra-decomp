/*
 * Test binary for ghidra-decomp e2e tests.
 * Includes: multiple functions, global strings, structs, function calls,
 * exported symbols, and enough variety to validate decompiler output.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Global strings — should appear in strings.json */
const char *BANNER = "ghidra-decomp test binary";
const char *VERSION = "1.0.0";

/* Global data — should appear in symbols.json */
int g_counter = 42;

/* Struct — should appear in types if Ghidra recovers it via DWARF */
typedef struct {
    int x;
    int y;
    char label[32];
} Point;

/* Simple arithmetic — easy to verify decompilation */
int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

/* Function that calls other functions — tests call graph */
int compute(int a, int b) {
    int sum = add(a, b);
    int product = multiply(a, b);
    return sum + product;
}

/* String usage — tests string xrefs */
void print_banner(void) {
    printf("Banner: %s\n", BANNER);
    printf("Version: %s\n", VERSION);
}

/* Struct usage */
Point make_point(int x, int y, const char *label) {
    Point p;
    p.x = x;
    p.y = y;
    strncpy(p.label, label, sizeof(p.label) - 1);
    p.label[sizeof(p.label) - 1] = '\0';
    return p;
}

/* Loop + conditional — more complex control flow */
int sum_array(const int *arr, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (arr[i] > 0) {
            total += arr[i];
        }
    }
    return total;
}

/* Recursive function */
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main(int argc, char *argv[]) {
    print_banner();

    int result = compute(3, 4);
    printf("compute(3, 4) = %d\n", result);

    Point p = make_point(10, 20, "origin");
    printf("Point: (%d, %d) '%s'\n", p.x, p.y, p.label);

    int nums[] = {1, -2, 3, -4, 5};
    printf("sum_positive = %d\n", sum_array(nums, 5));

    printf("factorial(6) = %d\n", factorial(6));

    return 0;
}
