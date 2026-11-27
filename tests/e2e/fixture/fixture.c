/*
 * Fixture program for the end-to-end tests.
 *
 * The tests look symbols up by NAME in the built binary, so this file can be
 * edited and rebuilt (./build.sh) without touching hard-coded addresses. What
 * the tests rely on:
 *
 *   g_blob   64 bytes of initialised data; main() takes the address of
 *            g_blob[2], helper() reads g_blob[5]
 *   g_pts    array of struct pt; helper() reads g_pts[1].y (offset 0x14)
 *   g_bss    uninitialised data
 *   sw       a dense switch (compiled to a jump table)
 *   helper   called three times by twice()
 *   twice    called once by main()
 *   mkbig    returns a 32-byte struct by value (hidden return pointer)
 *   a_function_with_a_rather_long_name_for_regex_tests
 */
#include <stdio.h>
#include <stdlib.h>

struct pt { int x; int y; char tag[8]; };
struct big { long a; long b; long c; long d; };

struct pt g_pts[4] = {{1, 2, "a"}, {3, 4, "b"}};
unsigned char g_blob[64] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
int g_bss[32];
const char g_text[] = "hello fixture string";

__attribute__((noinline)) int sw(int v) {
    switch (v) {
        case 0: return 11;
        case 1: return 27;
        case 2: return 33;
        case 3: return 41;
        case 4: return 58;
        case 5: return 63;
        case 6: return 79;
        case 7: return 85;
        default: return -1;
    }
}

__attribute__((noinline)) int helper(int a) { return a * 3 + g_pts[1].y + g_blob[5]; }

__attribute__((noinline)) int twice(int a) { return helper(a) + helper(a + 1) + helper(a + 2); }

__attribute__((noinline)) struct big mkbig(long v) {
    struct big r = {v, v + 1, v + 2, v + 3};
    return r;
}

__attribute__((noinline)) int a_function_with_a_rather_long_name_for_regex_tests(int v) { return v ^ 0x55; }

int main(int argc, char **argv) {
    int v = argc > 1 ? atoi(argv[1]) : 3;
    g_bss[3] = v;
    printf("%d %d %d %s %ld %d %s\n", sw(v), twice(v), g_bss[3], (char *)&g_blob[2], mkbig(v).c,
           a_function_with_a_rather_long_name_for_regex_tests(v), g_text);
    return 0;
}
