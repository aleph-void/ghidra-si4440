/* Ghidra-Rare test program for the Si4440 8051 variant: small, deliberately varied code (switch tables, bit variables,
 * indirect calls, 32-bit arithmetic, BCD, an interrupt handler, strings).  Written for this test suite; public domain. */
#include <stdint.h>

__sfr __at (0x80) P0;
__bit flag;
__data uint8_t tick;
__xdata uint8_t table[32];
__xdata uint32_t acc32;

void timer0_isr(void) __interrupt(1) { tick++; flag = !flag; }

uint8_t crc8(const uint8_t *p, uint8_t n) {
    uint8_t crc = 0xff, i;
    while (n--) {
        crc ^= *p++;
        for (i = 0; i < 8; i++) crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
    }
    return crc;
}

uint8_t to_bcd(uint8_t v) { return (uint8_t)(((v / 10) << 4) | (v % 10)); }

uint16_t isqrt(uint32_t x) {
    uint32_t r = 0, bit = 1UL << 30;
    while (bit > x) bit >>= 2;
    while (bit) {
        if (x >= r + bit) { x -= r + bit; r = (r >> 1) + bit; } else r >>= 1;
        bit >>= 2;
    }
    return (uint16_t)r;
}

uint8_t classify(uint8_t c) {
    switch (c) {
    case 'a': return 1;  case 'b': return 7;  case 'c': return 3;  case 'd': return 9;
    case 'e': return 4;  case 'f': return 12; case 'g': return 2;  case 'h': return 5;
    case 0:   return 0xff;
    default:  return c > 'z' ? 0x80 : 0;
    }
}

typedef uint8_t (*op_t)(uint8_t, uint8_t) __reentrant;
static uint8_t op_add(uint8_t a, uint8_t b) __reentrant { return a + b; }
static uint8_t op_sub(uint8_t a, uint8_t b) __reentrant { return a - b; }
static uint8_t op_xor(uint8_t a, uint8_t b) __reentrant { return a ^ b; }
static const op_t ops[3] = { op_add, op_sub, op_xor };
uint8_t apply(uint8_t k, uint8_t a, uint8_t b) { return k < 3 ? ops[k](a, b) : 0; }

uint8_t fact(uint8_t n) { return n < 2 ? 1 : (uint8_t)(n * fact(n - 1)); }

void sort(uint8_t *a, uint8_t n) {
    uint8_t i, j, t;
    for (i = 1; i < n; i++) {
        t = a[i];
        for (j = i; j && a[j - 1] > t; j--) a[j] = a[j - 1];
        a[j] = t;
    }
}

uint8_t strlen8(const char *s) { uint8_t n = 0; while (*s++) n++; return n; }

void main(void) {
    uint8_t i;
    for (i = 0; i < 32; i++) table[i] = (uint8_t)(i * 37u);
    sort(table, 32);
    acc32 = isqrt(1000000UL) + crc8(table, 32) + to_bcd(table[3]) + classify(table[5]) + apply(table[1] & 3, 5, 9) +
            fact(5) + strlen8("hello");
    P0 = (uint8_t)acc32;
    for (;;) { if (flag) P0 ^= 1; }
}
