#include <stdint.h>
#include <stdio.h>

static uint32_t xorshift32(uint32_t value) {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value;
}

int main(void) {
    uint32_t counter, seed, style;
#ifdef EASY_VARIANT
    static const uint32_t constants[4] = {0x13579BDFu, 0x2468ACE0u, 0xA5A5A5A5u, 0xC001D00Du};
#else
    static const uint32_t constants[4] = {0x7F4A7C15u, 0x91E10DA5u, 0xD192ED03u, 0x6C8E9CF5u};
#endif
    if (scanf("%u %u %u", &counter, &seed, &style) != 3 || style >= 4) {
        return 1;
    }
    printf("template=%u\n", xorshift32(seed ^ counter ^ constants[style]) & 7u);
    return 0;
}
