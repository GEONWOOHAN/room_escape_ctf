#include <stdint.h>
#include <stdio.h>

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline, used, noclone))
#else
#define NOINLINE
#endif

static const uint32_t constants[4] = {
    0x6d2b79f5u, 0xa511e9b3u, 0x9e3779b9u, 0xc0dec0deu
};

static NOINLINE uint32_t rotl32(uint32_t value, uint32_t amount) {
    amount &= 31u;
    return amount == 0u ? value : (value << amount) | (value >> (32u - amount));
}

static NOINLINE uint32_t xorshift32(uint32_t value) {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value;
}

static NOINLINE uint32_t avalanche32(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static NOINLINE uint32_t layout_state(uint32_t counter, uint32_t seed, uint32_t style) {
    uint32_t family = (style + ((counter >> 4) & 3u)) & 3u;
    uint32_t model_seed = seed >> 5;
    uint32_t state;
    if (family == 0u) {
        state = xorshift32(model_seed ^ counter * 0x9e3779b9u ^ constants[style]);
    } else if (family == 1u) {
        state = avalanche32(
            (model_seed + counter * 0x85ebca6bu) ^ constants[style] ^ 0xb5297a4du
        );
    } else if (family == 2u) {
        state = xorshift32(
            rotl32(model_seed ^ constants[style], counter)
            + counter * 0xc2b2ae35u + 0x27d4eb2fu
        );
    } else {
        state = avalanche32(
            rotl32(model_seed + constants[style], counter >> 3)
            ^ counter * 0x165667b1u ^ 0xd3a2646cu
        );
    }
    return (state ^ seed) & 31u;
}

#if defined(VAULT_ADMIN_HARNESS)
int main(void) {
    uint32_t counter, seed, style;
    if (scanf("%u %u %u", &counter, &seed, &style) != 3 || style >= 4u) return 2;
    uint32_t state = layout_state(counter, seed, style);
    printf("%u %u\n", state & 3u, (state >> 2) & 7u);
    return 0;
}
#else
static volatile uint32_t self_test_cases[][3] = {
    {0u, 0u, 0u},
    {16u, 18841u, 0u},
    {32u, 424242u, 0u},
    {48u, 0xdeadbeefu, 0u},
    {37u, 18841u, 2u},
    {999u, 424242u, 3u},
    {127u, 0x12345678u, 1u},
    {4096u, 0xcafebabeu, 3u},
};

int main(void) {
    uint32_t aggregate = 0x6c61796fu;
    for (uint32_t index = 0; index < 8u; ++index) {
        uint32_t value = layout_state(
            self_test_cases[index][0],
            self_test_cases[index][1],
            self_test_cases[index][2]
        );
        aggregate = avalanche32(aggregate ^ value ^ index * 0x9e3779b9u);
    }
    if (aggregate != 0xea4c55e1u) return 1;
    puts("layout model self-test: ok");
    return 0;
}
#endif
