#include <stdint.h>
#include <stdio.h>

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline, used, noclone))
#else
#define NOINLINE
#endif

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

static NOINLINE uint32_t layout_family(uint32_t tag) {
    return avalanche32(tag ^ 0x4c41594fu) & 3u;
}

static NOINLINE uint32_t boundary_owner(uint32_t tag, uint32_t boundary) {
    uint32_t value;
    switch (layout_family(tag)) {
        case 0:
            value = xorshift32(tag ^ boundary * 0x9e3779b9u ^ 0x6d2b79f5u);
            break;
        case 1:
            value = avalanche32((tag + boundary * 0x85ebca6bu) ^ 0xb5297a4du) >> 11;
            break;
        case 2:
            value = xorshift32(
                rotl32(tag, boundary) ^ boundary * 0xc2b2ae35u ^ 0x27d4eb2fu
            ) >> 23;
            break;
        default:
            value = avalanche32(
                (tag ^ rotl32(boundary * 0x165667b1u, tag >> 27)) + 0xd3a2646cu
            ) >> 31;
            break;
    }
    return value & 1u;
}

static NOINLINE uint32_t padding(
    uint32_t capture,
    uint32_t tag,
    uint32_t record
) {
    static const uint32_t constants[2] = {0xa511e9b3u, 0xc0dec0deu};
    uint32_t value;
    switch (layout_family(tag)) {
        case 0:
            value = xorshift32(tag ^ constants[capture] ^ record * 0x85ebca6bu);
            break;
        case 1:
            value = avalanche32(
                (tag + capture * 0x9e3779b9u) ^ record * 0x27d4eb2fu ^ 0x68e31da4u
            );
            break;
        case 2:
            value = xorshift32(
                rotl32(tag ^ constants[capture], record * 7u + 3u)
                + record * 0x165667b1u
            ) >> 4;
            break;
        default:
            value = avalanche32(
                tag ^ (record + 1u) * 0x7f4a7c15u
                ^ (capture ? 0x94d049bbu : 0x369dea0fu)
            ) >> 19;
            break;
    }
    return value & 7u;
}

/* The recoverable model remains in the ELF, but there is no query CLI. */
static NOINLINE uint32_t layout_digest(
    uint32_t capture,
    uint32_t tag,
    uint32_t token_count
) {
    uint32_t state = 0x13579bdfu ^ tag ^ capture * 0x9e3779b9u;
    uint32_t start = 0, count = 0, record = 0;
    for (uint32_t index = 0; index < token_count; ++index) {
        ++count;
        uint32_t boundary = index + 1u;
        uint32_t cut = boundary == token_count || count == 3u;
        if (!cut && boundary_owner(tag, boundary) == capture) cut = 1u;
        if (cut) {
            uint32_t pad = padding(capture, tag, record);
            uint32_t word = start * 0x85ebca6bu ^ count * 0xc2b2ae35u
                            ^ pad * 0x27d4eb2fu ^ record * 0x165667b1u;
            state = avalanche32(state ^ word);
            start += count;
            count = 0;
            ++record;
        }
    }
    return avalanche32(state ^ token_count);
}

#if defined(TLF_ADMIN_HARNESS)
int main(void) {
    uint32_t capture, tag, token_count;
    if (scanf("%u %u %u", &capture, &tag, &token_count) != 3
        || capture > 1u || token_count == 0u || token_count > 64u) {
        return 2;
    }
    uint32_t start = 0, count = 0, record = 0;
    for (uint32_t index = 0; index < token_count; ++index) {
        ++count;
        uint32_t boundary = index + 1u;
        uint32_t cut = boundary == token_count || count == 3u;
        if (!cut && boundary_owner(tag, boundary) == capture) cut = 1u;
        if (cut) {
            printf("%u %u %u\n", start, count, padding(capture, tag, record));
            start += count;
            count = 0;
            ++record;
        }
    }
    return 0;
}
#else
static volatile uint32_t self_test_cases[][3] = {
    {0u, 0x12345678u, 12u},
    {1u, 0x12345678u, 12u},
    {0u, 0x9abcdef0u, 24u},
    {1u, 0x0badf00du, 7u},
    {0u, 0xd00dfeedu, 19u},
    {1u, 0x31415926u, 5u},
    {0u, 0x27182818u, 16u},
    {1u, 0x20000000u, 9u},
};

int main(void) {
    uint32_t aggregate = 0x6c61796fu;
    for (uint32_t index = 0; index < 8u; ++index) {
        uint32_t value = layout_digest(
            self_test_cases[index][0],
            self_test_cases[index][1],
            self_test_cases[index][2]
        );
        aggregate = avalanche32(aggregate ^ value ^ index * 0x9e3779b9u);
    }
    if (aggregate != 0x2548c889u) return 1;
    puts("layout model self-test: ok");
    return 0;
}
#endif
