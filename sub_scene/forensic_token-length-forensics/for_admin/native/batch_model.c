#include <stdint.h>
#include <stdio.h>

#define FINGERPRINT_MODULUS 251u

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline, used, noclone))
#else
#define NOINLINE
#endif

static NOINLINE uint32_t rotl32(uint32_t value, uint32_t amount) {
    amount &= 31u;
    return amount == 0u ? value : (value << amount) | (value >> (32u - amount));
}

static NOINLINE uint32_t avalanche32(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static NOINLINE uint32_t fingerprint_family(
    uint32_t capture,
    uint32_t tag,
    uint32_t record
) {
    return avalanche32(
        tag ^ capture * 0x9e3779b9u ^ record * 0x85ebca6bu ^ 0x4650524eu
    ) & 3u;
}

static NOINLINE uint32_t update(uint32_t family, uint32_t state, uint8_t value) {
    if (family == 0u) return (state ^ value) * 0x01000193u;
    if (family == 1u) {
        return rotl32(state + value + 0x7f4a7c15u, 5u) ^ 0xa5a5a5a5u;
    }
    if (family == 2u) {
        state ^= value;
        for (uint32_t bit = 0; bit < 8u; ++bit) {
            uint32_t mask = 0u - (state & 1u);
            state = (state >> 1) ^ (0xedb88320u & mask);
        }
        return state;
    }
    state += (uint32_t)value + 0x9e3779b9u;
    state ^= state >> 16;
    state *= 0x21f0aaadu;
    return rotl32(state, 13u);
}

/* Recoverable from the stripped ELF, but intentionally not exposed as a CLI. */
static NOINLINE uint32_t batch_fingerprint(
    uint32_t capture,
    uint32_t tag,
    uint32_t record,
    uint32_t count,
    const char *const tokens[3]
) {
    static const uint32_t constants[2] = {0x243f6a88u, 0x85a308d3u};
    uint32_t family = fingerprint_family(capture, tag, record);
    uint32_t state;
    if (family == 0u) {
        state = 0x811c9dc5u ^ constants[capture] ^ tag ^ record * 0x9e3779b9u;
    } else if (family == 1u) {
        state = avalanche32(tag + constants[capture] + record * 0xc2b2ae35u);
    } else if (family == 2u) {
        state = 0xffffffffu ^ tag ^ rotl32(constants[capture], record);
    } else {
        state = (0x9e3779b9u + tag) ^ constants[capture] ^ record * 0x27d4eb2fu;
    }

    /* Singleton records leak scheduling state, never token contents. */
    if (count > 1u) {
        for (uint32_t token_index = 0; token_index < count; ++token_index) {
            if (token_index != 0u) state = update(family, state, 0xffu);
            const unsigned char *cursor = (const unsigned char *)tokens[token_index];
            while (*cursor != '\0') state = update(family, state, *cursor++);
        }
    }
    if (family == 1u) {
        state = avalanche32(state ^ count * 0x9e3779b9u);
    } else if (family == 2u) {
        state ^= state >> 16;
    } else if (family == 3u) {
        state = avalanche32(state + count * 0x85ebca6bu);
    }
    return state % FINGERPRINT_MODULUS;
}

typedef struct {
    volatile uint32_t capture;
    volatile uint32_t tag;
    volatile uint32_t record;
    volatile uint32_t count;
    const char *tokens[3];
} SelfTestCase;

#if defined(TLF_ADMIN_HARNESS)
int main(void) {
    uint32_t capture, tag, record, count;
    char storage[3][128] = {{0}};
    const char *tokens[3] = {storage[0], storage[1], storage[2]};
    if (scanf("%u %u %u %u", &capture, &tag, &record, &count) != 4
        || capture > 1u || count == 0u || count > 3u) {
        return 2;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (scanf("%127s", storage[index]) != 1) return 2;
    }
    printf("%u\n", batch_fingerprint(capture, tag, record, count, tokens));
    return 0;
}
#else
static SelfTestCase self_test_cases[] = {
    {0u, 0x12345678u, 0u, 2u, {"alpha", "beta", ""}},
    {1u, 0x12345678u, 1u, 3u, {"one", "two", "three"}},
    {0u, 0x9abcdef0u, 2u, 1u, {"solo", "", ""}},
    {1u, 0x0badf00du, 3u, 2u, {"archive", "audit", ""}},
    {0u, 0xd00dfeedu, 4u, 3u, {"red", "green", "blue"}},
    {1u, 0x31415926u, 5u, 1u, {"network", "", ""}},
    {0u, 0x27182818u, 6u, 2u, {"proof", "chain", ""}},
    {1u, 0x20000000u, 7u, 3u, {"cache", "state", "trace"}},
};

int main(void) {
    uint32_t aggregate = 0x6670726eu;
    for (uint32_t index = 0; index < 8u; ++index) {
        SelfTestCase *item = &self_test_cases[index];
        uint32_t value = batch_fingerprint(
            item->capture, item->tag, item->record, item->count, item->tokens
        );
        aggregate = avalanche32(aggregate ^ value ^ index * 0x9e3779b9u);
    }
    if (aggregate != 0x41f5af2bu) return 1;
    puts("fingerprint model self-test: ok");
    return 0;
}
#endif
