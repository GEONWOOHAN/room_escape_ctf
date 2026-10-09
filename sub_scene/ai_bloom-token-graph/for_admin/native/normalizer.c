#include <stdint.h>
#include "tokenizer_data.h"

#define EXPORT(name) __attribute__((export_name(name)))

static int hex_value(uint8_t value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int allowed(uint8_t value) {
    return (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') ||
           value == '{' || value == '}' || value == '_' || value == ':';
}

static uint32_t normalize(const uint8_t *input, uint32_t length, uint8_t *output) {
    uint32_t source = 0;
    uint32_t used = 0;
    int pending_space = 0;
    while (source < length) {
        uint8_t value = input[source++];
        if (value == '%' && source + 1 < length) {
            int high = hex_value(input[source]);
            int low = hex_value(input[source + 1]);
            if (high >= 0 && low >= 0) {
                value = (uint8_t)((high << 4) | low);
                source += 2;
            }
        }
        if (value >= 'A' && value <= 'Z') value = (uint8_t)(value + 0x20);
        if (allowed(value)) {
            if (pending_space && used) output[used++] = ' ';
            output[used++] = value;
            pending_space = 0;
        } else {
            pending_space = 1;
        }
    }
    return used;
}

static int matches(const uint8_t *input, uint32_t remaining, uint32_t token_id) {
    uint32_t length = VOCAB_LENGTHS[token_id];
    if (length > remaining) return 0;
    for (uint32_t index = 0; index < length; ++index) {
        if (input[index] != (uint8_t)VOCAB[token_id][index]) return 0;
    }
    return 1;
}

EXPORT("tokenize")
uint32_t tokenize(const uint8_t *input, uint32_t length, uint16_t *output, uint32_t capacity) {
    uint8_t normalized[768];
    if (length > 512) return 0xffffffffu;
    uint32_t normalized_length = normalize(input, length, normalized);
    uint32_t cursor = 0;
    uint32_t count = 0;
    while (cursor < normalized_length) {
        if (normalized[cursor] == ' ') {
            ++cursor;
            continue;
        }
        uint32_t part_end = cursor;
        while (part_end < normalized_length && normalized[part_end] != ' ') ++part_end;
        while (cursor < part_end) {
            uint32_t best = 0;
            uint32_t best_length = 0;
            for (uint32_t token_id = 1; token_id < VOCAB_COUNT; ++token_id) {
                uint32_t token_length = VOCAB_LENGTHS[token_id];
                if (token_length > best_length && matches(normalized + cursor, part_end - cursor, token_id)) {
                    best = token_id;
                    best_length = token_length;
                }
            }
            if (count >= capacity) return 0xfffffffeu;
            output[count++] = (uint16_t)best;
            cursor += best_length ? best_length : 1;
        }
    }
    return count;
}

EXPORT("normalizer_version")
uint32_t normalizer_version(void) {
    return 3;
}
