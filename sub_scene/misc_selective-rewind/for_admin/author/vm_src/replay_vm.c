#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_COUNT 512u
#define LINE_SIZE 64u
#define MEM_SIZE (LINE_COUNT * LINE_SIZE)
#define CACHE_LINES 32u
#define PROGRAM_HEADER_SIZE 32u
#define INSN_SIZE 16u
#define MAX_FILE_SIZE (32u * 1024u * 1024u)
#define FAULT_COUNT 5u

#define OP_MOVI 0x11u
#define OP_LOAD 0x27u
#define OP_STORE 0x39u
#define OP_ADD 0x44u
#define OP_SUB 0x4bu
#define OP_XOR 0x53u
#define OP_AND 0x5au
#define OP_OR 0x5fu
#define OP_ROL 0x61u
#define OP_ROR 0x68u
#define OP_HASHSTEP 0x72u
#define OP_FLUSH 0x80u
#define OP_BARRIER 0x91u
#define OP_CMP 0xa3u
#define OP_CMOV 0xabu
#define OP_JMP 0xb7u
#define OP_JNZ 0xc2u
#define OP_MEMCPY 0xd5u
#define OP_HALT 0xe7u
#define OP_NOP 0xf1u

#define GOLDEN UINT64_C(0x9e3779b97f4a7c15)
#define MULTIPLIER UINT64_C(0xd6e8feb86659fd93)

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t used;
} Sha256;

static uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(Sha256 *ctx, const uint8_t block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t words[64];
    for (size_t i = 0; i < 16; ++i) {
        words[i] = ((uint32_t)block[i * 4] << 24) |
                   ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) |
                   (uint32_t)block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(words[i - 15], 7) ^ rotr32(words[i - 15], 18) ^ (words[i - 15] >> 3);
        uint32_t s1 = rotr32(words[i - 2], 17) ^ rotr32(words[i - 2], 19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (size_t i = 0; i < 64; ++i) {
        uint32_t big1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + big1 + choose + constants[i] + words[i];
        uint32_t big0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = big0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(Sha256 *ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bit_count = 0;
    ctx->used = 0;
}

static void sha256_update(Sha256 *ctx, const uint8_t *data, size_t size) {
    ctx->bit_count += (uint64_t)size * 8u;
    while (size > 0) {
        size_t space = 64u - ctx->used;
        size_t take = size < space ? size : space;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        size -= take;
        if (ctx->used == 64u) {
            sha256_transform(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->bit_count;
    ctx->block[ctx->used++] = 0x80u;
    if (ctx->used > 56u) {
        memset(ctx->block + ctx->used, 0, 64u - ctx->used);
        sha256_transform(ctx, ctx->block);
        ctx->used = 0;
    }
    memset(ctx->block + ctx->used, 0, 56u - ctx->used);
    for (size_t i = 0; i < 8; ++i) {
        ctx->block[63u - i] = (uint8_t)(bits >> (8u * i));
    }
    sha256_transform(ctx, ctx->block);
    for (size_t i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)ctx->state[i];
    }
}

static void sha256_bytes(const uint8_t *data, size_t size, uint8_t out[32]) {
    Sha256 ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, size);
    sha256_final(&ctx, out);
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint8_t *read_file(const char *path, size_t *size_out) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "replay_vm: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long end = ftell(file);
    if (end < 0 || (unsigned long)end > MAX_FILE_SIZE || fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "replay_vm: invalid size for %s\n", path);
        fclose(file);
        return NULL;
    }
    size_t size = (size_t)end;
    uint8_t *data = malloc(size == 0 ? 1 : size);
    if (data == NULL || fread(data, 1, size, file) != size) {
        fprintf(stderr, "replay_vm: failed to read %s\n", path);
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *size_out = size;
    return data;
}

typedef struct {
    uint32_t checkpoint;
    uint16_t line;
} Fault;

typedef struct {
    const char *cursor;
    const char *end;
    const char *error;
} JsonParser;

static void json_ws(JsonParser *parser) {
    while (parser->cursor < parser->end && isspace((unsigned char)*parser->cursor)) {
        ++parser->cursor;
    }
}

static bool json_take(JsonParser *parser, char wanted) {
    json_ws(parser);
    if (parser->cursor >= parser->end || *parser->cursor != wanted) {
        parser->error = "unexpected JSON token";
        return false;
    }
    ++parser->cursor;
    return true;
}

static bool json_key(JsonParser *parser, char out[32]) {
    json_ws(parser);
    if (parser->cursor >= parser->end || *parser->cursor++ != '"') {
        parser->error = "object key must be a string";
        return false;
    }
    size_t used = 0;
    while (parser->cursor < parser->end && *parser->cursor != '"') {
        unsigned char ch = (unsigned char)*parser->cursor++;
        if (ch < 0x20u || ch == '\\' || used + 1 >= 32u) {
            parser->error = "escaped or oversized keys are rejected";
            return false;
        }
        out[used++] = (char)ch;
    }
    if (parser->cursor >= parser->end) {
        parser->error = "unterminated object key";
        return false;
    }
    ++parser->cursor;
    out[used] = '\0';
    return true;
}

static bool json_uint(JsonParser *parser, uint64_t maximum, uint64_t *out) {
    json_ws(parser);
    if (parser->cursor >= parser->end || !isdigit((unsigned char)*parser->cursor)) {
        parser->error = "expected a non-negative integer";
        return false;
    }
    if (*parser->cursor == '0' && parser->cursor + 1 < parser->end &&
        isdigit((unsigned char)parser->cursor[1])) {
        parser->error = "leading zero in integer";
        return false;
    }
    uint64_t value = 0;
    while (parser->cursor < parser->end && isdigit((unsigned char)*parser->cursor)) {
        unsigned digit = (unsigned)(*parser->cursor++ - '0');
        if (value > (maximum - digit) / 10u) {
            parser->error = "integer outside allowed range";
            return false;
        }
        value = value * 10u + digit;
    }
    *out = value;
    return true;
}

static bool parse_fault_object(JsonParser *parser, Fault *fault) {
    if (!json_take(parser, '{')) return false;
    bool seen_checkpoint = false, seen_line = false;
    for (unsigned fields = 0;; ++fields) {
        json_ws(parser);
        if (parser->cursor < parser->end && *parser->cursor == '}') {
            ++parser->cursor;
            break;
        }
        if (fields >= 2) {
            parser->error = "extra fault field";
            return false;
        }
        char key[32];
        uint64_t value;
        if (!json_key(parser, key) || !json_take(parser, ':')) return false;
        if (strcmp(key, "checkpoint") == 0) {
            if (seen_checkpoint || !json_uint(parser, UINT32_MAX, &value)) {
                parser->error = seen_checkpoint ? "duplicate checkpoint key" : parser->error;
                return false;
            }
            if (value == 0) {
                parser->error = "checkpoint zero is not executable";
                return false;
            }
            fault->checkpoint = (uint32_t)value;
            seen_checkpoint = true;
        } else if (strcmp(key, "line") == 0) {
            if (seen_line || !json_uint(parser, LINE_COUNT - 1u, &value)) {
                parser->error = seen_line ? "duplicate line key" : parser->error;
                return false;
            }
            fault->line = (uint16_t)value;
            seen_line = true;
        } else {
            parser->error = "unknown fault field";
            return false;
        }
        json_ws(parser);
        if (parser->cursor < parser->end && *parser->cursor == ',') {
            ++parser->cursor;
            json_ws(parser);
            if (parser->cursor >= parser->end || *parser->cursor == '}') {
                parser->error = "trailing comma in fault object";
                return false;
            }
            continue;
        }
        if (parser->cursor < parser->end && *parser->cursor == '}') {
            ++parser->cursor;
            break;
        }
        parser->error = "expected comma or object end";
        return false;
    }
    if (!seen_checkpoint || !seen_line) {
        parser->error = "fault requires checkpoint and line";
        return false;
    }
    return true;
}

static bool parse_fault_array(JsonParser *parser, Fault faults[FAULT_COUNT]) {
    if (!json_take(parser, '[')) return false;
    size_t count = 0;
    for (;;) {
        json_ws(parser);
        if (parser->cursor < parser->end && *parser->cursor == ']') {
            ++parser->cursor;
            break;
        }
        if (count >= FAULT_COUNT) {
            parser->error = "exactly five faults are required";
            return false;
        }
        if (!parse_fault_object(parser, &faults[count++])) return false;
        json_ws(parser);
        if (parser->cursor < parser->end && *parser->cursor == ',') {
            ++parser->cursor;
            json_ws(parser);
            if (parser->cursor >= parser->end || *parser->cursor == ']') {
                parser->error = "trailing comma in faults array";
                return false;
            }
            continue;
        }
        if (parser->cursor < parser->end && *parser->cursor == ']') {
            ++parser->cursor;
            break;
        }
        parser->error = "expected comma or array end";
        return false;
    }
    if (count != FAULT_COUNT) {
        parser->error = "exactly five faults are required";
        return false;
    }
    return true;
}

static bool parse_plan(const uint8_t *data, size_t size, Fault faults[FAULT_COUNT]) {
    JsonParser parser = {(const char *)data, (const char *)data + size, NULL};
    if (!json_take(&parser, '{')) goto failure;
    bool seen_version = false, seen_faults = false;
    for (unsigned fields = 0;; ++fields) {
        json_ws(&parser);
        if (parser.cursor < parser.end && *parser.cursor == '}') {
            ++parser.cursor;
            break;
        }
        if (fields >= 2) {
            parser.error = "extra root field";
            goto failure;
        }
        char key[32];
        if (!json_key(&parser, key) || !json_take(&parser, ':')) goto failure;
        if (strcmp(key, "version") == 0) {
            uint64_t version;
            if (seen_version || !json_uint(&parser, UINT32_MAX, &version)) {
                parser.error = seen_version ? "duplicate version key" : parser.error;
                goto failure;
            }
            if (version != 3) {
                parser.error = "unsupported plan version";
                goto failure;
            }
            seen_version = true;
        } else if (strcmp(key, "faults") == 0) {
            if (seen_faults || !parse_fault_array(&parser, faults)) {
                parser.error = seen_faults ? "duplicate faults key" : parser.error;
                goto failure;
            }
            seen_faults = true;
        } else {
            parser.error = "unknown root field";
            goto failure;
        }
        json_ws(&parser);
        if (parser.cursor < parser.end && *parser.cursor == ',') {
            ++parser.cursor;
            json_ws(&parser);
            if (parser.cursor >= parser.end || *parser.cursor == '}') {
                parser.error = "trailing comma in root object";
                goto failure;
            }
            continue;
        }
        if (parser.cursor < parser.end && *parser.cursor == '}') {
            ++parser.cursor;
            break;
        }
        parser.error = "expected comma or root object end";
        goto failure;
    }
    json_ws(&parser);
    if (parser.cursor != parser.end || !seen_version || !seen_faults) {
        parser.error = "incomplete plan or trailing data";
        goto failure;
    }
    for (size_t i = 1; i < FAULT_COUNT; ++i) {
        if (faults[i - 1].checkpoint >= faults[i].checkpoint) {
            fprintf(stderr, "replay_vm: checkpoints must be strictly increasing\n");
            return false;
        }
    }
    return true;

failure:
    fprintf(stderr, "replay_vm: invalid plan.json: %s\n",
            parser.error == NULL ? "parse failure" : parser.error);
    return false;
}

typedef struct {
    uint8_t data[LINE_SIZE];
    uint16_t line;
    bool valid;
    bool dirty;
    uint64_t stamp;
} CacheEntry;

typedef struct {
    uint8_t dram[MEM_SIZE];
    CacheEntry cache[CACHE_LINES];
    uint64_t regs[16];
    uint64_t clock;
    uint32_t pc;
    uint32_t checkpoint;
    uint32_t steps;
    uint32_t max_steps;
    uint32_t instruction_count;
    const uint8_t *code;
    bool zero;
    bool carry;
    bool negative;
    bool halted;
    uint32_t result_addr;
    unsigned faults_consumed;
} VM;

static CacheEntry *cache_find(VM *vm, uint16_t line) {
    for (size_t i = 0; i < CACHE_LINES; ++i) {
        if (vm->cache[i].valid && vm->cache[i].line == line) return &vm->cache[i];
    }
    return NULL;
}

static void cache_writeback(VM *vm, CacheEntry *entry) {
    if (entry->valid && entry->dirty) {
        memcpy(vm->dram + (size_t)entry->line * LINE_SIZE, entry->data, LINE_SIZE);
        entry->dirty = false;
    }
}

static CacheEntry *cache_get(VM *vm, uint16_t line) {
    ++vm->clock;
    CacheEntry *entry = cache_find(vm, line);
    if (entry != NULL) {
        entry->stamp = vm->clock;
        return entry;
    }
    CacheEntry *victim = NULL;
    for (size_t i = 0; i < CACHE_LINES; ++i) {
        if (!vm->cache[i].valid) {
            victim = &vm->cache[i];
            break;
        }
        if (victim == NULL || vm->cache[i].stamp < victim->stamp) victim = &vm->cache[i];
    }
    if (victim == NULL) return NULL;
    cache_writeback(vm, victim);
    memcpy(victim->data, vm->dram + (size_t)line * LINE_SIZE, LINE_SIZE);
    victim->line = line;
    victim->valid = true;
    victim->dirty = false;
    victim->stamp = vm->clock;
    return victim;
}

static bool address_ok(uint32_t addr, uint32_t width) {
    return width > 0 && addr < MEM_SIZE && width <= MEM_SIZE - addr;
}

static bool memory_read(VM *vm, uint32_t addr, unsigned width, uint64_t *out) {
    if (!address_ok(addr, width) || width > 8u) return false;
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) {
        uint32_t current = addr + i;
        CacheEntry *entry = cache_get(vm, (uint16_t)(current / LINE_SIZE));
        if (entry == NULL) return false;
        value |= (uint64_t)entry->data[current % LINE_SIZE] << (8u * i);
    }
    *out = value;
    return true;
}

static bool memory_write(VM *vm, uint32_t addr, uint64_t value, unsigned width) {
    if (!address_ok(addr, width) || width > 8u) return false;
    for (unsigned i = 0; i < width; ++i) {
        uint32_t current = addr + i;
        CacheEntry *entry = cache_get(vm, (uint16_t)(current / LINE_SIZE));
        if (entry == NULL) return false;
        entry->data[current % LINE_SIZE] = (uint8_t)(value >> (8u * i));
        entry->dirty = true;
    }
    return true;
}

static void flush_line(VM *vm, uint16_t line) {
    CacheEntry *entry = cache_find(vm, line);
    if (entry != NULL) cache_writeback(vm, entry);
}

static void apply_fault(VM *vm, uint16_t line) {
    CacheEntry *entry = cache_find(vm, line);
    if (entry != NULL && entry->dirty) {
        entry->valid = false;
        entry->dirty = false;
    }
}

static uint64_t rol64(uint64_t value, unsigned amount) {
    amount &= 63u;
    return amount == 0 ? value : (value << amount) | (value >> (64u - amount));
}

static uint64_t ror64(uint64_t value, unsigned amount) {
    amount &= 63u;
    return amount == 0 ? value : (value >> amount) | (value << (64u - amount));
}

static uint64_t hash_step(uint64_t state, uint64_t value, uint64_t constant, unsigned rotation) {
    uint64_t mixed = state + (value ^ constant) + GOLDEN;
    uint64_t right = value + constant * MULTIPLIER;
    return rol64(mixed, rotation) ^ right;
}

static unsigned access_width(uint8_t flags) {
    unsigned width = flags & 0x0fu;
    return width == 1u || width == 2u || width == 4u || width == 8u ? width : 0u;
}

static bool execute(VM *vm, const uint8_t *insn, uint32_t *next_pc, bool *request_halt) {
    uint8_t op = insn[0], flags = insn[1], dst = insn[2] & 15u, src = insn[3] & 15u;
    uint32_t imm = load32(insn + 4), addr = load32(insn + 8), aux = load32(insn + 12);
    uint64_t left, right, value;
    *next_pc = vm->pc + 1u;
    *request_halt = false;
    switch (op) {
        case OP_MOVI:
            vm->regs[dst] = (uint64_t)imm | ((uint64_t)aux << 32);
            break;
        case OP_LOAD: {
            unsigned width = access_width(flags);
            if (width == 0 || !memory_read(vm, addr, width, &vm->regs[dst])) return false;
            break;
        }
        case OP_STORE: {
            unsigned width = access_width(flags);
            if (width == 0 || !memory_write(vm, addr, vm->regs[src], width)) return false;
            break;
        }
        case OP_ADD:
            left = vm->regs[dst];
            right = vm->regs[src];
            value = left + right;
            vm->carry = value < left;
            vm->regs[dst] = value;
            vm->zero = value == 0;
            vm->negative = (value >> 63) != 0;
            break;
        case OP_SUB:
            left = vm->regs[dst];
            right = vm->regs[src];
            value = left - right;
            vm->carry = left >= right;
            vm->regs[dst] = value;
            vm->zero = value == 0;
            vm->negative = (value >> 63) != 0;
            break;
        case OP_XOR:
            vm->regs[dst] ^= vm->regs[src];
            vm->zero = vm->regs[dst] == 0;
            vm->negative = (vm->regs[dst] >> 63) != 0;
            break;
        case OP_AND:
            vm->regs[dst] &= vm->regs[src];
            vm->zero = vm->regs[dst] == 0;
            vm->negative = (vm->regs[dst] >> 63) != 0;
            break;
        case OP_OR:
            vm->regs[dst] |= vm->regs[src];
            vm->zero = vm->regs[dst] == 0;
            vm->negative = (vm->regs[dst] >> 63) != 0;
            break;
        case OP_ROL:
            vm->regs[dst] = rol64(vm->regs[dst], imm);
            break;
        case OP_ROR:
            vm->regs[dst] = ror64(vm->regs[dst], imm);
            break;
        case OP_HASHSTEP: {
            uint64_t old;
            uint64_t constant = (uint64_t)imm | ((uint64_t)aux << 32);
            if (!memory_read(vm, addr, 8, &old)) return false;
            value = hash_step(old, vm->regs[src], constant, flags & 63u);
            if (!memory_write(vm, addr, value, 8)) return false;
            break;
        }
        case OP_FLUSH:
            if (!address_ok(addr, 1)) return false;
            flush_line(vm, (uint16_t)(addr / LINE_SIZE));
            break;
        case OP_BARRIER:
            for (size_t i = 0; i < CACHE_LINES; ++i) {
                CacheEntry *entry = &vm->cache[i];
                if (entry->valid && entry->dirty && ((uint32_t)entry->line & imm) == aux) {
                    cache_writeback(vm, entry);
                }
            }
            break;
        case OP_CMP:
            left = vm->regs[dst];
            right = vm->regs[src];
            value = left - right;
            vm->zero = value == 0;
            vm->carry = left >= right;
            vm->negative = (value >> 63) != 0;
            break;
        case OP_CMOV:
            if ((flags & 1u) ? !vm->zero : vm->zero) vm->regs[dst] = vm->regs[src];
            break;
        case OP_JMP:
            *next_pc = imm;
            break;
        case OP_JNZ:
            if (!vm->zero) *next_pc = imm;
            break;
        case OP_MEMCPY: {
            if (!address_ok(imm, aux) || !address_ok(addr, aux)) return false;
            uint8_t *temporary = malloc(aux == 0 ? 1u : aux);
            if (temporary == NULL) return false;
            for (uint32_t i = 0; i < aux; ++i) {
                uint64_t byte;
                if (!memory_read(vm, imm + i, 1, &byte)) {
                    free(temporary);
                    return false;
                }
                temporary[i] = (uint8_t)byte;
            }
            for (uint32_t i = 0; i < aux; ++i) {
                if (!memory_write(vm, addr + i, temporary[i], 1)) {
                    free(temporary);
                    return false;
                }
            }
            free(temporary);
            break;
        }
        case OP_HALT:
            if (!address_ok(addr, 56)) return false;
            vm->result_addr = addr;
            *request_halt = true;
            break;
        case OP_NOP:
            break;
        default:
            fprintf(stderr, "replay_vm: unknown opcode 0x%02x at pc %u\n", op, vm->pc);
            return false;
    }
    return true;
}

static bool run_vm(VM *vm, const Fault faults[FAULT_COUNT]) {
    size_t fault_index = 0;
    while (!vm->halted && vm->steps < vm->max_steps) {
        if (vm->pc >= vm->instruction_count) {
            fprintf(stderr, "replay_vm: program counter outside program\n");
            return false;
        }
        const uint8_t *insn = vm->code + (size_t)vm->pc * INSN_SIZE;
        uint32_t next_pc;
        bool request_halt;
        if (!execute(vm, insn, &next_pc, &request_halt)) {
            fprintf(stderr, "replay_vm: execution error at pc %u\n", vm->pc);
            return false;
        }
        ++vm->steps;
        ++vm->checkpoint;
        while (fault_index < FAULT_COUNT && faults[fault_index].checkpoint == vm->checkpoint) {
            apply_fault(vm, faults[fault_index].line);
            ++vm->faults_consumed;
            ++fault_index;
        }
        vm->pc = next_pc;
        if (request_halt) vm->halted = true;
    }
    return true;
}

static void logical_snapshot(const VM *vm, uint8_t snapshot[MEM_SIZE]) {
    memcpy(snapshot, vm->dram, MEM_SIZE);
    for (size_t i = 0; i < CACHE_LINES; ++i) {
        const CacheEntry *entry = &vm->cache[i];
        if (entry->valid) {
            memcpy(snapshot + (size_t)entry->line * LINE_SIZE, entry->data, LINE_SIZE);
        }
    }
}

static bool write_outputs(VM *vm) {
    uint64_t fields[7] = {0, 0, 0, 0, 0, 0, 1};
    if (vm->halted) {
        for (size_t i = 0; i < 7; ++i) {
            if (!memory_read(vm, vm->result_addr + (uint32_t)i * 8u, 8, &fields[i])) return false;
        }
    }
    bool audit_valid = fields[5] == fields[6];
    bool success = vm->halted && fields[0] == 1u && fields[1] == 0u &&
                   fields[2] == 7u && fields[3] == 0u && fields[4] == 1u &&
                   audit_valid && vm->faults_consumed == FAULT_COUNT;
    FILE *result = fopen("result.json", "w");
    if (result == NULL) return false;
    /*
     * A valid but incorrect plan must not become a differential oracle.  In
     * particular, do not expose policy fields, cache state, or a memory hash:
     * every wrong five-fault replay has exactly the same observable receipt.
     */
    if (!success) {
        bool wrote = fputs("{\"success\":false}\n", result) >= 0;
        if (fclose(result) != 0) wrote = false;
        (void)remove("final_state.digest");
        return wrote;
    }
    bool wrote = fputs("{\"success\":true}\n", result) >= 0;
    if (fclose(result) != 0) wrote = false;
    if (!wrote) return false;

    uint8_t *snapshot = malloc(MEM_SIZE);
    if (snapshot == NULL) return false;
    logical_snapshot(vm, snapshot);
    uint8_t digest[32];
    sha256_bytes(snapshot, MEM_SIZE, digest);
    free(snapshot);
    FILE *digest_file = fopen("final_state.digest", "w");
    if (digest_file == NULL) return false;
    for (size_t i = 0; i < sizeof(digest); ++i) fprintf(digest_file, "%02x", digest[i]);
    fputc('\n', digest_file);
    fclose(digest_file);
    return true;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: ./replay_vm  (no arguments; reads the current directory)\n");
        return 2;
    }
    /* Never leave a stale successful receipt behind after a rejected replay. */
    (void)remove("result.json");
    (void)remove("final_state.digest");
    size_t plan_size, image_size, program_size;
    uint8_t *plan_data = read_file("plan.json", &plan_size);
    uint8_t *image_data = read_file("initial_state.bin", &image_size);
    uint8_t *program_data = read_file("program.bin", &program_size);
    if (plan_data == NULL || image_data == NULL || program_data == NULL) {
        free(plan_data);
        free(image_data);
        free(program_data);
        return 2;
    }
    Fault faults[FAULT_COUNT] = {{0, 0}};
    if (!parse_plan(plan_data, plan_size, faults)) {
        free(plan_data);
        free(image_data);
        free(program_data);
        return 2;
    }
    free(plan_data);

    const size_t expected_image = 24u + MEM_SIZE + 32u;
    uint8_t digest[32];
    if (image_size != expected_image || memcmp(image_data, "REWIND01", 8) != 0 ||
        load32(image_data + 8) != LINE_COUNT || load32(image_data + 12) != LINE_SIZE) {
        fprintf(stderr, "replay_vm: invalid initial_state.bin header\n");
        free(image_data);
        free(program_data);
        return 2;
    }
    sha256_bytes(image_data, image_size - 32u, digest);
    if (memcmp(digest, image_data + image_size - 32u, 32) != 0) {
        fprintf(stderr, "replay_vm: initial_state.bin checksum mismatch\n");
        free(image_data);
        free(program_data);
        return 2;
    }

    if (program_size < PROGRAM_HEADER_SIZE + 32u || memcmp(program_data, "SRWPROG1", 8) != 0 ||
        load32(program_data + 8) != 1u) {
        fprintf(stderr, "replay_vm: invalid program.bin header\n");
        free(image_data);
        free(program_data);
        return 2;
    }
    uint32_t instruction_count = load32(program_data + 12);
    uint32_t entry = load32(program_data + 16);
    uint32_t max_steps = load32(program_data + 20);
    size_t expected_program = PROGRAM_HEADER_SIZE + (size_t)instruction_count * INSN_SIZE + 32u;
    if (instruction_count == 0 || instruction_count > 1000000u || entry >= instruction_count ||
        max_steps == 0 || max_steps > 1000000u || program_size != expected_program) {
        fprintf(stderr, "replay_vm: invalid program.bin dimensions\n");
        free(image_data);
        free(program_data);
        return 2;
    }
    sha256_bytes(program_data, program_size - 32u, digest);
    if (memcmp(digest, program_data + program_size - 32u, 32) != 0) {
        fprintf(stderr, "replay_vm: program.bin checksum mismatch\n");
        free(image_data);
        free(program_data);
        return 2;
    }

    VM vm;
    memset(&vm, 0, sizeof(vm));
    memcpy(vm.dram, image_data + 24u, MEM_SIZE);
    vm.pc = entry;
    vm.max_steps = max_steps;
    vm.instruction_count = instruction_count;
    vm.code = program_data + PROGRAM_HEADER_SIZE;
    bool ok = run_vm(&vm, faults) && write_outputs(&vm);
    free(image_data);
    free(program_data);
    if (!ok) {
        fprintf(stderr, "replay_vm: execution or output failure\n");
        return 2;
    }
    return 0;
}
