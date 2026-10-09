#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GADGET_COUNT 360u
#define CHAIN_LENGTH 28u
#define VECTOR_COUNT 8u
#define PATCH_RECORD_COUNT 14u
#define ABS_WRITE_COUNT 2u
#define HEAP_WRITE_COUNT 12u
#define INPUT_ADDR 0x00600120u
#define FN_TABLE_ADDR 0x00600800u
#define HEAP_BASE 0x10000000u
#define RESULT_ADDR 0x10010000u
#define ROUTE_STATE0_ADDR 0x10010024u
#define ROUTE_STATE1_ADDR 0x10010028u
#define START_PTR_ADDR 0x10000020u
#define ARG_BIAS_ADDR 0x10000024u
#define ROUTE_TARGET_ADDR 0x10000030u
#define COOKIE 0xC3D2E1F0u
#define START_TOKEN 0x91C4A72Eu
#define RETURN_SENTINEL 0xFFFFFFF0u

static const uint8_t PROBLEM_ID[] = "no-stack-still-turing-v4";
static const uint8_t RECEIPT_DOMAIN[] = "no-stack-still-turing-receipt-v4\0";
static const uint8_t FLEET_DOMAIN[] = "no-stack-still-turing-vector-fleet-v4\0";

typedef struct {
    uint32_t base;
    size_t size;
    uint8_t *data;
    int writable;
} Region;

typedef struct {
    Region regions[8];
    size_t count;
} Memory;

static uint16_t load16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint32_t rol32(uint32_t value, unsigned count) {
    count &= 31u;
    return count == 0u ? value : (value << count) | (value >> (32u - count));
}

static uint32_t ror32(uint32_t value, unsigned count) {
    count &= 31u;
    return count == 0u ? value : (value >> count) | (value << (32u - count));
}

static int read_file(const char *path, uint8_t **data, size_t *size, size_t maximum) {
    FILE *stream = fopen(path, "rb");
    if (stream == NULL) return -1;
    if (fseek(stream, 0, SEEK_END) != 0) { fclose(stream); return -1; }
    long length = ftell(stream);
    if (length < 0 || (size_t)length > maximum || fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream); return -1;
    }
    uint8_t *buffer = malloc((size_t)length + 1u);
    if (buffer == NULL) { fclose(stream); return -1; }
    if ((size_t)length != 0u && fread(buffer, 1, (size_t)length, stream) != (size_t)length) {
        free(buffer); fclose(stream); return -1;
    }
    if (fclose(stream) != 0) { free(buffer); return -1; }
    *data = buffer;
    *size = (size_t)length;
    return 0;
}

static void memory_free(Memory *memory) {
    for (size_t i = 0; i < memory->count; ++i) free(memory->regions[i].data);
    memset(memory, 0, sizeof(*memory));
}

static int memory_map(Memory *memory, uint32_t base, const uint8_t *source,
                      size_t file_size, size_t memory_size, int writable) {
    if (memory->count >= sizeof(memory->regions) / sizeof(memory->regions[0]) ||
        file_size > memory_size || memory_size == 0u) return -1;
    uint64_t end = (uint64_t)base + memory_size;
    if (end > 0x100000000ULL) return -1;
    for (size_t i = 0; i < memory->count; ++i) {
        uint64_t other_end = (uint64_t)memory->regions[i].base + memory->regions[i].size;
        if ((uint64_t)base < other_end && (uint64_t)memory->regions[i].base < end) return -1;
    }
    uint8_t *data = calloc(1, memory_size);
    if (data == NULL) return -1;
    if (file_size != 0u) memcpy(data, source, file_size);
    memory->regions[memory->count++] = (Region){base, memory_size, data, writable};
    return 0;
}

static Region *memory_find(Memory *memory, uint32_t address, size_t size, int write) {
    uint64_t end = (uint64_t)address + size;
    for (size_t i = 0; i < memory->count; ++i) {
        Region *region = &memory->regions[i];
        if ((uint64_t)region->base <= address && end <= (uint64_t)region->base + region->size &&
            (!write || region->writable)) return region;
    }
    return NULL;
}

static int memory_read(Memory *memory, uint32_t address, void *output, size_t size) {
    Region *region = memory_find(memory, address, size, 0);
    if (region == NULL) return -1;
    memcpy(output, region->data + (address - region->base), size);
    return 0;
}

static int memory_write(Memory *memory, uint32_t address, const void *input, size_t size) {
    Region *region = memory_find(memory, address, size, 1);
    if (region == NULL) return -1;
    memcpy(region->data + (address - region->base), input, size);
    return 0;
}

static int memory_u16(Memory *memory, uint32_t address, uint16_t *value) {
    uint8_t raw[2];
    if (memory_read(memory, address, raw, sizeof(raw)) != 0) return -1;
    *value = load16(raw); return 0;
}

static int memory_u32(Memory *memory, uint32_t address, uint32_t *value) {
    uint8_t raw[4];
    if (memory_read(memory, address, raw, sizeof(raw)) != 0) return -1;
    *value = load32(raw); return 0;
}

static int memory_w8(Memory *memory, uint32_t address, uint8_t value) {
    return memory_write(memory, address, &value, 1);
}

static int memory_w16(Memory *memory, uint32_t address, uint16_t value) {
    uint8_t raw[2] = {(uint8_t)value, (uint8_t)(value >> 8)};
    return memory_write(memory, address, raw, sizeof(raw));
}

static int memory_w32(Memory *memory, uint32_t address, uint32_t value) {
    uint8_t raw[4]; store32(raw, value);
    return memory_write(memory, address, raw, sizeof(raw));
}

static int load_elf(Memory *memory, const uint8_t *raw, size_t size) {
    if (size < 52u || memcmp(raw, "\x7f" "ELF\x01\x01\x01", 7) != 0) return -1;
    uint32_t phoff = load32(raw + 28);
    uint16_t phentsize = load16(raw + 42), phnum = load16(raw + 44);
    if (phentsize < 32u || (uint64_t)phoff + (uint64_t)phentsize * phnum > size) return -1;
    for (uint16_t index = 0; index < phnum; ++index) {
        const uint8_t *header = raw + phoff + (size_t)index * phentsize;
        if (load32(header) != 1u) continue;
        uint32_t offset = load32(header + 4), address = load32(header + 8);
        uint32_t file_size = load32(header + 16), memory_size = load32(header + 20);
        uint32_t flags = load32(header + 24);
        if ((uint64_t)offset + file_size > size ||
            memory_map(memory, address, raw + offset, file_size, memory_size, (flags & 2u) != 0u) != 0) return -1;
    }
    return memory->count == 0u ? -1 : 0;
}

static int run_function(Memory *memory, uint32_t entry, uint32_t state_address,
                        uint32_t argument_address) {
    uint32_t registers[32] = {0};
    registers[4] = argument_address;
    registers[16] = state_address;
    registers[31] = RETURN_SENTINEL;
    uint32_t pc = entry, pending = 0;
    int has_pending = 0;
    for (unsigned step = 0; step < 240u; ++step) {
        uint32_t instruction;
        if (memory_u32(memory, pc, &instruction) != 0) return -1;
        uint32_t next_pc = pc + 4u;
        unsigned op = instruction >> 26;
        unsigned rs = (instruction >> 21) & 31u, rt = (instruction >> 16) & 31u;
        unsigned rd = (instruction >> 11) & 31u, sa = (instruction >> 6) & 31u;
        unsigned function = instruction & 63u;
        uint16_t immediate = (uint16_t)instruction;
        int32_t signed_immediate = (int16_t)immediate;
        uint32_t branch = 0;
        int has_branch = 0;
        if (instruction == 0u) {
            /* nop */
        } else if (op == 0u && function == 0x26u) {
            registers[rd] = registers[rs] ^ registers[rt];
        } else if (op == 0u && function == 0x21u) {
            registers[rd] = registers[rs] + registers[rt];
        } else if (op == 0u && function == 0x25u) {
            registers[rd] = registers[rs] | registers[rt];
        } else if (op == 0u && function == 0x00u) {
            registers[rd] = registers[rt] << sa;
        } else if (op == 0u && function == 0x03u) {
            registers[rd] = (uint32_t)((int32_t)registers[rt] >> sa);
        } else if (op == 0u && function == 0x02u) {
            registers[rd] = rs == 1u ? ror32(registers[rt], sa) : registers[rt] >> sa;
        } else if (op == 0u && function == 0x08u) {
            branch = registers[rs]; has_branch = 1;
        } else if (op == 0x23u) {
            if (memory_u32(memory, registers[rs] + (uint32_t)signed_immediate, &registers[rt]) != 0) return -1;
        } else if (op == 0x21u) {
            uint16_t value;
            if (memory_u16(memory, registers[rs] + (uint32_t)signed_immediate, &value) != 0) return -1;
            registers[rt] = (uint32_t)(int32_t)(int16_t)value;
        } else if (op == 0x25u) {
            uint16_t value;
            if (memory_u16(memory, registers[rs] + (uint32_t)signed_immediate, &value) != 0) return -1;
            registers[rt] = value;
        } else if (op == 0x2bu) {
            if (memory_w32(memory, registers[rs] + (uint32_t)signed_immediate, registers[rt]) != 0) return -1;
        } else if (op == 0x28u) {
            if (memory_w8(memory, registers[rs] + (uint32_t)signed_immediate, (uint8_t)registers[rt]) != 0) return -1;
        } else if (op == 0x29u) {
            if (memory_w16(memory, registers[rs] + (uint32_t)signed_immediate, (uint16_t)registers[rt]) != 0) return -1;
        } else if (op == 0x0cu) {
            registers[rt] = registers[rs] & immediate;
        } else if (op == 0x09u) {
            registers[rt] = registers[rs] + (uint32_t)signed_immediate;
        } else if (op == 0x0eu) {
            registers[rt] = registers[rs] ^ immediate;
        } else if (op == 0x04u) {
            if (registers[rs] == registers[rt]) {
                branch = pc + 4u + (uint32_t)(signed_immediate * 4);
                has_branch = 1;
            }
        } else {
            return -1;
        }
        registers[0] = 0;
        if (has_pending) {
            pc = pending;
            has_pending = 0;
            if (pc == RETURN_SENTINEL) return 0;
        } else {
            pc = next_pc;
            if (has_branch) { pending = branch; has_pending = 1; }
        }
    }
    return -1;
}

static int apply_payload(Memory *memory, const uint8_t *raw, size_t size) {
    if (size != 16u + PATCH_RECORD_COUNT * 12u || memcmp(raw, "NSST", 4) != 0 ||
        load16(raw + 4) != 3u || load16(raw + 6) != PATCH_RECORD_COUNT ||
        load32(raw + 8) != START_TOKEN || load32(raw + 12) != 0u) return -1;
    unsigned absolute_count = 0, heap_count = 0;
    uint32_t touched[PATCH_RECORD_COUNT];
    size_t touched_count = 0;
    for (unsigned index = 0; index < PATCH_RECORD_COUNT; ++index) {
        const uint8_t *record = raw + 16u + index * 12u;
        unsigned type = record[0], flags = record[1];
        uint16_t offset = load16(record + 2);
        uint32_t address = load32(record + 4), value = load32(record + 8), target;
        if (flags != 0u) return -1;
        if (type == 1u) {
            if (offset != 0u || (address != START_PTR_ADDR && address != ARG_BIAS_ADDR)) return -1;
            target = address; absolute_count++;
        } else if (type == 2u) {
            if (address != 0u || offset < 0x100u || offset > 0xfffcu) return -1;
            target = HEAP_BASE + offset; heap_count++;
        } else {
            return -1;
        }
        if ((target & 3u) != 0u || (RESULT_ADDR <= target && target < RESULT_ADDR + 0x40u)) return -1;
        for (size_t other = 0; other < touched_count; ++other) if (touched[other] == target) return -1;
        touched[touched_count++] = target;
        if (memory_w32(memory, target, value) != 0) return -1;
    }
    return absolute_count == ABS_WRITE_COUNT && heap_count == HEAP_WRITE_COUNT ? 0 : -1;
}

static void sha256_pair(const uint8_t *prefix, size_t prefix_size,
                        const uint8_t *body, size_t body_size, uint8_t output[32]) {
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, prefix, prefix_size);
    SHA256_Update(&context, body, body_size);
    SHA256_Final(output, &context);
}

static int execute_detailed(const uint8_t *target, size_t target_size,
                            const uint8_t *image, size_t image_size,
                            const uint8_t *payload, size_t payload_size,
                            const uint32_t input[8], uint8_t key[32],
                            uint8_t final_result[32]) {
    Memory memory = {0};
    int status = -1;
    if (load_elf(&memory, target, target_size) != 0 ||
        memory_map(&memory, HEAP_BASE, image, image_size, image_size, 1) != 0 ||
        apply_payload(&memory, payload, payload_size) != 0) goto done;
    for (unsigned index = 0; index < 8u; ++index) {
        if (memory_w32(&memory, RESULT_ADDR + index * 4u, input[index]) != 0) goto done;
    }
    if (memory_w32(&memory, ROUTE_STATE0_ADDR, 0) != 0 ||
        memory_w32(&memory, ROUTE_STATE1_ADDR, 0) != 0) goto done;

    SHA256_CTX receipt;
    SHA256_Init(&receipt);
    SHA256_Update(&receipt, RECEIPT_DOMAIN, sizeof(RECEIPT_DOMAIN) - 1u);
    uint8_t initial[32];
    if (memory_read(&memory, RESULT_ADDR, initial, sizeof(initial)) != 0) goto done;
    SHA256_Update(&receipt, initial, sizeof(initial));
    uint32_t offset, argument_bias;
    if (memory_u32(&memory, START_PTR_ADDR, &offset) != 0 ||
        memory_u32(&memory, ARG_BIAS_ADDR, &argument_bias) != 0) goto done;
    unsigned seen = 0;
    while (offset != 0xffffffffu) {
        if (offset > 0xfff0u || (offset & 0xfu) != 0u || seen > 64u) goto done;
        uint8_t node[16], before[32], after[32], route_before[8], route_after[8];
        if (memory_read(&memory, HEAP_BASE + offset, node, sizeof(node)) != 0) goto done;
        uint32_t function_id = load32(node), argument_offset = load32(node + 4);
        uint32_t next_offset = load32(node + 8), guard = load32(node + 12);
        if (function_id >= GADGET_COUNT ||
            guard != rol32(function_id ^ argument_offset ^ next_offset ^ COOKIE, 7)) goto done;
        uint32_t entry;
        if (memory_u32(&memory, FN_TABLE_ADDR + function_id * 4u, &entry) != 0) goto done;
        uint32_t argument_address = HEAP_BASE + ((argument_offset + argument_bias) & 0xffffu);
        if (memory_read(&memory, RESULT_ADDR, before, sizeof(before)) != 0 ||
            memory_read(&memory, ROUTE_STATE0_ADDR, route_before, sizeof(route_before)) != 0 ||
            run_function(&memory, entry, RESULT_ADDR, argument_address) != 0 ||
            memory_read(&memory, RESULT_ADDR, after, sizeof(after)) != 0 ||
            memory_read(&memory, ROUTE_STATE0_ADDR, route_after, sizeof(route_after)) != 0) goto done;
        uint8_t fields[20];
        store32(fields, seen); store32(fields + 4, function_id);
        store32(fields + 8, argument_offset); store32(fields + 12, next_offset);
        store32(fields + 16, argument_address - HEAP_BASE);
        SHA256_Update(&receipt, fields, sizeof(fields));
        SHA256_Update(&receipt, before, sizeof(before));
        SHA256_Update(&receipt, after, sizeof(after));
        SHA256_Update(&receipt, route_before, sizeof(route_before));
        SHA256_Update(&receipt, route_after, sizeof(route_after));
        offset = next_offset; seen++;
    }
    if (seen != CHAIN_LENGTH) goto done;
    uint32_t route0, route1, target0, target1;
    if (memory_u32(&memory, ROUTE_STATE0_ADDR, &route0) != 0 ||
        memory_u32(&memory, ROUTE_STATE1_ADDR, &route1) != 0 ||
        memory_u32(&memory, ROUTE_TARGET_ADDR, &target0) != 0 ||
        memory_u32(&memory, ROUTE_TARGET_ADDR + 4u, &target1) != 0 ||
        route0 != target0 || route1 != target1 || memory_w8(&memory, RESULT_ADDR + 0x20u, 1) != 0 ||
        memory_read(&memory, RESULT_ADDR, final_result, 32) != 0) goto done;
    uint8_t ending[8], seen_raw[4];
    store32(seen_raw, seen); store32(ending, route0); store32(ending + 4, route1);
    SHA256_Update(&receipt, seen_raw, sizeof(seen_raw));
    SHA256_Update(&receipt, final_result, 32);
    SHA256_Update(&receipt, ending, sizeof(ending));
    uint8_t receipt_digest[32];
    SHA256_Final(receipt_digest, &receipt);
    sha256_pair(RECEIPT_DOMAIN, sizeof(RECEIPT_DOMAIN) - 1u, receipt_digest, 32, key);
    status = 0;
done:
    memory_free(&memory);
    return status;
}

static int execute_fleet(const uint8_t *target, size_t target_size,
                         const uint8_t *image, size_t image_size,
                         const uint8_t *payload, size_t payload_size,
                         const uint8_t *vectors, size_t vectors_size,
                         uint8_t fleet_key[32]) {
    if (vectors_size != 8u + VECTOR_COUNT * 32u || memcmp(vectors, "NSV3", 4) != 0 ||
        load16(vectors + 4) != VECTOR_COUNT || load16(vectors + 6) != 8u) return -1;
    SHA256_CTX transcript;
    SHA256_Init(&transcript);
    SHA256_Update(&transcript, FLEET_DOMAIN, sizeof(FLEET_DOMAIN) - 1u);
    for (unsigned vector_index = 0; vector_index < VECTOR_COUNT; ++vector_index) {
        uint32_t input[8];
        for (unsigned word = 0; word < 8u; ++word) {
            input[word] = load32(vectors + 8u + vector_index * 32u + word * 4u);
        }
        uint8_t key[32], result[32], index_raw[4];
        if (execute_detailed(target, target_size, image, image_size, payload, payload_size,
                             input, key, result) != 0) return -1;
        store32(index_raw, vector_index);
        SHA256_Update(&transcript, index_raw, sizeof(index_raw));
        SHA256_Update(&transcript, key, sizeof(key));
        SHA256_Update(&transcript, result, sizeof(result));
    }
    uint8_t digest[32];
    SHA256_Final(digest, &transcript);
    sha256_pair(RECEIPT_DOMAIN, sizeof(RECEIPT_DOMAIN) - 1u, digest, sizeof(digest), fleet_key);
    return 0;
}

static int decrypt_flag(const uint8_t key[32], const uint8_t *container, size_t size,
                        const uint8_t *aad, size_t aad_size, uint8_t **plaintext,
                        size_t *plaintext_size) {
    if (size < 40u || memcmp(container, "NSFE", 4) != 0 || load16(container + 4) != 4u ||
        load16(container + 6) != 12u) return -1;
    uint32_t ciphertext_size = load32(container + 20);
    if ((uint64_t)24u + ciphertext_size + 16u != size) return -1;
    const uint8_t *nonce = container + 8, *ciphertext = container + 24;
    const uint8_t *tag = ciphertext + ciphertext_size;
    uint8_t *output = malloc((size_t)ciphertext_size + 1u);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (output == NULL || context == NULL) { free(output); EVP_CIPHER_CTX_free(context); return -1; }
    int length = 0, total = 0, ok =
        EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(context, NULL, &length, aad, (int)aad_size) == 1 &&
        EVP_DecryptUpdate(context, output, &length, ciphertext, (int)ciphertext_size) == 1;
    total = length;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(context, output + total, &length) == 1;
    total += ok ? length : 0;
    EVP_CIPHER_CTX_free(context);
    if (!ok || total < 5 || memcmp(output, "SHA{", 4) != 0 || output[total - 1] != '}') {
        free(output); return -1;
    }
    output[total] = 0;
    *plaintext = output; *plaintext_size = (size_t)total;
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    uint8_t *target = NULL, *image = NULL, *payload = NULL, *vectors = NULL, *sealed = NULL;
    size_t target_size = 0, image_size = 0, payload_size = 0, vectors_size = 0, sealed_size = 0;
    int success = argc == 1 &&
        read_file("target.elf", &target, &target_size, 4u * 1024u * 1024u) == 0 &&
        read_file("memory.img", &image, &image_size, 2u * 1024u * 1024u) == 0 &&
        read_file("payload.bin", &payload, &payload_size, 4096u) == 0 &&
        read_file("vectors.bin", &vectors, &vectors_size, 4096u) == 0 &&
        read_file("flag.enc", &sealed, &sealed_size, 4096u) == 0;
    uint8_t fleet_key[32];
    if (success) success = execute_fleet(target, target_size, image, image_size, payload, payload_size,
                                         vectors, vectors_size, fleet_key) == 0;
    uint8_t *plain = NULL; size_t plain_size = 0;
    if (success) {
        uint8_t target_hash[32], image_hash[32], vector_hash[32];
        SHA256(target, target_size, target_hash);
        SHA256(image, image_size, image_hash);
        SHA256(vectors, vectors_size, vector_hash);
        uint8_t aad[sizeof(PROBLEM_ID) - 1u + 96u];
        memcpy(aad, PROBLEM_ID, sizeof(PROBLEM_ID) - 1u);
        memcpy(aad + sizeof(PROBLEM_ID) - 1u, target_hash, 32);
        memcpy(aad + sizeof(PROBLEM_ID) - 1u + 32u, image_hash, 32);
        memcpy(aad + sizeof(PROBLEM_ID) - 1u + 64u, vector_hash, 32);
        success = decrypt_flag(fleet_key, sealed, sealed_size, aad, sizeof(aad),
                               &plain, &plain_size) == 0;
    }
    if (success) fwrite(plain, 1, plain_size, stdout), fputc('\n', stdout);
    else fputs("invalid result\n", stdout);
    free(plain); free(target); free(image); free(payload); free(vectors); free(sealed);
    return success ? 0 : 1;
}
