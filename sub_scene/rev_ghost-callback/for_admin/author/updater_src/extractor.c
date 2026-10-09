#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PATH_LEN 512

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *source, char *target, size_t capacity) {
    size_t length = strlen(source);
    if ((length & 1) || length / 2 >= capacity) return -1;
    for (size_t i = 0; i < length; i += 2) {
        int high = hex_value(source[i]), low = hex_value(source[i + 1]);
        if (high < 0 || low < 0) return -1;
        target[i / 2] = (char)((high << 4) | low);
        if (target[i / 2] == '\0') return -1;
    }
    target[length / 2] = '\0';
    return 0;
}

static int normalize(const char *input, char *output, size_t capacity) {
    if (!input[0] || input[0] == '/') return -1;
    char copy[MAX_PATH_LEN], *segments[80], *save = NULL;
    if (strlen(input) >= sizeof(copy)) return -1;
    strcpy(copy, input);
    size_t count = 0;
    for (char *part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".")) continue;
        if (!strcmp(part, "..")) {
            if (!count) return -1;
            count--;
            continue;
        }
        if (strchr(part, '\\') || !strcmp(part, "")) return -1;
        if (count >= 80) return -1;
        segments[count++] = part;
    }
    if (!count) return -1;
    size_t used = 0;
    for (size_t i = 0; i < count; i++) {
        size_t length = strlen(segments[i]);
        if (used + length + (i != 0) + 1 > capacity) return -1;
        if (i) output[used++] = '/';
        memcpy(output + used, segments[i], length);
        used += length;
    }
    output[used] = '\0';
    return 0;
}

static int mkdir_parents(const char *path) {
    char copy[PATH_MAX];
    if (strlen(path) >= sizeof(copy)) return -1;
    strcpy(copy, path);
    for (char *cursor = copy + 1; *cursor; cursor++) {
        if (*cursor == '/') {
            *cursor = '\0';
            if (mkdir(copy, 0700) && errno != EEXIST) return -1;
            *cursor = '/';
        }
    }
    return 0;
}

static int copy_file(const char *source, const char *destination) {
    int input = open(source, O_RDONLY | O_NOFOLLOW);
    if (input < 0) return -1;
    if (mkdir_parents(destination)) { close(input); return -1; }
    int output = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (output < 0) { close(input); return -1; }
    char buffer[8192];
    ssize_t amount;
    while ((amount = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < amount) {
            ssize_t written = write(output, buffer + offset, (size_t)(amount - offset));
            if (written <= 0) { close(input); close(output); return -1; }
            offset += written;
        }
    }
    int failed = amount < 0;
    if (close(input)) failed = 1;
    if (close(output)) failed = 1;
    return failed ? -1 : 0;
}

int main(void) {
    FILE *manifest = fopen(".update_work/entries.tsv", "r");
    if (!manifest) return 2;
    char line[2048], encoded[1025], blob[128], decoded[MAX_PATH_LEN], final[MAX_PATH_LEN];
    int firmware_writes[3] = {0, 0, 0}, calibration_writes = 0;
    while (fgets(line, sizeof(line), manifest)) {
        char *tab = strchr(line, '\t');
        if (!tab) { fclose(manifest); return 3; }
        *tab = '\0';
        strncpy(encoded, line, sizeof(encoded) - 1); encoded[sizeof(encoded) - 1] = 0;
        strncpy(blob, tab + 1, sizeof(blob) - 1); blob[sizeof(blob) - 1] = 0;
        blob[strcspn(blob, "\r\n")] = 0;
        if (decode_hex(encoded, decoded, sizeof(decoded)) || normalize(decoded, final, sizeof(final))) {
            fclose(manifest); return 4;
        }
        if (!strcmp(final, "firmware/firmware_a.bin")) {
            if (++firmware_writes[0] != 1) { fclose(manifest); return 5; }
        } else if (!strcmp(final, "firmware/firmware_b.bin")) {
            if (++firmware_writes[1] != 1) { fclose(manifest); return 5; }
        } else if (!strcmp(final, "firmware/firmware_c.bin")) {
            if (++firmware_writes[2] != 1) { fclose(manifest); return 5; }
        } else if (!strcmp(final, "profiles/calibration.bin")) {
            calibration_writes++;
        } else if (strncmp(final, "extras/", 7)) {
            fclose(manifest); return 6;
        }
        char source[PATH_MAX], destination[PATH_MAX];
        if (snprintf(source, sizeof(source), ".update_work/%s", blob) >= (int)sizeof(source) ||
            snprintf(destination, sizeof(destination), ".stage/%s", final) >= (int)sizeof(destination) ||
            copy_file(source, destination)) {
            fclose(manifest); return 7;
        }
    }
    fclose(manifest);
    return firmware_writes[0] == 1 && firmware_writes[1] == 1 &&
           firmware_writes[2] == 1 && calibration_writes >= 1 ? 0 : 8;
}
