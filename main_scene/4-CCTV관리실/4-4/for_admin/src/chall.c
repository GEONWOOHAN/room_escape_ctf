#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/random.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 31344
#define MAX_LINE 512
#define MAX_TEAMS 64
#define MAX_TOKEN 512
#define MAX_RECORD 64
#define MAX_ASSETS 128
#define TARGET_RECORD "CAM042-20260919xxxxxx-Snapshot.png"
#define DEFAULT_RECORD "CAM042-20260919004000-Snapshot.png"
#define TEMPLATE_DIR "/home/ctf/template"
#define RUNTIME_DIR "/tmp/cctv-live"
#define FLAG_FILE "/home/ctf/flag"
#define AUTH_SOCKET "/run/uos-auth.sock"
#define DEFAULT_TOKEN_FILE "/run/secrets/archive_sweeper_tokens"
#define CTFD_AUTH_HELPER "/home/ctf/ctfd_auth.py"
#define DEFAULT_STATE_DIR "/data"
#define STATE_MAGIC 0x41535732U
#define STATE_VERSION 1U

typedef enum {
    STATE_EMPTY = 0,
    STATE_LOADED = 1,
    STATE_QUEUED = 2,
    STATE_VALIDATING = 3,
    STATE_FINISHED = 4,
    STATE_REJECTED = 5
} CleanupState;

typedef struct {
    char cleanup_id[16];
    char approved_record[MAX_RECORD];
    char target_record[MAX_RECORD];
    unsigned char approval_signature[32];
    int approval_valid;
    CleanupState state;
    unsigned int generation;
    uint32_t snapshot_version;
    int version_used;
} CleanupRequest;

typedef struct {
    int fd;
} ClientContext;

typedef struct {
    char team_id[32];
    char token[MAX_TOKEN];
    char archive_dir[128];
    CleanupRequest request;
    pthread_mutex_t lock;
    pthread_cond_t snapshot_ready;
    char last_verified[MAX_RECORD];
    char last_deleted[MAX_RECORD];
    int protected_deleted;
    uint32_t version_secret;
} TeamState;

typedef struct {
    uint32_t magic;
    uint32_t version;
    CleanupRequest request;
    char last_verified[MAX_RECORD];
    char last_deleted[MAX_RECORD];
    int protected_deleted;
    uint32_t version_secret;
} PersistedTeamState;

static TeamState teams[MAX_TEAMS];
static size_t team_count;
static pthread_mutex_t teams_lock = PTHREAD_MUTEX_INITIALIZER;
static char asset_records[MAX_ASSETS][MAX_RECORD];
static size_t asset_count;
static __thread TeamState *current_team;
static int initialize_archive(void);
static int valid_record(const char *record);
static pthread_mutex_t connections_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int active_connections;
static unsigned int max_active_connections = 128;
static unsigned int max_concurrent_auth = 8;
static unsigned int auth_timeout_seconds = 15;
static unsigned int idle_timeout_seconds = 300;
static unsigned int active_auth;
static pthread_mutex_t auth_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t auth_available = PTHREAD_COND_INITIALIZER;

#define cleanup_request (current_team->request)
#define request_lock (current_team->lock)
#define last_verified_record (current_team->last_verified)
#define last_deleted_record (current_team->last_deleted)
#define protected_record_deleted (current_team->protected_deleted)

static unsigned int environment_uint(const char *name, unsigned int fallback,
                                     unsigned int minimum,
                                     unsigned int maximum) {
    const char *value = getenv(name);
    if (!value || !value[0])
        return fallback;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (!end || *end || parsed < minimum || parsed > maximum)
        return fallback;
    return (unsigned int)parsed;
}

static void socket_timeout(int fd, unsigned int seconds) {
    struct timeval timeout = {.tv_sec = (time_t)seconds, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int state_path(const TeamState *team, char *path, size_t size,
                      const char *suffix) {
    const char *directory = getenv("STATE_DIR");
    if (!directory || !directory[0])
        directory = DEFAULT_STATE_DIR;
    for (const char *p = team->team_id; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
            return 0;
    int count = snprintf(path, size, "%s/%s%s", directory, team->team_id,
                         suffix ? suffix : "");
    return count > 0 && (size_t)count < size;
}

static void persist_current_team(void) {
    char path[256], temporary[272];
    if (!state_path(current_team, path, sizeof(path), ".state") ||
        !state_path(current_team, temporary, sizeof(temporary), ".state.tmp"))
        return;
    PersistedTeamState snapshot = {
        .magic = STATE_MAGIC,
        .version = STATE_VERSION,
    };
    pthread_mutex_lock(&request_lock);
    snapshot.request = cleanup_request;
    memcpy(snapshot.last_verified, last_verified_record,
           sizeof(snapshot.last_verified));
    memcpy(snapshot.last_deleted, last_deleted_record,
           sizeof(snapshot.last_deleted));
    snapshot.protected_deleted = protected_record_deleted;
    snapshot.version_secret = current_team->version_secret;

    int descriptor = open(temporary,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        pthread_mutex_unlock(&request_lock);
        return;
    }
    const unsigned char *data = (const unsigned char *)&snapshot;
    size_t remaining = sizeof(snapshot);
    while (remaining) {
        ssize_t written = write(descriptor, data, remaining);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            break;
        data += written;
        remaining -= (size_t)written;
    }
    if (!remaining && fsync(descriptor) == 0) {
        close(descriptor);
        if (rename(temporary, path) != 0)
            unlink(temporary);
    } else {
        close(descriptor);
        unlink(temporary);
    }
    pthread_mutex_unlock(&request_lock);
}

static void restore_current_team(void) {
    char path[256];
    if (!state_path(current_team, path, sizeof(path), ".state"))
        return;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return;
    PersistedTeamState snapshot;
    unsigned char *data = (unsigned char *)&snapshot;
    size_t remaining = sizeof(snapshot);
    while (remaining) {
        ssize_t count = read(descriptor, data, remaining);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            break;
        data += count;
        remaining -= (size_t)count;
    }
    close(descriptor);
    if (remaining || snapshot.magic != STATE_MAGIC ||
        snapshot.version != STATE_VERSION || !snapshot.version_secret ||
        snapshot.request.state < STATE_EMPTY ||
        snapshot.request.state > STATE_REJECTED ||
        !memchr(snapshot.request.cleanup_id, '\0', sizeof(snapshot.request.cleanup_id)) ||
        !memchr(snapshot.request.approved_record, '\0', sizeof(snapshot.request.approved_record)) ||
        !memchr(snapshot.request.target_record, '\0', sizeof(snapshot.request.target_record)) ||
        !memchr(snapshot.last_verified, '\0', sizeof(snapshot.last_verified)) ||
        !memchr(snapshot.last_deleted, '\0', sizeof(snapshot.last_deleted)))
        return;
    if (snapshot.request.state == STATE_QUEUED ||
        snapshot.request.state == STATE_VALIDATING) {
        snapshot.request.state = STATE_LOADED;
        snapshot.request.snapshot_version = 0;
        snapshot.request.version_used = 0;
    }
    cleanup_request = snapshot.request;
    memcpy(last_verified_record, snapshot.last_verified,
           sizeof(last_verified_record));
    memcpy(last_deleted_record, snapshot.last_deleted,
           sizeof(last_deleted_record));
    protected_record_deleted = snapshot.protected_deleted ? 1 : 0;
    current_team->version_secret = snapshot.version_secret;
    if (valid_record(last_deleted_record)) {
        char deleted[512];
        int count = snprintf(deleted, sizeof(deleted), "%s/%s",
                             current_team->archive_dir, last_deleted_record);
        if (count > 0 && (size_t)count < sizeof(deleted))
            (void)unlink(deleted);
    }
}

static int send_text(int fd, const char *text) {
    size_t length = strlen(text);
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(fd, text + sent, length - sent, MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (count == 0)
            return 0;
        sent += (size_t)count;
    }
    return 1;
}

static int send_format(int fd, const char *format, ...) {
    char buffer[2048];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    if (length < 0)
        return 0;
    if ((size_t)length >= sizeof(buffer))
        length = (int)sizeof(buffer) - 1;
    return send_text(fd, buffer);
}

static int receive_line(int fd, char *buffer, size_t size) {
    size_t used = 0;
    while (used + 1 < size) {
        unsigned char c;
        ssize_t count = recv(fd, &c, 1, 0);
        if (count == 0)
            return 0;
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (c == '\n')
            break;
        if (c != '\r')
            buffer[used++] = (char)c;
    }
    buffer[used] = '\0';
    return 1;
}

static int compare_asset_names(const void *left, const void *right) {
    return strcmp((const char *)left, (const char *)right);
}

static int asset_index(const char *record) {
    if (!record)
        return -1;
    for (size_t index = 0; index < asset_count; index++) {
        if (!strcmp(asset_records[index], record))
            return (int)index;
    }
    return -1;
}

static const char *default_approved_record(void) {
    int preferred = asset_index(DEFAULT_RECORD);
    if (preferred >= 0)
        return asset_records[preferred];
    for (size_t index = 0; index < asset_count; index++) {
        if (strcmp(asset_records[index], TARGET_RECORD))
            return asset_records[index];
    }
    return NULL;
}

static int load_assets(void) {
    DIR *directory = opendir(TEMPLATE_DIR);
    if (!directory)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        size_t length = strlen(entry->d_name);
        if (length < 5 || strcmp(entry->d_name + length - 4, ".png"))
            continue;
        if (length >= MAX_RECORD || asset_count >= MAX_ASSETS) {
            closedir(directory);
            return 0;
        }

        char path[512];
        int written = snprintf(path, sizeof(path), "%s/%s",
                               TEMPLATE_DIR, entry->d_name);
        struct stat status;
        if (written < 0 || (size_t)written >= sizeof(path) ||
            stat(path, &status) != 0 || !S_ISREG(status.st_mode))
            continue;

        strcpy(asset_records[asset_count], entry->d_name);
        asset_count++;
    }
    closedir(directory);

    qsort(asset_records, asset_count, sizeof(asset_records[0]),
          compare_asset_names);
    return asset_index(TARGET_RECORD) >= 0 && default_approved_record() != NULL;
}

static int load_teams(void) {
    const char *path = getenv("TEAM_TOKENS_FILE");
    if (!path || !path[0])
        path = DEFAULT_TOKEN_FILE;

    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "failed to open team token file: %s\n", path);
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0] || line[0] == '#')
            continue;
        char *separator = strchr(line, ':');
        if (!separator || separator == line || !separator[1] || team_count >= MAX_TEAMS) {
            fclose(file);
            return 0;
        }
        *separator = '\0';
        TeamState *team = &teams[team_count];
        if (strlen(line) >= sizeof(team->team_id) ||
            strlen(separator + 1) >= sizeof(team->token)) {
            fclose(file);
            return 0;
        }
        strcpy(team->team_id, line);
        strcpy(team->token, separator + 1);
        snprintf(team->archive_dir, sizeof(team->archive_dir),
                 RUNTIME_DIR "/team-%03zu", team_count + 1);
        team->version_secret = 0x8f21c4d7U ^ (uint32_t)team_count;
        (void)getrandom(&team->version_secret,
                        sizeof(team->version_secret), 0);
        if (!team->version_secret)
            team->version_secret = 0x8f21c4d7U ^ (uint32_t)team_count;
        pthread_mutex_init(&team->lock, NULL);
        pthread_cond_init(&team->snapshot_ready, NULL);
        team_count++;
    }
    fclose(file);
    return team_count > 0;
}

static TeamState *find_team(const char *token) {
    for (size_t index = 0; index < team_count; index++) {
        if (!strcmp(teams[index].token, token))
            return &teams[index];
    }
    return NULL;
}

/* The helper validates each Access Token with CTFd. No token is cached here. */
static int ctfd_team_id(const char *token, char *team_id, size_t size) {
    pthread_mutex_lock(&auth_lock);
    while (active_auth >= max_concurrent_auth)
        pthread_cond_wait(&auth_available, &auth_lock);
    active_auth++;
    pthread_mutex_unlock(&auth_lock);

    int valid = 0;
    int input[2], output[2];
    if (pipe(input) != 0)
        goto done;
    if (pipe(output) != 0) {
        close(input[0]); close(input[1]);
        goto done;
    }
    pid_t child = fork();
    if (child < 0) {
        close(input[0]); close(input[1]);
        close(output[0]); close(output[1]);
        goto done;
    }
    if (child == 0) {
        dup2(input[0], STDIN_FILENO);
        dup2(output[1], STDOUT_FILENO);
        close(input[0]); close(input[1]);
        close(output[0]); close(output[1]);
        execl("/usr/bin/python3", "python3", CTFD_AUTH_HELPER, (char *)NULL);
        _exit(127);
    }
    close(input[0]); close(output[1]);
    size_t length = strlen(token);
    int written = length > 0 && length < MAX_TOKEN;
    for (size_t offset = 0; written && offset < length;) {
        ssize_t count = write(input[1], token + offset, length - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            written = 0;
            break;
        }
        offset += (size_t)count;
    }
    close(input[1]);
    char response[32] = {0};
    ssize_t received = read(output[0], response, sizeof(response) - 1);
    close(output[0]);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (!written || received <= 0 || waited != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto done;
    response[received] = '\0';
    response[strcspn(response, "\r\n")] = '\0';
    if (!response[0] || response[0] == '0')
        goto done;
    for (const char *p = response; *p; p++)
        if (!isdigit((unsigned char)*p))
            goto done;
    int count = snprintf(team_id, size, "ctfd-%s", response);
    valid = count > 0 && (size_t)count < size;

done:
    pthread_mutex_lock(&auth_lock);
    if (active_auth)
        active_auth--;
    pthread_cond_signal(&auth_available);
    pthread_mutex_unlock(&auth_lock);
    return valid;
}

static TeamState *find_or_create_ctfd_team(const char *team_id) {
    pthread_mutex_lock(&teams_lock);
    for (size_t index = 0; index < team_count; index++) {
        if (!strcmp(teams[index].team_id, team_id)) {
            TeamState *team = &teams[index];
            pthread_mutex_unlock(&teams_lock);
            return team;
        }
    }
    if (team_count >= MAX_TEAMS) {
        pthread_mutex_unlock(&teams_lock);
        return NULL;
    }
    TeamState *team = &teams[team_count];
    snprintf(team->team_id, sizeof(team->team_id), "%s", team_id);
    snprintf(team->archive_dir, sizeof(team->archive_dir),
             RUNTIME_DIR "/team-%03zu", team_count + 1);
    (void)getrandom(&team->version_secret, sizeof(team->version_secret), 0);
    if (!team->version_secret)
        team->version_secret = 0x8f21c4d7U ^ (uint32_t)team_count;
    pthread_mutex_init(&team->lock, NULL);
    pthread_cond_init(&team->snapshot_ready, NULL);
    current_team = team;
    if (!initialize_archive()) {
        pthread_mutex_unlock(&teams_lock);
        return NULL;
    }
    restore_current_team();
    team_count++;
    pthread_mutex_unlock(&teams_lock);
    return team;
}

static int initialize_archive(void) {
    if (mkdir(RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return 0;
    if (mkdir(current_team->archive_dir, 0700) != 0 && errno != EEXIST)
        return 0;

    for (size_t index = 0; index < asset_count; index++) {
        char source[512];
        char destination[512];
        int source_length = snprintf(source, sizeof(source), "%s/%s",
                                     TEMPLATE_DIR, asset_records[index]);
        int destination_length = snprintf(destination, sizeof(destination),
                                          "%s/%s", current_team->archive_dir,
                                          asset_records[index]);
        if (source_length < 0 || (size_t)source_length >= sizeof(source) ||
            destination_length < 0 ||
            (size_t)destination_length >= sizeof(destination))
            return 0;
        if (unlink(destination) != 0 && errno != ENOENT)
            return 0;
        if (symlink(source, destination) != 0)
            return 0;
    }
    return 1;
}

static void build_approval_signature(const char *record, unsigned char output[32]) {
    uint32_t state = 0x7a31c95dU;
    for (size_t index = 0; record[index]; index++) {
        state ^= (unsigned char)record[index];
        state *= 0x01000193U;
        state = (state << 5) | (state >> 27);
    }
    for (size_t index = 0; index < 32; index++) {
        state ^= (uint32_t)(index * 0x45d9f3bU);
        state = state * 1664525U + 1013904223U;
        output[index] = (unsigned char)(state >> 24);
    }
}

static int verify_approval(const char *record, const unsigned char signature[32]) {
    unsigned char expected[32];
    build_approval_signature(record, expected);
    unsigned char difference = 0;
    for (size_t index = 0; index < sizeof(expected); index++)
        difference |= expected[index] ^ signature[index];
    return difference == 0;
}

__attribute__((noinline))
static uint32_t make_snapshot_version(unsigned int generation,
                                      uint32_t secret) {
    uint32_t value = generation ^ secret ^ 0x6d2b79f5U;
    value ^= value >> 15;
    value *= 0x2c1b3c6dU;
    value ^= value >> 12;
    return value ^ 0x91e10da5U;
}

static const char *state_name(CleanupState state) {
    switch (state) {
    case STATE_EMPTY: return "EMPTY";
    case STATE_LOADED: return "READY";
    case STATE_QUEUED: return "PROCESSING";
    case STATE_VALIDATING: return "PROCESSING";
    case STATE_FINISHED: return "FINISHED";
    case STATE_REJECTED: return "REJECTED";
    default: return "UNKNOWN";
    }
}

static int valid_record(const char *record) {
    return asset_index(record) >= 0;
}

/* Storage workers address footage by an internal handle, not its public ID. */
__attribute__((noinline))
static uint32_t record_handle(const char *record) {
    uint32_t value = 0x43435456U;
    for (size_t index = 0; record[index]; index++) {
        value = (value << 7) | (value >> 25);
        value ^= (unsigned char)record[index];
        value += 0x9e3779b9U;
    }
    return value ^ 0xa5c31f27U;
}

static const char *resolve_handle(const char *handle) {
    unsigned int supplied;
    char trailing;
    if (!handle || sscanf(handle, "STG-%8x%c", &supplied, &trailing) != 1)
        return NULL;

    for (size_t index = 0; index < asset_count; index++) {
        if (record_handle(asset_records[index]) == supplied)
            return asset_records[index];
    }
    return NULL;
}

static int delete_record(const char *record) {
    if (!valid_record(record))
        return 0;
    char path[512];
    int written = snprintf(path, sizeof(path), "%s/%s",
                           current_team->archive_dir, record);
    if (written < 0 || (size_t)written >= sizeof(path))
        return 0;
    return unlink(path) == 0;
}

static void *cleanup_worker(void *argument) {
    current_team = argument;
    char approved_snapshot[MAX_RECORD];
    unsigned char signature_snapshot[32];
    unsigned int generation_snapshot;

    pthread_mutex_lock(&request_lock);
    if (cleanup_request.state != STATE_QUEUED) {
        pthread_mutex_unlock(&request_lock);
        return NULL;
    }
    memcpy(approved_snapshot, cleanup_request.approved_record,
           sizeof(approved_snapshot));
    memcpy(signature_snapshot, cleanup_request.approval_signature,
           sizeof(signature_snapshot));
    generation_snapshot = cleanup_request.generation;
    cleanup_request.state = STATE_VALIDATING;
    pthread_mutex_unlock(&request_lock);

    if (!verify_approval(approved_snapshot, signature_snapshot)) {
        pthread_mutex_lock(&request_lock);
        if (cleanup_request.generation == generation_snapshot)
            cleanup_request.state = STATE_REJECTED;
        pthread_mutex_unlock(&request_lock);
        return NULL;
    }

    /* The storage node publishes a snapshot version after validation. */
    pthread_mutex_lock(&request_lock);
    if (cleanup_request.generation != generation_snapshot) {
        pthread_mutex_unlock(&request_lock);
        return NULL;
    }
    cleanup_request.snapshot_version =
        make_snapshot_version(generation_snapshot,
                              current_team->version_secret);
    pthread_mutex_unlock(&request_lock);

    /*
     * The storage backend holds the validated snapshot for up to two seconds.
     * A conditional update wakes it immediately.  This preserves the TOCTOU
     * while avoiding a race that depends on host load or network latency.
     */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;

    pthread_mutex_lock(&request_lock);
    while (cleanup_request.generation == generation_snapshot &&
           cleanup_request.state == STATE_VALIDATING &&
           !cleanup_request.version_used) {
        int result = pthread_cond_timedwait(&current_team->snapshot_ready,
                                            &request_lock, &deadline);
        if (result == ETIMEDOUT)
            break;
    }
    pthread_mutex_unlock(&request_lock);

    char target_snapshot[MAX_RECORD];
    pthread_mutex_lock(&request_lock);
    if (cleanup_request.generation != generation_snapshot) {
        pthread_mutex_unlock(&request_lock);
        return NULL;
    }
    cleanup_request.snapshot_version = 0;
    memcpy(target_snapshot, cleanup_request.target_record,
           sizeof(target_snapshot));
    memcpy(last_verified_record, approved_snapshot, sizeof(last_verified_record));
    pthread_mutex_unlock(&request_lock);

    int deletion_succeeded = delete_record(target_snapshot);

    pthread_mutex_lock(&request_lock);
    memcpy(last_deleted_record, target_snapshot, sizeof(last_deleted_record));
    if (deletion_succeeded && !strcmp(target_snapshot, TARGET_RECORD))
        protected_record_deleted = 1;
    cleanup_request.state = STATE_FINISHED;
    pthread_mutex_unlock(&request_lock);
    return NULL;
}

static void load_cleanup_request(int fd, const char *cleanup_id,
                                 const char *requested_record) {
    if (!cleanup_id || strcmp(cleanup_id, "CLN-0007")) {
        send_text(fd, "[-] Unknown cleanup request.\n");
        return;
    }
    if (!requested_record)
        requested_record = default_approved_record();
    if (!valid_record(requested_record)) {
        send_text(fd, "[-] Unknown archive record.\n");
        return;
    }
    if (!strcmp(requested_record, TARGET_RECORD)) {
        send_text(fd, "[-] Protected footage requires administrator approval.\n");
        return;
    }

    pthread_mutex_lock(&request_lock);
    if (cleanup_request.state == STATE_QUEUED ||
        cleanup_request.state == STATE_VALIDATING) {
        pthread_mutex_unlock(&request_lock);
        send_text(fd, "[-] A cleanup request is currently processing.\n");
        return;
    }

    unsigned int next_generation = cleanup_request.generation + 1;
    memset(&cleanup_request, 0, sizeof(cleanup_request));
    strncpy(cleanup_request.cleanup_id, "CLN-0007",
            sizeof(cleanup_request.cleanup_id) - 1);
    strncpy(cleanup_request.approved_record, requested_record,
            sizeof(cleanup_request.approved_record) - 1);
    strncpy(cleanup_request.target_record, requested_record,
            sizeof(cleanup_request.target_record) - 1);
    build_approval_signature(cleanup_request.approved_record,
                             cleanup_request.approval_signature);
    cleanup_request.approval_valid = 1;
    cleanup_request.state = STATE_LOADED;
    cleanup_request.generation = next_generation;
    pthread_mutex_unlock(&request_lock);

    send_format(fd,
        "[+] Cleanup request loaded.\n"
        "Cleanup ID      : CLN-0007\n"
        "Approved record : %s\n"
        "Target record   : %s\n"
        "State           : READY\n",
        requested_record, requested_record);
}

static int parse_snapshot_version(const char *option, const char *text,
                                  uint32_t *version) {
    unsigned long supplied;
    char *end;
    if (!option || strcmp(option, "--if-version") || !text || !text[0])
        return 0;
    errno = 0;
    supplied = strtoul(text, &end, 10);
    if (errno || *end || supplied > UINT32_MAX)
        return 0;
    *version = (uint32_t)supplied;
    return 1;
}

static void retarget_cleanup(int fd, const char *handle,
                             const char *version_option,
                             const char *version_text) {
    const char *record = resolve_handle(handle);
    if (!record) {
        send_text(fd, "[-] Unknown storage handle.\n");
        return;
    }

    pthread_mutex_lock(&request_lock);
    CleanupState state = cleanup_request.state;
    if (state == STATE_LOADED) {
        strncpy(cleanup_request.target_record, record,
                sizeof(cleanup_request.target_record) - 1);
        cleanup_request.target_record[sizeof(cleanup_request.target_record) - 1] = '\0';
        memset(cleanup_request.approval_signature, 0,
               sizeof(cleanup_request.approval_signature));
        cleanup_request.approval_valid = 0;
        pthread_mutex_unlock(&request_lock);
        send_text(fd,
            "[+] Cleanup target updated.\n"
            "[i] Existing administrator approval invalidated.\n");
        return;
    }

    /* BUG: target updates remain available during validation. */
    if (state == STATE_VALIDATING) {
        uint32_t supplied_version;
        if (!parse_snapshot_version(version_option, version_text,
                                    &supplied_version) ||
            !cleanup_request.snapshot_version ||
            supplied_version != cleanup_request.snapshot_version) {
            pthread_mutex_unlock(&request_lock);
            send_text(fd, "[-] Snapshot version does not match.\n");
            return;
        }
        if (cleanup_request.version_used) {
            pthread_mutex_unlock(&request_lock);
            send_text(fd, "[-] Snapshot version has already been consumed.\n");
            return;
        }
        cleanup_request.version_used = 1;
        strncpy(cleanup_request.target_record, record,
                sizeof(cleanup_request.target_record) - 1);
        cleanup_request.target_record[sizeof(cleanup_request.target_record) - 1] = '\0';
        pthread_cond_signal(&current_team->snapshot_ready);
        pthread_mutex_unlock(&request_lock);
        send_text(fd, "[+] Cleanup target updated.\n");
        return;
    }
    pthread_mutex_unlock(&request_lock);
    send_text(fd, "[-] Cleanup target is locked in the current state.\n");
}

static void inspect_cleanup(int fd, const char *cleanup_id) {
    if (!cleanup_id || strcmp(cleanup_id, "CLN-0007")) {
        send_text(fd, "[-] Unknown cleanup request.\n");
        return;
    }
    CleanupState state;
    uint32_t version;
    pthread_mutex_lock(&request_lock);
    state = cleanup_request.state;
    version = state == STATE_VALIDATING && !cleanup_request.version_used
        ? cleanup_request.snapshot_version : 0;
    pthread_mutex_unlock(&request_lock);

    send_format(fd,
        "Cleanup ID       : CLN-0007\n"
        "Coordinator state: %s\n"
        "Snapshot version : %s",
        state_name(state), version ? "" : "-\n");
    if (version)
        send_format(fd, "%u\n", version);
}

static void commit_cleanup(int fd) {
    pthread_mutex_lock(&request_lock);
    if (cleanup_request.state != STATE_LOADED) {
        pthread_mutex_unlock(&request_lock);
        send_text(fd, "[-] Load a ready cleanup request first.\n");
        return;
    }
    cleanup_request.state = STATE_QUEUED;
    pthread_mutex_unlock(&request_lock);

    pthread_t worker;
    if (pthread_create(&worker, NULL, cleanup_worker, current_team) != 0) {
        pthread_mutex_lock(&request_lock);
        cleanup_request.state = STATE_REJECTED;
        pthread_mutex_unlock(&request_lock);
        send_text(fd, "[-] Cleanup worker could not be started.\n");
        return;
    }
    send_text(fd, "[+] Cleanup request submitted for validation.\n");
    /*
     * The coordinator waits for the storage worker before returning control to
     * this client.  A second operator session can still inspect or retarget the
     * shared request while validation is in progress.
     */
    pthread_join(worker, NULL);
}

static void send_flag_if_deleted(int fd) {
    char approved_record[MAX_RECORD];
    pthread_mutex_lock(&request_lock);
    int intended_result =
        protected_record_deleted &&
        cleanup_request.state == STATE_FINISHED &&
        cleanup_request.approval_valid &&
        valid_record(last_verified_record) &&
        strcmp(last_verified_record, TARGET_RECORD) &&
        !strcmp(last_deleted_record, TARGET_RECORD);
    memcpy(approved_record, last_verified_record, sizeof(approved_record));
    pthread_mutex_unlock(&request_lock);
    if (!intended_result)
        return;
    int flag_fd = open(FLAG_FILE, O_RDONLY);
    if (flag_fd < 0)
        return;
    char flag[128];
    ssize_t count = read(flag_fd, flag, sizeof(flag) - 1);
    close(flag_fd);
    if (count <= 0)
        return;
    flag[count] = '\0';
    send_format(fd,
        "\n[INTEGRITY ALERT]\n"
        "Approved record : %s\n"
        "Deleted record  : %s\n"
        "Result          : RECORD MISMATCH\n"
        "\n[DELETION MONITOR]\n"
        "Protected footage is no longer available.\n",
        approved_record, TARGET_RECORD);
    send_text(fd, flag);
    if (flag[count - 1] != '\n')
        send_text(fd, "\n");
}

static void show_cleanup_status(int fd) {
    char approved[MAX_RECORD];
    char target[MAX_RECORD];
    CleanupState state;
    int approval_valid;
    pthread_mutex_lock(&request_lock);
    memcpy(approved, cleanup_request.approved_record, sizeof(approved));
    memcpy(target, cleanup_request.target_record, sizeof(target));
    state = cleanup_request.state;
    approval_valid = cleanup_request.approval_valid;
    pthread_mutex_unlock(&request_lock);

    send_format(fd,
        "Cleanup ID      : %s\n"
        "Approved record : %s\n"
        "Target record   : %s\n"
        "Approval        : %s\n"
        "State           : %s\n",
        state == STATE_EMPTY ? "-" : "CLN-0007",
        approved[0] ? approved : "-",
        target[0] ? target : "-",
        approval_valid ? "VALID" : "INVALID",
        state_name(state));
    send_flag_if_deleted(fd);
}

static void show_audit(int fd) {
    pthread_mutex_lock(&request_lock);
    if (!last_verified_record[0]) {
        pthread_mutex_unlock(&request_lock);
        send_text(fd, "No completed cleanup audit records.\n");
        return;
    }
    char verified[MAX_RECORD];
    char deleted[MAX_RECORD];
    memcpy(verified, last_verified_record, sizeof(verified));
    memcpy(deleted, last_deleted_record, sizeof(deleted));
    pthread_mutex_unlock(&request_lock);
    send_format(fd,
        "APPROVED  %s\n"
        "DELETED   %s\n",
        verified, deleted);
}

static int parse_snapshot_name(const char *name,
                               char camera[8], char timestamp[20]) {
    static const char suffix[] = "-Snapshot.png";
    if (strlen(name) != 34 || strncmp(name, "CAM", 3) ||
        name[6] != '-' || strcmp(name + 21, suffix))
        return 0;
    for (size_t index = 3; index < 6; index++) {
        if (!isdigit((unsigned char)name[index]))
            return 0;
    }
    for (size_t index = 7; index < 21; index++) {
        if (!isdigit((unsigned char)name[index]) && name[index] != 'x')
            return 0;
    }
    snprintf(camera, 8, "CAM-%.3s", name + 3);
    snprintf(timestamp, 20, "%.4s-%.2s-%.2s %.2s:%.2s:%.2s",
             name + 7, name + 11, name + 13,
             name + 15, name + 17, name + 19);
    return 1;
}

static void list_archive(int fd) {
    send_text(fd,
        "RECORD                                  CAMERA    TIME                  STATE\n");
    for (size_t index = 0; index < asset_count; index++) {
        const char *record = asset_records[index];
        const char *state = !strcmp(record, TARGET_RECORD) ?
                            "PROTECTED" : "EXPIRED";
        char camera[8] = "UNKNOWN";
        char timestamp[20] = "-";
        (void)parse_snapshot_name(record, camera, timestamp);
        send_format(fd, "%-39s %-8s  %-19s  %s\n",
                    record, camera, timestamp, state);
    }
}

static void list_cleanup_candidates(int fd) {
    send_text(fd,
        "CLEANUP ID  APPROVABLE RECORD                         STATE\n");
    for (size_t index = 0; index < asset_count; index++) {
        if (!strcmp(asset_records[index], TARGET_RECORD))
            continue;
        send_format(fd, "CLN-0007   %-39s READY\n", asset_records[index]);
    }
}

static void print_main_help(int fd) {
    send_text(fd,
        "Available command groups:\n"
        "  system      Server and archive status\n"
        "  archive     CCTV footage records\n"
        "  cleanup     Approved cleanup requests\n"
        "  audit       Cleanup audit history\n"
        "  auth        Session authentication\n"
        "\n  help <group>     Show commands in a group\n"
        "  exit             Disconnect\n");
}

static void print_group_help(int fd, const char *group) {
    if (!group) {
        print_main_help(fd);
    } else if (!strcmp(group, "system")) {
        send_text(fd, "system status | system version\n");
    } else if (!strcmp(group, "archive")) {
        send_text(fd, "archive list | archive show <record-id>\n");
    } else if (!strcmp(group, "cleanup")) {
        send_text(fd,
            "cleanup list | cleanup load <cleanup-id> [record-name]\n"
            "cleanup inspect <cleanup-id>\n"
            "cleanup retarget <storage-handle> [--if-version <version>]\n"
            "cleanup commit | cleanup status\n");
    } else if (!strcmp(group, "audit")) {
        send_text(fd, "audit show\n");
    } else if (!strcmp(group, "auth")) {
        send_text(fd, "auth status | auth login\n");
    } else {
        send_text(fd, "[-] Unknown command group.\n");
    }
}

static int external_authenticate(const char *token) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, AUTH_SOCKET, sizeof(address.sun_path) - 1);
    int result = 0;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0 &&
        send(fd, token, strlen(token), MSG_NOSIGNAL) == (ssize_t)strlen(token)) {
        unsigned char response = 0;
        if (recv(fd, &response, 1, 0) == 1)
            result = response == 1;
    }
    close(fd);
    return result;
}

static void dispatch_command(int fd, char *line) {
    char *save = NULL;
    char *group = strtok_r(line, " ", &save);
    char *sub = strtok_r(NULL, " ", &save);
    char *arg = strtok_r(NULL, " ", &save);
    char *arg2 = strtok_r(NULL, " ", &save);
    char *arg3 = strtok_r(NULL, " ", &save);
    if (!group)
        return;

    if (!strcmp(group, "help")) {
        print_group_help(fd, sub);
    } else if (!strcmp(group, "system")) {
        if (sub && !strcmp(sub, "status"))
            send_text(fd,
                "Server           : CCTV-CLEANUP-01\n"
                "Archive          : ONLINE\n"
                "Cleanup worker   : ONLINE\n"
                "Deletion monitor : ACTIVE\n");
        else if (sub && !strcmp(sub, "version"))
            send_text(fd, "UOS CCTV Cleanup Coordinator 2.4.0\n");
        else
            send_text(fd, "[-] Usage: system status|version\n");
    } else if (!strcmp(group, "archive")) {
        if (sub && !strcmp(sub, "list"))
            list_archive(fd);
        else if (sub && !strcmp(sub, "show") && valid_record(arg))
            send_format(fd,
                "Record ID     : %s\n"
                "Delete access : %s\n",
                arg, !strcmp(arg, TARGET_RECORD) ? "ADMIN" : "APPROVED CLEANUP ONLY");
        else
            send_text(fd, "[-] Usage: archive list | archive show <record-id>\n");
    } else if (!strcmp(group, "cleanup")) {
        if (sub && !strcmp(sub, "list"))
            list_cleanup_candidates(fd);
        else if (sub && !strcmp(sub, "load"))
            load_cleanup_request(fd, arg, arg2);
        else if (sub && !strcmp(sub, "inspect"))
            inspect_cleanup(fd, arg);
        else if (sub && !strcmp(sub, "retarget"))
            retarget_cleanup(fd, arg, arg2, arg3);
        else if (sub && !strcmp(sub, "commit"))
            commit_cleanup(fd);
        else if (sub && !strcmp(sub, "status"))
            show_cleanup_status(fd);
        else
            send_text(fd,
                "[-] Usage: cleanup list\n"
                "           cleanup load <cleanup-id> [record-name]\n"
                "           cleanup inspect <cleanup-id>\n"
                "           cleanup retarget <storage-handle> [--if-version <version>]\n"
                "           cleanup commit | cleanup status\n");
    } else if (!strcmp(group, "audit")) {
        if (sub && !strcmp(sub, "show"))
            show_audit(fd);
        else
            send_text(fd, "[-] Usage: audit show\n");
    } else if (!strcmp(group, "auth")) {
        if (sub && !strcmp(sub, "status"))
            send_text(fd, "User: cctv_operator\nRole: OPERATOR\nProvider: UOS-AUTH\n");
        else if (sub && !strcmp(sub, "login")) {
            send_text(fd, "Administrator token: ");
            char token[96];
            if (receive_line(fd, token, sizeof(token)))
                send_text(fd, external_authenticate(token)
                    ? "[+] Authentication accepted.\n"
                    : "[-] Authentication failed.\n");
        } else
            send_text(fd, "[-] Usage: auth status|login\n");
    } else {
        send_text(fd, "[-] Unknown command. Type 'help'.\n");
    }
}

static void *client_worker(void *argument) {
    ClientContext *context = argument;
    int fd = context->fd;
    free(context);
    socket_timeout(fd, auth_timeout_seconds);

    char token[MAX_TOKEN];
    send_text(fd, "Team token: ");
    if (!receive_line(fd, token, sizeof(token))) {
        goto done;
    }
    const char *ctfd_url = getenv("CTFD_BASE_URL");
    if (ctfd_url && ctfd_url[0]) {
        char team_id[32];
        current_team = ctfd_team_id(token, team_id, sizeof(team_id))
            ? find_or_create_ctfd_team(team_id) : NULL;
    } else {
        current_team = find_team(token);
    }
    if (!current_team) {
        send_text(fd, "[-] Invalid team token.\n");
        goto done;
    }

    socket_timeout(fd, idle_timeout_seconds);

    send_text(fd,
        "UOS CCTV Cleanup Coordinator 2.4.0\n"
        "Connected node : CCTV-CLEANUP-01\n"
        "Session user   : cctv_operator\n"
        "Session role   : OPERATOR\n");
    send_format(fd, "Team workspace : %s\n", current_team->team_id);
    send_text(fd, "\nType 'help' for available commands.\n\n");

    char line[MAX_LINE];
    while (1) {
        if (!send_text(fd, "cleanup> "))
            break;
        if (!receive_line(fd, line, sizeof(line)))
            break;
        if (!strcmp(line, "exit") || !strcmp(line, "quit"))
            break;
        dispatch_command(fd, line);
        persist_current_team();
        send_text(fd, "\n");
    }
done:
    close(fd);
    pthread_mutex_lock(&connections_lock);
    if (active_connections)
        active_connections--;
    pthread_mutex_unlock(&connections_lock);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    max_active_connections = environment_uint(
        "MAX_ACTIVE_CONNECTIONS", 128, 30, 1024);
    max_concurrent_auth = environment_uint(
        "MAX_CONCURRENT_AUTH", 8, 1, 32);
    auth_timeout_seconds = environment_uint(
        "AUTH_TIMEOUT_SECONDS", 15, 3, 120);
    idle_timeout_seconds = environment_uint(
        "IDLE_TIMEOUT_SECONDS", 300, 30, 3600);
    int port = DEFAULT_PORT;
    if (argc == 2) {
        long parsed = strtol(argv[1], NULL, 10);
        if (parsed > 0 && parsed <= 65535)
            port = (int)parsed;
    }

    const char *ctfd_url = getenv("CTFD_BASE_URL");
    if (!load_assets() || ((!ctfd_url || !ctfd_url[0]) && !load_teams()))
        return 1;
    for (size_t index = 0; index < team_count; index++) {
        current_team = &teams[index];
        if (!initialize_archive())
            return 1;
        restore_current_team();
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0)
        return 1;
    int enabled = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0)
        return 1;
    if (listen(server, 64) != 0)
        return 1;

    while (1) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        pthread_mutex_lock(&connections_lock);
        if (active_connections >= max_active_connections) {
            pthread_mutex_unlock(&connections_lock);
            send_text(client, "[-] Server is busy. Try again shortly.\n");
            close(client);
            continue;
        }
        active_connections++;
        pthread_mutex_unlock(&connections_lock);
        ClientContext *context = malloc(sizeof(*context));
        if (!context) {
            close(client);
            pthread_mutex_lock(&connections_lock);
            active_connections--;
            pthread_mutex_unlock(&connections_lock);
            continue;
        }
        context->fd = client;
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_worker, context) != 0) {
            close(client);
            free(context);
            pthread_mutex_lock(&connections_lock);
            active_connections--;
            pthread_mutex_unlock(&connections_lock);
            continue;
        }
        pthread_detach(thread);
    }
    close(server);
    return 0;
}
