#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define OBJECT_SIZE 0x30
#define NOTE_SIZE 24
#define LINE_SIZE 256
#define DELETED_DIR "/home/ctf/[Deleted]"
#define AUTH_SOCKET "/run/uos-auth.sock"

typedef struct RecoveryJob RecoveryJob;
typedef void (*recovery_handler_t)(RecoveryJob *);

struct RecoveryJob {
    char camera[24];
    recovery_handler_t handler;
    uint64_t segment_id;
    uint64_t status;
};

typedef struct {
    char message[24];
    unsigned char reserved[24];
} RecoveryNote;

typedef struct {
    char profile_name[16];
    char codec[8];
    recovery_handler_t handler;
    uint64_t segment_id;
    uint32_t flags;
    uint32_t checksum;
} RecoveryProfile;

_Static_assert(sizeof(RecoveryJob) == OBJECT_SIZE, "RecoveryJob size mismatch");
_Static_assert(sizeof(RecoveryNote) == OBJECT_SIZE, "RecoveryNote size mismatch");
_Static_assert(sizeof(RecoveryProfile) == OBJECT_SIZE, "RecoveryProfile size mismatch");

static RecoveryJob *active_job;
static RecoveryJob *queued_job;
static RecoveryNote *active_note;
static RecoveryProfile *active_profile;
static int job_exists;
static int audit_rotated;
static int auth_attempts;

static ssize_t read_line_raw(void *dst, size_t max_len) {
    unsigned char *buf = dst;
    size_t used = 0;

    while (used < max_len) {
        unsigned char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == 0)
            return used ? (ssize_t)used : 0;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (c == '\n')
            break;
        if (c != '\r')
            buf[used++] = c;
    }
    return (ssize_t)used;
}

static int read_line(char *dst, size_t size) {
    if (size == 0)
        return -1;
    ssize_t n = read_line_raw(dst, size - 1);
    if (n < 0)
        return -1;
    dst[n] = '\0';
    return (int)n;
}

static int read_line_capped(char *dst, size_t capacity, size_t limit) {
    if (!capacity || limit >= capacity)
        return -1;
    size_t used = 0;
    while (1) {
        unsigned char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (c == '\n')
            break;
        if (c != '\r' && used < limit)
            dst[used++] = (char)c;
    }
    dst[used] = '\0';
    return (int)used;
}

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_profile_hex(const char *input, unsigned char output[OBJECT_SIZE]) {
    if (strlen(input) != OBJECT_SIZE * 2)
        return 0;
    for (size_t i = 0; i < OBJECT_SIZE; i++) {
        int high = hex_value((unsigned char)input[i * 2]);
        int low = hex_value((unsigned char)input[i * 2 + 1]);
        if (high < 0 || low < 0)
            return 0;
        output[i] = (unsigned char)((high << 4) | low);
    }
    return 1;
}

__attribute__((noinline, used))
static void operator_recovery(RecoveryJob *job) {
    (void)job;
    puts("Checking archive permissions...");
    puts("Current role  : OPERATOR");
    puts("Required role : ADMIN");
    puts("[-] Cold archive access denied.");
}

__attribute__((noinline, used))
static void restore_deleted_snapshots(RecoveryJob *job) {
    if (!job || job->segment_id != 0x09182326ULL) {
        puts("[-] Recovery profile does not match an archived segment.");
        return;
    }
    puts("[RECOVERY] Cold-storage index matched: SEG-09182326");
    puts("[RECOVERY] Reconstructing incident snapshots... 100%");
    puts("[RECOVERY] Snapshot integrity: OK");
    printf("[RECOVERY] Restored files: %s\n", DELETED_DIR);
    puts("[RECOVERY] Maintenance shell granted.");

    char *const shell_argv[] = {"/bin/sh", "-i", NULL};
    char *const shell_envp[] = {
        "HOME=/home/ctf",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };
    execve(shell_argv[0], shell_argv, shell_envp);
    puts("[-] Failed to start the maintenance shell.");
}

__attribute__((noinline, used))
static uint32_t recovery_profile_checksum(const RecoveryProfile *profile) {
    const unsigned char *bytes = (const unsigned char *)profile;
    uint32_t value = 0x52454356U;
    for (size_t index = 0; index < 44; index++) {
        value ^= bytes[index];
        value *= 0x01000193U;
        value = (value << 5) | (value >> 27);
    }
    return value ^ 0xa17c9e3bU;
}

static int valid_recovery_profile(const RecoveryProfile *profile) {
    static const char expected_name[16] = "cold-restore";
    static const char expected_codec[8] = "raw-v1";
    return profile &&
        !memcmp(profile->profile_name, expected_name, sizeof(expected_name)) &&
        !memcmp(profile->codec, expected_codec, sizeof(expected_codec)) &&
        profile->handler == (recovery_handler_t)restore_deleted_snapshots &&
        profile->segment_id == 0x09182326ULL &&
        profile->flags == 1 &&
        profile->checksum == recovery_profile_checksum(profile);
}

static int request_external_auth(const char *token) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, AUTH_SOCKET, sizeof(address.sun_path) - 1);

    int ok = 0;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        uint16_t length = htons((uint16_t)strlen(token));
        if (write(fd, &length, sizeof(length)) == sizeof(length) &&
            write(fd, token, strlen(token)) == (ssize_t)strlen(token)) {
            unsigned char result = 0;
            if (read(fd, &result, 1) == 1)
                ok = result == 1;
        }
    }
    close(fd);
    return ok;
}

static void print_main_help(void) {
    puts("Available command groups:");
    puts("  system      Server and storage status");
    puts("  camera      Registered CCTV cameras");
    puts("  archive     Recorded footage archive");
    puts("  job         Recovery job management");
    puts("  audit       Recovery audit records");
    puts("  profile     Recovery profile management");
    puts("  auth        Session authentication");
    puts("\n  help <group>     Show commands in a group");
    puts("  exit             Disconnect");
}

static void print_group_help(const char *group) {
    if (!group) {
        print_main_help();
    } else if (!strcmp(group, "system")) {
        puts("system status | system storage | system version");
    } else if (!strcmp(group, "camera")) {
        puts("camera list | camera show <camera-id>");
    } else if (!strcmp(group, "archive")) {
        puts("archive search <camera> <date>");
        puts("archive info <segment-id> | archive preview <segment-id>");
    } else if (!strcmp(group, "job")) {
        puts("job create <segment-id> | job list | job show <job-id>");
        puts("job resume <job-id> | job cancel <job-id>");
    } else if (!strcmp(group, "audit")) {
        puts("audit list | audit show <job-id> [--raw]");
        puts("audit note <job-id> | audit rotate <job-id>");
    } else if (!strcmp(group, "profile")) {
        puts("profile list | profile show <profile-name>");
        puts("profile apply <job-id>");
    } else if (!strcmp(group, "auth")) {
        puts("auth status | auth login | auth logout");
    } else {
        puts("[-] Unknown command group.");
    }
}

static void command_system(char *sub) {
    if (sub && !strcmp(sub, "status")) {
        puts("Server         : FRAMEVAULT-02");
        puts("Service        : ONLINE");
        puts("Archive        : DEGRADED");
        printf("Recovery queue : %d job(s)\n", job_exists ? 1 : 0);
        puts("Audit database : ONLINE");
        puts("Authentication : UOS-AUTH");
    } else if (sub && !strcmp(sub, "storage")) {
        puts("VOLUME          USAGE    STATUS");
        puts("/archive/live   71.2%    ONLINE");
        puts("/archive/cold   84.7%    RESTRICTED");
        puts("/archive/tmp    12.4%    ONLINE");
    } else if (sub && !strcmp(sub, "version")) {
        puts("UOS CCTV Recovery Server 4.8.2");
    } else {
        puts("[-] Usage: system status|storage|version");
    }
}

static void command_camera(char *sub, char *arg) {
    if (sub && !strcmp(sub, "list")) {
        puts("CAMERA    LOCATION              STATUS");
        puts("CAM-071   Main Entrance         ONLINE");
        puts("CAM-073   Faculty Office Hall   ONLINE");
        puts("CAM-075   Research Hall         WARNING");
        puts("CAM-077   East Stairway         OFFLINE");
    } else if (sub && !strcmp(sub, "show") && arg) {
        printf("Camera ID       : %s\n", arg);
        puts("Storage node    : FRAMEVAULT-02");
        puts("Retention       : 30 days");
        puts("Last sync       : 2026-09-18 23:31:04");
    } else {
        puts("[-] Usage: camera list | camera show <camera-id>");
    }
}

static int valid_segment(const char *segment) {
    return segment && !strcmp(segment, "SEG-09182326");
}

static int valid_job(const char *job) {
    return job_exists && job && !strcmp(job, "JOB-0075");
}

static void command_archive(char *sub, char *arg1, char *arg2) {
    if (sub && !strcmp(sub, "search") && arg1 && arg2) {
        puts("SEGMENT         CAMERA    CAPTURE TIME   TYPE       STATUS");
        puts("SEG-09182305    CAM-073   23:05:11       SNAPSHOT   AVAILABLE");
        puts("SEG-09182326    CAM-075   23:26:20       SNAPSHOT   DELETED");
    } else if (sub && !strcmp(sub, "info") && valid_segment(arg1)) {
        puts("Segment ID      : SEG-09182326");
        puts("Camera          : CAM-075");
        puts("Snapshot time   : 2026-09-18 23:26:20");
        puts("Primary copy    : DELETED");
        puts("Cold copy       : LOCKED");
        puts("Deletion time   : 2026-09-18 23:31:02");
    } else if (sub && !strcmp(sub, "preview") && valid_segment(arg1)) {
        puts("[-] Preview unavailable. The primary recording has been deleted.");
    } else {
        puts("[-] Usage: archive search <camera> <date>");
        puts("           archive info|preview <segment-id>");
    }
}

static void create_job(const char *segment) {
    if (!valid_segment(segment)) {
        puts("[-] Unknown or non-recoverable segment.");
        return;
    }
    if (job_exists) {
        puts("[-] A recovery job already exists for this segment.");
        return;
    }

    active_job = malloc(sizeof(*active_job));
    if (!active_job)
        exit(1);
    memset(active_job, 0, sizeof(*active_job));
    memcpy(active_job->camera, "CAM-075", 8);
    active_job->handler = operator_recovery;
    active_job->segment_id = 0x09182326ULL;
    active_job->status = 1;
    queued_job = active_job;
    job_exists = 1;

    puts("Recovery job created.");
    puts("Job ID : JOB-0075");
    puts("State  : WAITING");
}

static void cancel_job(void) {
    if (!job_exists) {
        puts("[-] No recovery job exists.");
        return;
    }
    if (active_job)
        free(active_job);
    else if (active_note)
        free(active_note);
    else if (active_profile)
        free(active_profile);
    active_job = NULL;
    active_note = NULL;
    active_profile = NULL;
    queued_job = NULL;
    job_exists = 0;
    audit_rotated = 0;
    puts("[+] Recovery job cancelled and removed from the queue.");
}

static void command_job(char *sub, char *arg) {
    if (sub && !strcmp(sub, "create")) {
        create_job(arg);
    } else if (sub && !strcmp(sub, "list")) {
        if (job_exists)
            puts("JOB-0075   SEG-09182326   OBSOLETE   QUEUED");
        else
            puts("No recovery jobs.");
    } else if (sub && !strcmp(sub, "show") && valid_job(arg)) {
        puts("Job ID      : JOB-0075");
        puts("Owner       : cctv_operator");
        puts("Segment     : SEG-09182326");
        puts("Profile     : standard-h264");
        printf("State       : %s\n", audit_rotated ? "OBSOLETE" : "WAITING");
        puts("Queue state : WAITING");
    } else if (sub && !strcmp(sub, "resume") && valid_job(arg)) {
        if (!queued_job) {
            puts("[-] Recovery queue is empty.");
            return;
        }
        /*
         * Only the original job or a fully materialized recovery profile is a
         * valid queue object.  This keeps a short note overwrite from becoming
         * an alternate partial-pointer exploit while preserving the intended
         * Job -> Note -> Profile type-confusion chain.
         */
        if (queued_job->handler == operator_recovery) {
            if (active_job != queued_job) {
                puts("[-] Queue object type does not match the recovery handler.");
                return;
            }
        } else if (queued_job->handler == restore_deleted_snapshots) {
            if (!audit_rotated || active_note ||
                active_profile != (RecoveryProfile *)queued_job ||
                !valid_recovery_profile(active_profile)) {
                puts("[-] Recovery profile validation failed.");
                return;
            }
        } else {
            puts("[-] Unsupported recovery handler rejected.");
            return;
        }
        queued_job->handler(queued_job);
    } else if (sub && !strcmp(sub, "cancel") && valid_job(arg)) {
        cancel_job();
    } else {
        puts("[-] Usage: job create <segment-id> | job list");
        puts("           job show|resume|cancel <job-id>");
    }
}

static void show_audit_text(void) {
    puts("2026-09-18 23:31:02  Snapshot deletion detected");
    puts("2026-09-18 23:31:03  Cold copy located");
    puts("2026-09-18 23:31:04  Recovery job created");
    puts("2026-09-18 23:31:05  Job marked obsolete");
}

static void show_raw_note(void) {
    if (!active_note) {
        puts("[-] No operator note is attached to this record.");
        return;
    }
    puts("RAW-LENGTH: 48");
    puts("----- BEGIN RAW AUDIT RECORD -----");
    write(STDOUT_FILENO, active_note, sizeof(*active_note));
    write(STDOUT_FILENO, "\n", 1);
    puts("----- END RAW AUDIT RECORD -----");
}

static void rotate_audit(void) {
    if (!active_job || audit_rotated) {
        puts("[-] No obsolete audit context is available for rotation.");
        return;
    }
    free(active_job);
    active_job = NULL;
    audit_rotated = 1;
    puts("Rotating obsolete audit record...");
    puts("1 record removed.");
}

static void add_note(void) {
    if (!audit_rotated || active_note || active_profile) {
        puts("[-] This audit record cannot accept a new note.");
        return;
    }
    active_note = malloc(sizeof(*active_note));
    if (!active_note)
        exit(1);
    char note_input[NOTE_SIZE + 1];
    printf("Note: ");
    int n = read_line_capped(note_input, sizeof(note_input), NOTE_SIZE);
    if (n < 0)
        exit(1);
    memcpy(active_note->message, note_input, (size_t)n);
    if (n < NOTE_SIZE)
        memset(active_note->message + n, 0, NOTE_SIZE - (size_t)n);
    puts("Audit note attached.");
}

static void command_audit(char *sub, char *arg, char *option) {
    if (sub && !strcmp(sub, "list")) {
        if (job_exists)
            puts("JOB-0075   2026-09-18 23:31:05   OBSOLETE");
        else
            puts("No audit records.");
    } else if (sub && !strcmp(sub, "show") && valid_job(arg)) {
        if (option && !strcmp(option, "--raw"))
            show_raw_note();
        else
            show_audit_text();
    } else if (sub && !strcmp(sub, "rotate") && valid_job(arg)) {
        rotate_audit();
    } else if (sub && !strcmp(sub, "note") && valid_job(arg)) {
        add_note();
    } else {
        puts("[-] Usage: audit list | audit show <job-id> [--raw]");
        puts("           audit note|rotate <job-id>");
    }
}

static void apply_profile(const char *job) {
    if (!valid_job(job) || !active_note) {
        puts("[-] A recovery job with an operator note is required.");
        return;
    }

    char name[64];
    char encoded[OBJECT_SIZE * 2 + 2];
    printf("Profile name: ");
    if (read_line(name, sizeof(name)) <= 0)
        return;
    if (strcmp(name, "custom-recovery")) {
        puts("[-] Profile unavailable for the current role.");
        return;
    }
    printf("Profile data (96 hex characters): ");
    if (read_line(encoded, sizeof(encoded)) <= 0)
        return;

    unsigned char decoded[OBJECT_SIZE];
    if (!decode_profile_hex(encoded, decoded)) {
        puts("[-] Invalid recovery profile data.");
        return;
    }

    free(active_note);
    active_note = NULL;
    active_profile = malloc(sizeof(*active_profile));
    if (!active_profile)
        exit(1);
    memcpy(active_profile, decoded, sizeof(*active_profile));
    puts("Recovery profile applied to JOB-0075.");
}

static void command_profile(char *sub, char *arg) {
    if (sub && !strcmp(sub, "list")) {
        puts("PROFILE               CODEC    ACCESS");
        puts("standard-h264         H.264    OPERATOR");
        puts("damaged-frame-scan    AUTO     OPERATOR");
        puts("cold-storage-restore  RAW      ADMIN");
        puts("custom-recovery       RAW      OPERATOR");
    } else if (sub && !strcmp(sub, "show") && arg) {
        printf("Profile : %s\n", arg);
        puts("Purpose : CCTV deleted-snapshot recovery");
    } else if (sub && !strcmp(sub, "apply")) {
        apply_profile(arg);
    } else {
        puts("[-] Usage: profile list | profile show <name>");
        puts("           profile apply <job-id>");
    }
}

static void command_auth(char *sub) {
    if (sub && !strcmp(sub, "status")) {
        puts("User     : cctv_operator");
        puts("Role     : OPERATOR");
        puts("Provider : UOS-AUTH");
    } else if (sub && !strcmp(sub, "login")) {
        if (auth_attempts >= 3) {
            puts("[-] Authentication temporarily locked for this session.");
            return;
        }
        char token[96];
        printf("Administrator token: ");
        if (read_line(token, sizeof(token)) <= 0)
            return;
        auth_attempts++;
        if (request_external_auth(token))
            puts("[+] Authentication accepted.");
        else
            puts("[-] Authentication failed.");
    } else if (sub && !strcmp(sub, "logout")) {
        puts("[+] Session remains authenticated as cctv_operator.");
    } else {
        puts("[-] Usage: auth status|login|logout");
    }
}

static void dispatch(char *line) {
    char *save = NULL;
    char *group = strtok_r(line, " ", &save);
    char *sub = strtok_r(NULL, " ", &save);
    char *arg1 = strtok_r(NULL, " ", &save);
    char *arg2 = strtok_r(NULL, " ", &save);

    if (!group)
        return;
    if (!strcmp(group, "help"))
        print_group_help(sub);
    else if (!strcmp(group, "system"))
        command_system(sub);
    else if (!strcmp(group, "camera"))
        command_camera(sub, arg1);
    else if (!strcmp(group, "archive"))
        command_archive(sub, arg1, arg2);
    else if (!strcmp(group, "job"))
        command_job(sub, arg1);
    else if (!strcmp(group, "audit"))
        command_audit(sub, arg1, arg2);
    else if (!strcmp(group, "profile"))
        command_profile(sub, arg1);
    else if (!strcmp(group, "auth"))
        command_auth(sub);
    else
        puts("[-] Unknown command. Type 'help'.");
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("UOS FrameVault Recovery Server 4.8.2");
    puts("Connected node : FRAMEVAULT-02");
    puts("Session user   : cctv_operator");
    puts("Session role   : OPERATOR");
    puts("\nType 'help' for available commands.\n");

    char line[LINE_SIZE];
    while (1) {
        printf("framevault> ");
        int length = read_line(line, sizeof(line));
        if (length <= 0)
            break;
        if (!strcmp(line, "exit") || !strcmp(line, "quit"))
            break;
        dispatch(line);
        putchar('\n');
    }
    puts("Disconnected.");
    return 0;
}
