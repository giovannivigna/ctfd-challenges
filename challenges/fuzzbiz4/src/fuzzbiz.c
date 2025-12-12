#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PAYLOAD_SIZE 4096
#define MAX_COMMAND_LEN 64
#define MAGIC_NUMBER "\xDE\xAD\xBE\xEF"
#define PROTOCOL_VERSION_MAJOR 4
#define PROTOCOL_VERSION_MINOR 1

#define SECTION_METADATA 1
#define SECTION_COMMAND  2
#define SECTION_DATA     3

typedef struct {
    uint8_t magic[4]; 
    uint8_t version_major; 
    uint8_t version_minor;
    uint16_t payload_length;
} PacketHeader;

typedef struct {
    uint16_t section_length;
    uint8_t section_type;
    uint8_t data[];
} PacketSection;

typedef struct {
    int authenticated;
    int error_count;
    char last_command[MAX_COMMAND_LEN];
} SessionState;

void init_session(SessionState *session) {
    session->authenticated = 0;
    session->error_count = 0;
    memset(session->last_command, 0, sizeof(session->last_command));
}

void authenticate(SessionState *session) {
    session->authenticated = 1;
}

void log_command(SessionState *session, const char *cmd) {
    strncpy(session->last_command, cmd, MAX_COMMAND_LEN - 1); 
}

int validate_header(const PacketHeader *hdr) {
    return memcmp(hdr->magic, MAGIC_NUMBER, 4) == 0 &&
           hdr->version_major == PROTOCOL_VERSION_MAJOR &&
           hdr->version_minor == PROTOCOL_VERSION_MINOR &&
           hdr->payload_length <= MAX_PAYLOAD_SIZE;
}

void handle_command(SessionState *session, const uint8_t *data, size_t len) {
    char command[MAX_COMMAND_LEN];

    if (len >= MAX_COMMAND_LEN) {
        memcpy(command, data, MAX_COMMAND_LEN - 1);
        command[MAX_COMMAND_LEN - 1] = '\0';  
    } else {
        memcpy(command, data, len);
        command[len] = '\0';
    }
    printf("Handling command: %s\n", command);
    if (session->authenticated) {
        if (strstr(command, "SECRET_CRASH")) {
            char *p = NULL;
            *p = 'X';  
        }
    }

    log_command(session, command);
}


void process_packet(const uint8_t *input, size_t input_len, SessionState *session) {
    if (input_len < sizeof(PacketHeader)) {
        fprintf(stderr, "Packet too short\n");
        session->error_count++;
        return;
    }

    PacketHeader hdr;
    memcpy(&hdr, input, sizeof(hdr));
    printf("Received header (length %lu) with magic %x %x %x %x, version %d.%d, payload length %d...\n", 
        sizeof(hdr), hdr.magic[0], hdr.magic[1], hdr.magic[2], hdr.magic[3], 
        hdr.version_major, hdr.version_minor, hdr.payload_length); 

    if (!validate_header(&hdr)) {
        fprintf(stderr, "Invalid header\n");
        session->error_count++;
        return;
    }

    size_t payload_len = hdr.payload_length;
    if (input_len < sizeof(hdr) + payload_len) {
        fprintf(stderr, "Payload too short\n");
        session->error_count++;
        return;
    }

    const uint8_t *payload = input + sizeof(hdr);
    size_t remaining = payload_len;

    while (remaining >= sizeof(PacketSection)) {
        PacketSection *section = (PacketSection *)payload;
        printf("Processing section (header of length %lu) with length %d type %d and data %s...\n", 
            sizeof(PacketSection), section->section_length, section->section_type, section->data);

        if (section->section_length > remaining - sizeof(PacketSection)) {
            fprintf(stderr, "Section too long\n");
            session->error_count++;
            break;
        }

        switch (section->section_type) {
            case SECTION_METADATA:
                printf("Metadata section\n");
                if (section->section_length == 7 && memcmp(section->data, "AUTHKEY", 7) == 0) {
                    authenticate(session);
                    printf("Authenticated\n");
                }
                break;

            case SECTION_COMMAND:
                handle_command(session, section->data, section->section_length);
                break;

            default:
                session->error_count++;
        }

        size_t section_size = sizeof(PacketSection) + section->section_length - 1;
        payload += section_size;
        remaining -= section_size;
    }
}


int main() {
    uint8_t buffer[sizeof(PacketHeader) + MAX_PAYLOAD_SIZE];
    size_t len = fread(buffer, 1, sizeof(buffer), stdin);

    printf("Read packet of length %lu\n", len);
    for (int i = 0; i < len; i++) {
        printf("0x%02x ", buffer[i]);
    }
    printf("\n");

    printf("Initializing session...\n");
    SessionState session;
    init_session(&session);

    printf("Starting processing packet...\n");
    process_packet(buffer, len, &session);
    printf("Ending packet processing...\n");

    if (session.error_count > 3) {
        fprintf(stderr, "Too many errors - malformed packet\n");
    }

    return 0;
}