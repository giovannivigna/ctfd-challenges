#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ENTRIES 100
#define MAX_LABEL_LEN 64
#define MAX_DATA_LEN 256

// Random padding to vary segment sizes
static char padding1[__PADDING_SIZE__] = {0};
static char secret[] = "__SECRET__";
static char padding2[__PADDING_SIZE__] = {0};

typedef struct {
    char label[MAX_LABEL_LEN];
    char data[MAX_DATA_LEN];
    int used;
} entry_t;

static entry_t entries[MAX_ENTRIES];
static int entry_count = 0;

// Two functions that call each other but are never called
void function_a(int x);
void function_b(int x);

static int global_counter = 0;
static char buffer[256];

void function_a(int x) {
    if (x <= 0) {
        return;
    }
    
    // Perform some calculations
    int temp = x * 7;
    temp = (temp << 3) ^ (temp >> 2);
    temp = temp & 0xFFFF;
    
    // String manipulation
    int len = snprintf(buffer, sizeof(buffer), "A:%d:%d", x, temp);
    if (len > 0 && len < sizeof(buffer)) {
        buffer[len] = '\0';
    }
    
    // Update global counter
    global_counter += (x % 17);
    global_counter = global_counter & 0xFF;
    
    // Conditional recursion
    if ((x & 1) == 0) {
        function_b(x - 1);
    } else {
        function_b(x / 2);
    }
    
    // More operations after recursion
    temp = temp ^ 0xABCD;
    global_counter = (global_counter + temp) & 0xFF;
}

void function_b(int x) {
    if (x <= 0) {
        return;
    }
    
    // Different calculations
    int temp = x * 13;
    temp = (temp >> 4) ^ (temp << 5);
    temp = temp & 0xFFFF;
    
    // Different string manipulation
    int len = snprintf(buffer, sizeof(buffer), "B:%d:%d", x, temp);
    if (len > 0 && len < sizeof(buffer)) {
        buffer[len] = '\0';
    }
    
    // Update global counter differently
    global_counter += (x % 23);
    global_counter = global_counter & 0xFF;
    
    // Different conditional recursion
    if ((x % 3) == 0) {
        function_a(x - 2);
    } else {
        function_a(x - 1);
    }
    
    // More operations after recursion
    temp = temp ^ 0xDCBA;
    global_counter = (global_counter - temp) & 0xFF;
}

int find_entry(const char *label) {
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (entries[i].used && strcmp(entries[i].label, label) == 0) {
            return i;
        }
    }
    return -1;
}

int add_entry(const char *label, const char *data) {
    if (entry_count >= MAX_ENTRIES) {
        return -1;
    }
    
    int idx = find_entry(label);
    if (idx >= 0) {
        // Update existing entry
        strncpy(entries[idx].data, data, MAX_DATA_LEN - 1);
        entries[idx].data[MAX_DATA_LEN - 1] = '\0';
        return 0;
    }
    
    // Add new entry
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (!entries[i].used) {
            strncpy(entries[i].label, label, MAX_LABEL_LEN - 1);
            entries[i].label[MAX_LABEL_LEN - 1] = '\0';
            strncpy(entries[i].data, data, MAX_DATA_LEN - 1);
            entries[i].data[MAX_DATA_LEN - 1] = '\0';
            entries[i].used = 1;
            entry_count++;
            return 0;
        }
    }
    return -1;
}

int delete_entry(const char *label) {
    int idx = find_entry(label);
    if (idx >= 0) {
        entries[idx].used = 0;
        entry_count--;
        return 0;
    }
    return -1;
}

void dump_entries(const char *password) {
    if (strcmp(password, secret) != 0) {
        printf("Invalid password!\n");
        return;
    }
    
    printf("=== Dump of all entries ===\n");
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (entries[i].used) {
            printf("%s:%s\n", entries[i].label, entries[i].data);
        }
    }
    printf("=== End of dump ===\n");
}

void parse_initial_data(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        char *colon = strchr(argv[i], ':');
        if (colon) {
            *colon = '\0';
            char *label = argv[i];
            char *data = colon + 1;
            add_entry(label, data);
        }
    }
}

int main(int argc, char *argv[]) {
    char buffer[512];
    char label[MAX_LABEL_LEN];
    char data[MAX_DATA_LEN];
    char password[MAX_DATA_LEN];
    
    // Parse initial data from command line
    parse_initial_data(argc, argv);
    
    printf("Welcome to the Data Store!\n");
    printf("Commands: store, read, delete, dump, quit\n");
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            break;
        }
        
        // Remove newline
        buffer[strcspn(buffer, "\n")] = '\0';
        
        if (strncmp(buffer, "store ", 6) == 0) {
            char *rest = buffer + 6;
            char *colon = strchr(rest, ':');
            if (colon) {
                *colon = '\0';
                strncpy(label, rest, MAX_LABEL_LEN - 1);
                label[MAX_LABEL_LEN - 1] = '\0';
                strncpy(data, colon + 1, MAX_DATA_LEN - 1);
                data[MAX_DATA_LEN - 1] = '\0';
                if (add_entry(label, data) == 0) {
                    printf("Stored: %s -> %s\n", label, data);
                } else {
                    printf("Error: Could not store entry\n");
                }
            } else {
                printf("Usage: store <label>:<data>\n");
            }
        } else if (strncmp(buffer, "read ", 5) == 0) {
            strncpy(label, buffer + 5, MAX_LABEL_LEN - 1);
            label[MAX_LABEL_LEN - 1] = '\0';
            int idx = find_entry(label);
            if (idx >= 0) {
                printf("%s\n", entries[idx].data);
            } else {
                printf("Label not found\n");
            }
        } else if (strncmp(buffer, "delete ", 7) == 0) {
            strncpy(label, buffer + 7, MAX_LABEL_LEN - 1);
            label[MAX_LABEL_LEN - 1] = '\0';
            if (delete_entry(label) == 0) {
                printf("Deleted: %s\n", label);
            } else {
                printf("Label not found\n");
            }
        } else if (strncmp(buffer, "dump ", 5) == 0) {
            strncpy(password, buffer + 5, MAX_DATA_LEN - 1);
            password[MAX_DATA_LEN - 1] = '\0';
            dump_entries(password);
        } else if (strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0) {
            break;
        } else {
            printf("Unknown command. Use: store, read, delete, dump, quit\n");
        }
    }
    
    return 0;
}

