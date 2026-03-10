#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reads username from stdin */
char *read_username() {
    char buffer[256];

    printf("Enter username: ");
    fflush(stdout);

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        return NULL;
    }

    buffer[strcspn(buffer, "\n")] = '\0';

    return strdup(buffer);
}

static int allowed_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '$' || c == '(' || c == ')' ||
           c == '{' || c == '}' || c == '/' || c == '>' || c == '<' ;
}

/* Returns 0 on success, -1 if illegal character found */
int normalize(char *s) {
    for (char *p = s; *p; p++) {
        if (!allowed_char(*p)) {
            return -1;
        }
    }
    return 0;
}

/* Returns 1 if path is under /tmp, 0 otherwise */
static int path_under_tmp(const char *path) {
    if (strncmp(path, "/tmp/", 5) != 0 && strcmp(path, "/tmp") != 0) {
        return 0;
    }
    if (strstr(path, "..") != NULL) {
        return 0;
    }
    return 1;
}

/* Create a file under /tmp. Returns 0 on success, -1 on error */
static int create_file(const char *path, const char *content) {
    if (!path_under_tmp(path)) {
        fprintf(stderr, "Path must be under /tmp\n");
        return -1;
    }
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        return -1;
    }
    if (fputs(content, f) < 0) {
        perror("fputs");
        fclose(f);
        return -1;
    }
    fclose(f);
    printf("File created: %s\n", path);
    return 0;
}

/* Read a file under /tmp. Returns 0 on success, -1 on error */
static int read_file(const char *path) {
    if (!path_under_tmp(path)) {
        fprintf(stderr, "Path must be under /tmp\n");
        return -1;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        printf("%s", buf);
    }
    fclose(f);
    return 0;
}

/* Builds a command to retrieve account info */
char *build_command(const char *user) {
    char *cmd = malloc(512);
    if (!cmd) return NULL;

    // Intended: get user info from system database
    snprintf(cmd, 512, "getent passwd %s", user);
    return cmd;
}

int main() {
    char buf[512];

    for (;;) {
        printf("\n--- Menu ---\n");
        printf("1. Get user info\n");
        printf("2. List all users\n");
        printf("3. Create file (under /tmp)\n");
        printf("4. Read file (under /tmp)\n");
        printf("5. Exit\n");
        printf("Choice: ");
        fflush(stdout);

        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            break;
        }
        buf[strcspn(buf, "\n")] = '\0';

        if (strcmp(buf, "1") == 0) {
            char *username = read_username();
            if (!username) {
                fprintf(stderr, "Input error\n");
                continue;
            }
            if (normalize(username) != 0) {
                fprintf(stderr, "Invalid username: illegal characters not allowed\n");
                free(username);
                continue;
            }
            char *command = build_command(username);
            if (!command) {
                fprintf(stderr, "Allocation error\n");
                free(username);
                continue;
            }
            printf("Executing command: %s\n", command);
            FILE *fp = popen(command, "r");
            if (!fp) {
                perror("popen failed");
                free(username);
                free(command);
                continue;
            }
            char output[256];
            while (fgets(output, sizeof(output), fp)) {
                printf("%s", output);
            }
            pclose(fp);
            free(username);
            free(command);
        } else if (strcmp(buf, "2") == 0) {
            FILE *fp = popen("getent passwd", "r");
            if (!fp) {
                perror("popen failed");
                continue;
            }
            char output[256];
            while (fgets(output, sizeof(output), fp)) {
                printf("%s", output);
            }
            pclose(fp);
        } else if (strcmp(buf, "3") == 0) {
            printf("Path (under /tmp): ");
            fflush(stdout);
            if (fgets(buf, sizeof(buf), stdin) == NULL) continue;
            buf[strcspn(buf, "\n")] = '\0';
            printf("Content: ");
            fflush(stdout);
            char content[512];
            if (fgets(content, sizeof(content), stdin) == NULL) continue;
            content[strcspn(content, "\n")] = '\0';
            create_file(buf, content);
        } else if (strcmp(buf, "4") == 0) {
            printf("Path (under /tmp): ");
            fflush(stdout);
            if (fgets(buf, sizeof(buf), stdin) == NULL) continue;
            buf[strcspn(buf, "\n")] = '\0';
            read_file(buf);
        } else if (strcmp(buf, "5") == 0) {
            printf("Bye.\n");
            break;
        } else {
            printf("Invalid choice\n");
        }
    }
    return 0;
}