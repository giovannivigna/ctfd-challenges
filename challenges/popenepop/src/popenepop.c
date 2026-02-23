#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

/* Naive normalization: trims leading/trailing spaces */
void normalize(char *s) {
    while (isspace(*s)) s++;

    char *end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) {
        *end-- = '\0';
    }
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
    char *username = read_username();
    if (!username) {
        fprintf(stderr, "Input error\n");
        return 1;
    }

    normalize(username);

    char *command = build_command(username);
    if (!command) {
        fprintf(stderr, "Allocation error\n");
        free(username);
        return 1;
    }

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("popen failed");
        free(username);
        free(command);
        return 1;
    }

    char output[256];
    while (fgets(output, sizeof(output), fp)) {
        printf("%s", output);
    }

    pclose(fp);
    free(username);
    free(command);
    return 0;
}