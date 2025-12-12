#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_LINE 1024

// Sanitization function
int is_safe_input(const char *input) {
    // Check for dangerous characters
    if (strchr(input, '&') != NULL || 
        strchr(input, ';') != NULL || 
        strchr(input, '|') != NULL) {
        return 0; // Dangerous character found
    }
    return 1; // Input is considered safe
}

// Program that reads a line from stdin and appends it to file
int main(int argc, char *argv[]) {
    char buffer[MAX_LINE];

    // Read a line from stdin and store it in buffer
    if (fgets(buffer, MAX_LINE, stdin) == NULL) {
        fprintf(stderr, "Error reading line.\n");
        return 1;
    }
    
    // Remove trailing newlines
    while (buffer[strlen(buffer) - 1] == '\n') {
        buffer[strlen(buffer) - 1] = '\0';
    }

    // Sanitize the input
    if (!is_safe_input(buffer)) {
        printf("Error: Unsafe input detected!\n");
        return 1;
    }

    char command[MAX_LINE * 2];
    printf("Recording message: ");
    fflush(stdout);
    snprintf(command, sizeof(command), "echo \"%s\" | tee -a /tmp/loggable", buffer);
    
    // fprintf(stderr, "Executing: [%s]\n", command);
    system(command);
    printf("Message [%s] received and added to the log\n", buffer);
   
   return 0;
}