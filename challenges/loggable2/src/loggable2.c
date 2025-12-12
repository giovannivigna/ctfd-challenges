#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex.h>

#define MAX_LINE 1024
// Allows only the characters for text, numbers, and URLs, inlcuding dot, dash, @, colon, quotes, and /
#define SANITIZE_REGEX "^[A-Za-z0-9 .-@:\"//]+$"

// Function to check if a string matches a given regex pattern
int is_safe_input(const char *string, const char *pattern) {
    regex_t regex;
    int ret;

    // Compile the regular expression
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        return 1;
    }

    // Execute the regular expression match
    ret = regexec(&regex, string, 0, NULL, 0);
    
    // Free the compiled regex
    regfree(&regex);

    if (!ret) {
        fprintf(stderr, "String [%s] matches the allowed pattern\n", string);
        return 1;  
    } else if (ret == REG_NOMATCH) {
        fprintf(stderr, "String [%s] does not match the allowed pattern\n", string);
        return 0;  
    } else {
        char errbuf[100];
        regerror(ret, &regex, errbuf, sizeof(errbuf));
        fprintf(stderr, "Regex match failed: %s\n", errbuf);
        return 0;
    }
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
    if (!is_safe_input(buffer, SANITIZE_REGEX)) {
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