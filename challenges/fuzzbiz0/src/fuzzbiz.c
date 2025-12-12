#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int check_input(char *input) {
    printf("Checking input [%s]\n", input);
    if (strstr(input, "MAGIC") == NULL) {
        printf("Input invalid!\n");
        return 1;
    }
    return 0;
}

void complex_work() {
    printf("Doing some complex work...\n");
    printf("Complex work done!\n");
}

void vuln_function(char *input) {
    char buffer[16]; 
    strcpy(buffer, input);
    printf("You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    char input[256];

    printf("Enter input: ");
    fgets(input, sizeof(input), stdin);
    printf("Received input: [%s]\n", input);

    if (check_input(input)) {
        return 1;
    }

    complex_work();
    vuln_function(input);

    return 0;
}
