#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_INPUT_SIZE 32

void secret_function() {
    printf("💥 Crash triggered! 💥\n");
    *(volatile int*)0 = 0; // Intentional segmentation fault
}

void process_input(const char *input) {
    char buffer[MAX_INPUT_SIZE];
    static int state = 0;  

    if (strlen(input) > MAX_INPUT_SIZE - 1) {
        printf("Input too long!\n");
        return;
    }

    strcpy(buffer, input); 

    for (int i = 0; i < strlen(buffer); i++) {
        switch (state) {
            case 0: if (buffer[i] == 'A') state = 1; else state = 0; break;
            case 1: if (buffer[i] == 'F') state = 2; else state = 0; break;
            case 2: if (buffer[i] == 'L') state = 3; else state = 0; break;
            case 3: if (buffer[i] == '+') state = 4; else state = 0; break;
            case 4: if (buffer[i] == '+') state = 5; else state = 0; break;
            case 5: secret_function(); return;  
        }
    }
}

int main() {
    char input[128];
    
    printf("Enter input: ");
    fgets(input, sizeof(input), stdin);
    printf("Received input: [%s]\n", input);
    
    process_input(input);
    printf("Everything went well!\n");
    
    return 0;
}