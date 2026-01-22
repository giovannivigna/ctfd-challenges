#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void readflag() {
    FILE *fp = fopen("/flag", "r");
    if (fp == NULL) {
        printf("Error: Could not open flag file\n");
        return;
    }
    
    char flag[256];
    if (fgets(flag, sizeof(flag), fp) != NULL) {
        printf("%s", flag);
    }
    fclose(fp);
}

// Destructor function - will be called on exit
void __attribute__((destructor)) cleanup() {
    // This function will be called when the program exits
    // We can overwrite its pointer in .fini_array
}

int main() {
    unsigned long long addr;
    unsigned long long value;
    
    // Read 16 bytes: first 8 bytes as address, second 8 bytes as value
    if (read(STDIN_FILENO, &addr, 8) != 8) {
        return 1;
    }
    if (read(STDIN_FILENO, &value, 8) != 8) {
        return 1;
    }
    
    // Write value to address
    *(unsigned long long *)addr = value;
    
    // Return instead of calling exit()
    return 0;
}
