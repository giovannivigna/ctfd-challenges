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
    
    // Call exit
    exit(0);
}
