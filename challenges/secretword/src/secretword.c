#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SECRET "\x1a\x55\x13\x04\x1c\x3d\x0a\x17\x52\x07\x11\x27\x0c\x1c\x25\x10\x50\x0c\x06\x74\x16\x43\x01\x0a\x54\x2e\x04\x0a\x2a"  
#define KEY "SuperSecretKey"  
#define SECRET_LEN (sizeof(SECRET) - 1)
#define KEY_LEN (sizeof(KEY) - 1)

// XOR function to obfuscate the secret
void xor_encrypt_decrypt(char *data, size_t len, const char *key, size_t keylen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

void read_flag() {
    FILE *fp = fopen("/flag", "r");
    if (!fp) {
        perror("Error opening flag file");
        exit(1);
    }
    char flag[1024]; 
    if (fgets(flag, sizeof(flag), fp)) {
        printf("The flag is: %s\n", flag);
    }
    fclose(fp);
}

int main() {
    char decrypted_secret[SECRET_LEN + 1] = SECRET;
    xor_encrypt_decrypt(decrypted_secret, SECRET_LEN, KEY, KEY_LEN);
    // Makes sure that the decrypted secret is NULL-terminated
    decrypted_secret[SECRET_LEN] = '\0';

    char user_input[SECRET_LEN + 1];
    printf("Enter the secret: ");
    fflush(stdout);
    fgets(user_input, sizeof(user_input), stdin);

    // Remove newline character from input
    user_input[strcspn(user_input, "\n")] = '\0';
    
    int res = strcmp(user_input, decrypted_secret);
    if (res == 0) {
        read_flag(); 
    } else {
        printf("Wrong input! No flag for you!\n");
    }

    return 0;
}
