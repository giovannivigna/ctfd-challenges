#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define SECRET "\xc5\xd8\x26\xb6\x78\x15\xfe\x4d\xab\x40\xc3\x8c\x13\x5c\xb4\x2f\x82\x40\xf5\x3a\x39\xb8\x76\xa3\xe9\xf8\xcb\x06\xa9\xb7\x7b\xdb\xbc\xf1"  
#define KEY "SuperSecretKey"  
#define SECRET_LEN (sizeof(SECRET) - 1)
#define KEY_LEN (sizeof(KEY) - 1)

#define STATE_SIZE 256 

void init(uint8_t *S, const uint8_t *key, size_t key_len) {
    for (int i = 0; i < STATE_SIZE; i++) {
        S[i] = i;
    }

    int j = 0;
    for (int i = 0; i < STATE_SIZE; i++) {
        j = (j + S[i] + key[i % key_len]) % STATE_SIZE;
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

void crypt(uint8_t *data, size_t data_len, uint8_t *S) {
    int i = 0, j = 0;
    for (size_t n = 0; n < data_len; n++) {
        i = (i + 1) % STATE_SIZE;
        j = (j + S[i]) % STATE_SIZE;

        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        data[n] ^= S[(S[i] + S[j]) % STATE_SIZE];
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
    uint8_t S[STATE_SIZE];
    init(S, KEY, KEY_LEN);

    char decrypted_secret[SECRET_LEN + 1] = SECRET;
    crypt(decrypted_secret, SECRET_LEN, S);
    
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
