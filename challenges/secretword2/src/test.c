#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

int main() {
    uint8_t key[] = "SuperSecretKey";  
    uint8_t data[] = "OK, this time was slightly harder!"; 

    size_t key_len = strlen((char *)key);
    size_t data_len = strlen((char *)data);

    uint8_t S[STATE_SIZE];  // RC4 state array

    printf("Original Data: %s\n", data);

    // Encrypt
    init(S, key, key_len);
    crypt(data, data_len, S);
    printf("Encrypted Data: ");
    for (size_t i = 0; i < data_len; i++) {
        printf("\\x%02x", data[i]);
    }
    printf("\n");

    // Decrypt (same function)
    init(S, key, key_len);
    crypt(data, data_len, S);
    printf("Decrypted Data: %s\n", data);

    return 0;
}
