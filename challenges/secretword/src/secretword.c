#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#define KEY "SuperSecretKey"
#define KEY_LEN (sizeof(KEY) - 1)

// We generate a new plaintext secret each run, as a series of English words.
// The service prints the XOR-encrypted secret (hex) and asks the user to decrypt it.
#define SECRET_WORDS 5
#define MAX_WORD_LEN 16
#define MAX_SECRET_LEN (SECRET_WORDS * (MAX_WORD_LEN + 1))  // includes spaces + NUL

static const char *WORDLIST[] = {
    "apple", "river", "cloud", "castle", "garden", "yellow", "winter", "silver",
    "coffee", "planet", "window", "pencil", "forest", "orange", "little", "rocket",
    "summer", "purple", "monkey", "butter", "ticket", "friend", "dragon", "candle",
    "shadow", "gentle", "mirror", "bright", "flower", "smooth", "hunter", "pocket",
    "happy", "silent", "thunder", "violet", "golden", "rabbit", "sailor", "mountain",
    "bottle", "sugar", "pepper", "breeze", "ocean", "island", "laptop", "magnet",
    "symphony", "whisper", "sunrise", "starlight", "moonlight", "rainbow",
};
#define WORDLIST_LEN (sizeof(WORDLIST) / sizeof(WORDLIST[0]))

// XOR function to obfuscate the secret
static void xor_encrypt_decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t keylen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

static void read_flag(void) {
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

static uint32_t urand32(void) {
    uint32_t v = 0;
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        fread(&v, 1, sizeof(v), fp);
        fclose(fp);
        return v;
    }
    // Fallback: not cryptographically secure, but avoids hard failure.
    return (uint32_t)getpid() ^ (uint32_t)time(NULL);
}

static size_t generate_secret(char *out, size_t out_sz) {
    // Build "word word word ..." (space-separated).
    size_t used = 0;
    out[0] = '\0';
    for (int i = 0; i < SECRET_WORDS; i++) {
        const char *w = WORDLIST[urand32() % WORDLIST_LEN];
        size_t wl = strlen(w);
        if (wl > MAX_WORD_LEN) wl = MAX_WORD_LEN;

        // Add space if not first.
        if (i != 0) {
            if (used + 1 >= out_sz) break;
            out[used++] = ' ';
            out[used] = '\0';
        }

        if (used + wl >= out_sz) break;
        memcpy(out + used, w, wl);
        used += wl;
        out[used] = '\0';
    }
    return used;
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    char plaintext[MAX_SECRET_LEN];
    size_t plaintext_len = generate_secret(plaintext, sizeof(plaintext));

    uint8_t ciphertext[MAX_SECRET_LEN];
    memcpy(ciphertext, plaintext, plaintext_len);
    xor_encrypt_decrypt(ciphertext, plaintext_len, (const uint8_t *)KEY, KEY_LEN);

    printf("Encrypted secret (hex): ");
    print_hex(ciphertext, plaintext_len);

    char user_input[MAX_SECRET_LEN];
    printf("Enter the secret: ");
    fflush(stdout);
    fgets(user_input, sizeof(user_input), stdin);

    // Remove newline character from input
    user_input[strcspn(user_input, "\n")] = '\0';
    
    int res = strcmp(user_input, plaintext);
    if (res == 0) {
        read_flag(); 
    } else {
        printf("Wrong input! No flag for you!\n");
    }

    return 0;
}
