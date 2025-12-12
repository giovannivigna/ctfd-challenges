#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define ENCRYPT "encrypt"
#define DECRYPT "decrypt"
#define SHIFT_AMOUNT 5

char rotater(unsigned char x, int n) {
    char c;
    unsigned char temp = x << (8 - n);
    x = x >> n;
    c = (x | temp);
    return c;
}
char rotatel(unsigned char x, int n) {
    char c;
    unsigned char temp = x >> (8 - n);
    x = x << n;
    c = (x | temp);
    return c;
}

int main(int argc, char** argv)
{
	char c;
	char xor_c;
	char rot_c;
	char out_c;
	char *operation;
	char *key;
	int key_len;
	int key_i = 0;
	int i;
	int iter = 0;

	if (argc < 3) {
		fprintf(stderr, "Please specify an operation and a key\n");
		exit(1);
	}

	operation = argv[1];
	fprintf(stderr, "Using operation %s\n", operation);
	key = argv[2];
	key_len = strlen(key);
	fprintf(stderr, "Using key %s\n", key);
	
	while (1) {
		fprintf(stderr, "ITR %d\n", iter);
		iter = iter + 1;

		i = read(0, &c, 1);
		fprintf(stderr, "REC [%c][%02x]\n", c, c);
		if (i == 0) {
			fprintf(stderr, "Null read\n");
			exit(0);
		}
		fprintf(stderr, "KEY [%c][%02x]\n", key[key_i], key[key_i]);

		if (!strcmp(operation, ENCRYPT)) { 
			rot_c = rotater(c, SHIFT_AMOUNT);
			fprintf(stderr, "ROT [%c][%02x]\n", rot_c, rot_c);
			xor_c = rot_c ^ key[key_i];
			fprintf(stderr, "XOR [%c][%02x]\n", xor_c, xor_c);
			out_c = xor_c;
			
		}
		else if (!strcmp(operation, DECRYPT)) {
			xor_c = c ^ key[key_i];
			fprintf(stderr, "XOR [%c][%02x]\n", xor_c, xor_c);
			rot_c = rotatel(xor_c, SHIFT_AMOUNT);
			fprintf(stderr, "ROT [%c][%02x]\n", rot_c, rot_c);
			out_c = rot_c;
		}
		else {
			fprintf(stderr, "Unknown operation %s\n", operation);
			exit(1);
		}
		key_i = (key_i + 1) % key_len;
		fprintf(stderr, "OUT [%c][%02x]\n", out_c, out_c);
		write(1, &out_c, 1);
	}

	/* Never reached */
	return 0;
}
