#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 128

typedef struct {
    char *data; 
    int flag;   
} ParsedMessage;

ParsedMessage* parse_message(const char *input) {
    ParsedMessage *msg = malloc(sizeof(ParsedMessage));
    if (!msg) {
        perror("malloc failed");
        exit(1);
    }

    size_t len = strlen(input);

    if (len == 64) {
        msg->data = NULL;     
        msg->flag = 1;        
    } else {
        msg->data = strdup(input);  
        msg->flag = 0;
    }
    printf("Message length: %ld, data: %s, flag: %d\n", len, msg->data, msg->flag);
    return msg;
}

void process_message(ParsedMessage *msg) {
    if (msg->flag) {
        printf("First byte of data: %c\n", msg->data[0]);
    } else {
        printf("Message: %s\n", msg->data);
    }
}

int main() {
    char input[MAX_INPUT];

    if (fgets(input, sizeof(input), stdin) == NULL) {
        perror("fgets failed");
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';
    printf("Input: %s\n", input);

    ParsedMessage *msg = parse_message(input);
    process_message(msg);

    if (msg->data) free(msg->data);
    free(msg);

    return 0;
}