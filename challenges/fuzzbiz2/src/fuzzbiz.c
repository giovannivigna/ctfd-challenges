#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef struct Node {
    int id;
    char *data;
    struct Node *next;
    int is_freed; 
} Node;

void process(Node *node) {
    if (node && node->data) {
        printf("Processing Node ID: %d\n", node->id);
        printf("Data before corruption: %s\n", node->data);

        printf("Overwriting heap metadata...\n");
        size_t *metadata = (size_t *)(node->data - 8);  
        *metadata = (size_t)-1;  

        printf("Heap metadata overwritten! Next malloc/free will likely crash.\n");
    }
}

Node *create_node(int id, const char *input_data) {
    Node *new_node = (Node *)malloc(sizeof(Node));
    if (!new_node) {
        perror("malloc failed");
        return NULL;
    }

    new_node->id = id;
    new_node->data = (char *)malloc(64);
    if (!new_node->data) {
        perror("malloc failed");
        free(new_node);
        return NULL;
    }

    strncpy(new_node->data, input_data, 63);
    new_node->data[63] = '\0';
    new_node->next = NULL;
    new_node->is_freed = 0; 
    return new_node;
}


void append_node(Node **head, int id, const char *data) {
    Node *new_node = create_node(id, data);
    if (!new_node) return;

    if (!*head) {
        *head = new_node;
        return;
    }

    Node *temp = *head;
    while (temp->next)
        temp = temp->next;

    temp->next = new_node;
}

void conditional_free(Node *node) {
    if (!node) return;
    printf("Freeing Node ID: %d (but keeping in list!)\n", node->id);
    
    free(node->data);  
    node->is_freed = 1; 
}

void process_trigger(Node *node) {
    if (!node) return;
    printf("Triggering Use-After-Free on Node ID: %d\n", node->id);

    process(node);  

    printf("Attempting to allocate another buffer...\n");
    char *new_buffer = malloc(64); 
    if (new_buffer) {
        printf("New allocation successful: %p\n", (void *)new_buffer);
        free(new_buffer); 
    }
}


Node *find_node(Node *head, int id) {
    Node *temp = head;
    while (temp) {
        if (temp->id == id) {
            return temp; 
        }
        temp = temp->next;
    }
    return NULL;
}

int main() {
    Node *head = NULL;
    int choice, id;
    char buffer[64];

    while (1) {
        printf("\nMenu:\n");
        printf("1. Add Node\n");
        printf("2. Free Node\n");
        printf("3. Trigger Use-After-Free\n");
        printf("4. Exit\n");
        printf("Choose an option: ");

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input\n");
            break;
        }

        while (getchar() != '\n'); 

        switch (choice) {
            case 1:
                printf("Enter Node ID: ");
                if (scanf("%d", &id) != 1) {
                    printf("Invalid input\n");
                    continue;
                }
                while (getchar() != '\n');

                printf("Enter Node Data: ");
                fgets(buffer, 64, stdin);
                buffer[strcspn(buffer, "\n")] = '\0';

                append_node(&head, id, buffer);
                break;

            case 2: { 
                printf("Enter Node ID to Free: ");
                if (scanf("%d", &id) != 1) {
                    printf("Invalid input\n");
                    continue;
                }
                while (getchar() != '\n');

                Node *node = find_node(head, id);
                if (!node) {
                    printf("Node ID %d not found!\n", id);
                    continue;
                }

                conditional_free(node);
                break;
            }

            case 3: { 
                printf("Enter Node ID to Trigger UAF: ");
                if (scanf("%d", &id) != 1) {
                    printf("Invalid input\n");
                    continue;
                }
                while (getchar() != '\n');

                Node *node = find_node(head, id);
                if (!node) {
                    printf("Node ID %d not found!\n", id);
                    continue;
                }

                process_trigger(node); 
                break;
            }

            case 4:
                printf("Exiting...\n");
                while (head) {
                    Node *temp = head;
                    head = head->next;
                    if (!temp->is_freed) {
                        free(temp->data);
                    }
                    free(temp);
                }
                return 0;

            default:
                printf("Invalid choice, try again.\n");
        }
    }

    return 0;
}