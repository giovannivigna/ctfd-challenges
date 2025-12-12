#include <stdio.h>

void targetFunction(int a, int b, int c, int d) {
    printf("Hello!\n");
}

void anotherFunction(int x) {
    printf("Another function\n");
}

int main() {
    targetFunction(1, 2, 3, 4);
    return 0;
}