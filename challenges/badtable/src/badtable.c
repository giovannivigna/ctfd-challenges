#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

char *service_name = "badtable";
int timeout = 10;

void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}

int get_int() {
  char buf[1024];
  int i;
  fgets(buf, 1024, stdin);
  i = strtol(buf, NULL, 0);
  //printf("String [%s], Parsed value: %d\n", buf, i);
  return i;
}

char get_char() {
  char buf[16];
  fgets(buf, 16, stdin);
  return buf[0];
}

int main(int argc, char *argv[])
{
  int array[1024];
  int index;
  int value;
  char command;
  
  if (timeout) {
    signal(SIGALRM, timeout_handler);
    alarm(timeout);
  }
  
  printf("This service allows you to store integers in a table for future use.\n");
  printf("Commands: Store (s), Read (r), Dump (d), Quit (q)\n");
  
  for (index = 0; index < 1024; index++) {
    array[index] = 0;
  }
        
  while(1) {
    printf("Command: ");
    fflush(stdout);

    command = get_char();
    if (command == EOF) {
      return 1;
    }
    
    switch(command) {
      case 's':
        printf("Index: ");
        fflush(stdout);
        index = get_int();
        printf("Value: ");
        fflush(stdout);
        value = get_int();
        printf("Updating table value at index %04d with %08d (0x%08x): previous value was %08d (0x%08x)\n", 
          index, value, value, array[index], array[index]); 
        array[index] = value;
        break;
      case 'r':
        printf("Index: ");
        fflush(stdout);
        index = get_int();
        printf("Value: %08d (0x%08x)\n", array[index], array[index]);
        break;
      case 'd':
        for (index = 0; index < 1024; index++) {
          printf("%04d: %08d (0x%08x)\n", index, array[index], array[index]);
        }
        break;
      case 'q':
        printf("Quitting...\n");
        return 0;
      case '\n':
        break;
      default:
        printf("Unknown command %c\n", command);
        break;
    }
  }

  /* Never reached */
  return 0;
}
