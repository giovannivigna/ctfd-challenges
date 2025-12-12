#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>

struct info {
	char filename[0x100];
	char username[0x8000];
};

char *service_name = "longshotr";
int timeout = 10;

char data[0x10000];

void gadget()
{
  __asm__("jmp *\%esp");
}


void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}

int verify_username(char *username) 
{
  int i;

  printf("Verifying username...\n");
  if ((strstr(username, "%n") != NULL) || (strstr(username, " ") != NULL)) {
    printf("Illegal character sequence in username!\n");
    return 1;
  }
  printf("Verified username: ");
  for (i = 0; i < strlen(username); i++) {
    username[i] = tolower(username[i]);
  }
  printf(username);
  return 0;
}

int main(int argc, char *argv[])
{
  struct info info;
  char *filename = info.filename;
  char *username = info.username;
  long max;
  short len;
  struct stat statbuf;
  
  if (timeout) {
    signal(SIGALRM, timeout_handler);
    alarm(timeout);
  }

  printf("Your ticket is %p... Please provide your name: ", &info);
  fflush(stdout);
  if (fgets(username, 0x400, stdin) == NULL) {
    perror("fgets");
    return 1;
  }

  if (username[strlen(username) - 1] == '\n') {
    username[strlen(username) - 1] = '\0';
  }
  
  if (verify_username(username)) {
    printf("Username not verified!\n");
    return 1;
  }
  
  fflush(stdout);
  printf("\nPlease provide the name of the file to be analyzed: ");
  fflush(stdout);

  if (fgets(data, 0x10000, stdin) == NULL) {
    perror("fgets");
    return 1;
  }

  if (data[strlen(data) - 1] == '\n') {
    data[strlen(data) - 1] = '\0';
  }

  max = sizeof(info.filename);
  len = strlen(data);

  if (len > max) {
    printf("File name too long!\n");
    return 1;
  }

  strcpy(filename, data);
  
  if (stat(filename, &statbuf)) {
    printf("Access denied!\n");
    return 1;
  }

  printf("%s\n", filename);
  printf("\tDevice: %d\n", statbuf.st_dev);
  printf("\tI-node: %d\n", statbuf.st_ino);
  printf("\tMode  : %x\n", statbuf.st_mode);
  printf("\tUID   : %d\n", statbuf.st_uid);
  printf("\tGID   : %d\n", statbuf.st_gid);
  printf("\tSize  : %d\n", statbuf.st_size);

  return 0;
}
  


  
 
