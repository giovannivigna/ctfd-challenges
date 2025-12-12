#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

uid_t user_id;
char filename[256];

char *service_name = "thisisbss";
int timeout = 10;

void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}

int main(int argc, char *argv[])
{

  struct stat statbuf;
  char cmd[1024];

  signal(SIGALRM, timeout_handler);
  alarm(timeout);

  user_id = getuid();
  
  printf("Please provide the file to access: ");
  fflush(stdout);

  if (fgets(filename, 1024, stdin) == NULL) {
    perror("fgets");
    return 1;
  }
  if (filename[strlen(filename) - 1] == '\n') {
    filename[strlen(filename) - 1] = '\0';
  }

  if (stat(filename, &statbuf)) {
    perror("stat");
    return 1;
  }

  if (statbuf.st_uid != user_id) {
    printf("You do not own this file! The owner has id %d while yours is %d. Action aborted...\n", 
      statbuf.st_uid, user_id);
    return 1;
  }
  snprintf(cmd, 1024, "/bin/cat %s", filename);
  system(cmd);
  return 0;
}
  
  
  
  
