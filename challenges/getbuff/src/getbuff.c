#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <getopt.h>

char *service_name = "getbuff";
int timeout = 10;
int debug = 0;
#define PATH_MAX 4096

void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}

int i, j, checksum;
char c;
  
int main(int argc, char *argv[])
{
  char buf[1024];
  int opt;
  char *workdir = NULL;
  char cwd[PATH_MAX];
  
  while ((opt = getopt(argc, argv, "t:w:d")) != -1) {
    switch (opt) {
      case 't':
        timeout = atoi(optarg);
        break;
      case 'w':
        workdir = strdup(optarg);
        break;
      case 'd':
        debug = 1;
        break;
      default:
        fprintf(stderr, "Usage: %s -t <timeout> -w <workdir> [-d]\n", argv[0]);
          return 1;
    }
  }

  if (timeout) {
    signal(SIGALRM, timeout_handler);
    alarm(timeout);
  }

  if (workdir) {
    chdir(workdir);
  }

  getcwd(cwd, PATH_MAX);
  if (debug) {
    printf("Running service %s in %s as user %d...\n", service_name, cwd, getuid());
  }
 
  printf("Welcome to the checksum verifier service!\n\
    Your service ticket id is: %p\n\
    Please provide the data to verify: ", 
    buf);
  fflush(stdout);

  i = 0;
  while (1) {
    c = getchar(); 
    if (c == '\n') break;

    buf[i] = c;
    buf[i+1] = '\0';
    i++;
  }

  printf("Received a buffer of length %d\n", i);
  fflush(stdout);
    
  checksum = 0;
  for (j = 0; j < i; j++) {
    checksum = checksum ^ buf[j];
  }

  if (checksum != 0) {
    printf("Checksum failed! Exiting now...\n");
    fflush(stdout);
    exit(1);
  }

  printf("Checksum is correct!\n");
  fflush(stdout);

  return 0;
}
