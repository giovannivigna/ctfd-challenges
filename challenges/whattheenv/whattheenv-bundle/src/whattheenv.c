#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>
#include <wordexp.h>
#include <getopt.h>

char *service_name = "whattheenv";
int timeout = 10;
int debug = 0;
#define PATH_MAX 4096

void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}


int main(int argc, char *argv[]) 
{
  char varname[16];
  char value[512];
  char command[16];
  char template[] = "idXXXXXX"; 
  char chmod_str[5];
  char cwd[PATH_MAX];
  unsigned long chmod_mask = 0;
  char *dir_name;
  char *data;
  char *permission_path;
  FILE* f;
  wordexp_t p;
  int res;
  char *workdir = NULL;

  int opt;
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

  umask(0);
  // it assumes the process is running in a writable directory
  dir_name = mkdtemp(template);

  if(dir_name == NULL) {
    perror("mkdtemp");
    return 1;
  }

  if (chdir(dir_name)) {
    perror("chdir");
    return 1;
  }

  printf("Your service ID is %s\n", dir_name);
  fflush(stdout);

  while (1) {
    printf("Command (load/store/quit): ");
    fflush(stdout);
    
    if (fgets(command, 16, stdin) == NULL) {
      perror("fgets");
      return 1;
    }
    
    if (command[strlen(command) - 1] == '\n') {
      command[strlen(command) - 1] = '\0';
    }

    if (!strcmp(command, "load")) {
     
      printf("Please enter a variable: ");
      fflush(stdout);
      
      if (fgets(varname, 16, stdin) == NULL) {
        perror("fgets");
        return 1;
      }

      if (varname[strlen(varname) - 1] == '\n') {
        varname[strlen(varname) - 1] = '\0';
      }
      
      printf("Please enter a value: ");
      fflush(stdout);
      
      if (fgets(value, 512, stdin) == NULL) {
        perror("fgets");
        return 1;
      }

      if (value[strlen(value) - 1] == '\n') {
        value[strlen(value) - 1] = '\0';
      }
      
      setenv(varname, value, 1);
    }
    else if (!strcmp(command, "store")) {
     
      printf("Please enter a variable: ");
      fflush(stdout);
      

      if (fgets(varname, 16, stdin) == NULL) {
        perror("fgets");
        return 1;
      }

      if (varname[strlen(varname) - 1] == '\n') {
        varname[strlen(varname) - 1] = '\0';
      }

      data = getenv(varname);
      if (data == NULL) {
        printf("Non-existent variable!\n");
        fflush(stdout);
        continue;
      }

      wordexp("~/permissions", &p, 0);
      permission_path = p.we_wordv[0];
      printf("Opening permission file %s\n", permission_path);

      f = fopen(permission_path, "r");
      if (f == NULL) {
        printf("Cannot find the permission file\n");
        perror("fopen");
        fflush(stdout);
        printf("Creating permission file %s\n", permission_path);

        f = fopen(permission_path, "w+");
        if (f == NULL) {
          perror("fopen");
          printf("Cannot create the file permissions spec\n");
          fflush(stdout);
          continue;    
        }   
        fwrite("0600", strlen("0600"), 1, f);
        rewind(f);
      }
      fread(chmod_str, 1, 4, f);
      chmod_str[4] = '\0';
      chmod_mask = strtoul(chmod_str, NULL, 8);
      
      f = fopen(varname, "w+");
      fwrite(data, strlen(data), 1, f);
      fclose(f);

      res = chmod(varname, chmod_mask);
      printf("chmod %lx res %d\n", chmod_mask, res);
      if (res != 0) {
        perror("chmod");
      }
      
      printf("Variable value saved!\n");
      fflush(stdout);
    }
    else if (!strcmp(command, "quit")) {
      printf("Currently saved values:\n");
      execlp("ls", "ls", ".", (char *)0);
      return 0;
    }
    else {
      printf("Unknown command!\n");
    }
  }
 
  return 0;
}
