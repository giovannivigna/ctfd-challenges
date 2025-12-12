#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>

char *service_name = "formath";
int timeout = 10;


void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}


int main(int argc, char *argv[])
{
  char function[64];
  char parameter[64];
  char msg[1024];
  double para;
  double result;
  
  if (timeout) {
    signal(SIGALRM, timeout_handler);
    alarm(timeout);
  }
  
  printf("Execution id: %p\n", msg);
  
  printf("Please provide a mathematical function: ");
  fflush(stdout);
  
  if (fgets(function, 64, stdin) == NULL) {
    perror("fgets");
    return 1;
  }

  if (function[strlen(function) - 1] == '\n') {
    function[strlen(function) - 1] = '\0';
  }
  
  printf("Please provide a parameter: ");
  fflush(stdout);

  if (fgets(parameter, 64, stdin) == NULL) {
    perror("fgets");
    return 1;
  }

  if (parameter[strlen(parameter) - 1] == '\n') {
    parameter[strlen(parameter) - 1] = '\0';
  }
  para = atof(parameter);

  result = 0;
  if (!strcmp(function, "abs")) {
    result = abs(para);
  }
  else if (!strcmp(function, "sinh")) {
    result = sinh(para);
  }
  else if (!strcmp(function, "cosh")) {
    result = cosh(para);
  }
  else if (!strcmp(function, "tanh")) {
    result = tanh(para);
  }
  else {
    printf("Unknown function %s!\n", function);
    return 1;
  }    
  
  snprintf(msg, 1024 - 1, "The application of %s to %s returned %f\n", function, parameter, result);
  msg[1024 - 1] = '\0';
  printf(msg);
  return 0;
}
