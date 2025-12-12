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
#include <dirent.h>

char *service_name = "sympathy";
int timeout = 10;
int debug = 0;
#define PATH_MAX 4096

void timeout_handler(int signal)
{
  printf("\n\nTimeout expired!\n");
  exit(1);
}

const char table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void decode(const char *input, char *output, size_t output_len) {
    int buffer = 0, bits = 0, j = 0;
    for (size_t i = 0; i < strlen(input) && j < output_len; ++i) {
        char *ptr = strchr(table, input[i]);
        if (ptr) {
            buffer = (buffer << 6) | (ptr - table);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                output[j++] = (char)((buffer >> bits) & 0xFF);
            }
        }
    }
    output[j] = '\0';
}

void list_files() {
    struct dirent *de;
    DIR *dr = opendir("./files");

    if (dr == NULL) {
        perror("Could not open directory");
        return;
    }

    printf("Files:\n");
    while ((de = readdir(dr)) != NULL) {
        if (de->d_name[0] != '.') // Skip hidden files and "." and ".."
            printf("%s\n", de->d_name);
    }

    closedir(dr);
}

void print_file(const char *filepath) {
    char buffer[256];
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }
    fclose(file);
}

int main(int argc, char** argv) {
  int choice;
  char input[256];
  char decoded_filename[256];
  char filepath[512];
  char cwd[PATH_MAX];

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


  while (1) {
    printf("\nSelect an option:\n");
    printf("1. List files\n");
    printf("2. Read a file\n");
    printf("3. Exit\n");
    printf("Enter your choice: ");
    fflush(stdout);

    if (scanf("%d", &choice) != 1) {
      fprintf(stderr, "Invalid input\n");
      while (getchar() != '\n'); 
      continue;
    }

    switch (choice) {
      case 1:
          list_files();
          break;

      case 2:
        printf("Enter the filename: ");
        fflush(stdout);
        scanf("%s", input);

        if (strstr(input, "..") != NULL) {
            fprintf(stderr, "Unsafe pattern detected!\n");
            return 1;
        }

        if ((unsigned char)input[0] == 0x90) {
            decode(input + 1, decoded_filename, sizeof(decoded_filename));
            if (debug) printf("Decoded filename: %s\n", decoded_filename);
        } else {
            strncpy(decoded_filename, input, sizeof(decoded_filename) - 1);
            decoded_filename[sizeof(decoded_filename) - 1] = '\0';
        }

        snprintf(filepath, sizeof(filepath), "./files/%s", decoded_filename);
        printf("Opening file %s\n", filepath);
        print_file(filepath);
        fflush(stdout);
        break;

      case 3:
        printf("Exiting...\n");
        fflush(stdout);
        return 0;

      default:
        printf("Invalid choice. Try again.\n");
        fflush(stdout);
    }
  }

  return 0;
}


