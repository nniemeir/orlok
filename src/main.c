#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "trace.h"

static void process_args(int argc, char *argv[], char **program_path,
                         int *isAttached, pid_t *child) {
  int c;
  optind = 1;
  while ((c = getopt(argc, argv, "hn:p:")) != -1) {
    switch (c) {
    case 'h':
      printf("-h\tDisplay program usage\n");
      printf("-n[PATH]\tSpecify path of executable to run\n");
      printf("-p[PID]\tSpecify process ID to hook\n");
      exit(EXIT_FAILURE);

    case 'n':
      *program_path = strdup(optarg);
      if (!*program_path) {
        fprintf(stderr, "Failed to duplicate string to program_path: %s",
                strerror(errno));
        exit(EXIT_FAILURE);
      }
      break;

    case 'p':
      *child = atoi(optarg);
      *isAttached = 1;
      break;

    case '?':
      fprintf(stderr, "Unknown option '-%c'. Run with -h for options.\n",
              optopt);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char *argv[]) {
  pid_t child;
  char *program_path = NULL;
  int isAttached = 0;

  process_args(argc, argv, &program_path, &isAttached, &child);

  if (isAttached) {
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
      fprintf(stderr, "ATTACH Failed: %s\n", strerror(errno));
      free(program_path);
      exit(EXIT_FAILURE);
    }
  } else {
    if (!program_path) {
      fprintf(stderr, "Must specify program path\n");
      exit(EXIT_FAILURE);
    }

    child = fork();

    if (child == 0) {
      if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        fprintf(stderr, "TRACEME Failed: %s\n", strerror(errno));
        free(program_path);
        exit(EXIT_FAILURE);
      }

      if (execl(program_path, program_path, NULL) == -1) {
        fprintf(stderr, "Failed to execute file: %s\n", strerror(errno));
        free(program_path);
        exit(EXIT_FAILURE);
      }

      free(program_path);
    } else if (child == -1) {
      fprintf(stderr, "Failed to fork process: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  trace_child(child, isAttached);

  if (isAttached) {
    if (ptrace(PTRACE_DETACH, child, NULL, NULL) == -1) {
      fprintf(stderr, "DETACH Failed: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  exit(0);
}
