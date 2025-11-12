#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include "trace.h"

int main(void) {
  pid_t child;
  child = fork();
  if (child == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      fprintf(stderr, "TRACEME Failed: %s\n", strerror(errno));
      exit(1);
    }
    if (execl("/bin/cat", "cat", NULL) == -1) {
      fprintf(stderr, "Failed to execute file: %s\n", strerror(errno));
      exit(1);
    }
  } else if (child == -1) {
    fprintf(stderr, "Failed to fork process: %s\n", strerror(errno));
    exit(1);
  } else {
    trace_child(child);
  }
  return 0;
}
