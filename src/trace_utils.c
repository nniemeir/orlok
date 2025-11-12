#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "syscall_types.h"
#include "trace.h"

void read_string_arg(char **buffer, pid_t pid, unsigned long addr) {
  int i = 0;
  long word;
  while (i < ARG_MAX) {
    errno = 0;
    // PEEKDATA can return -1 on success, so we manually set errno to 0 to
    // detect errors
    word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    if (errno != 0) {
      fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
      break;
    }
    memcpy(*buffer + i, &word, sizeof(word));
    if (memchr(&word, 0, sizeof(word)))
      break;
    i += sizeof(word);
  }
}

void read_string_array(char ***buffer, pid_t pid, unsigned long addr) {
  if (addr == 0) {
    return;
  }

  int count = 0;
  unsigned long ptr_addr = addr;
  while (1) {
    errno = 0;
    ptrace(PTRACE_PEEKDATA, pid, ptr_addr, NULL);
    if (errno != 0) {
      fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
      break;
    }
    count++;
    ptr_addr += sizeof(long);

    if (count > 1024) {
      break;
    }
  }

  char **result = malloc((count + 1) * sizeof(char *));
  if (!result) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  if (!result) {
    return;
  }

  ptr_addr = addr;
  for (int i = 0; i < count; i++) {
    errno = 0;
    long ptr = ptrace(PTRACE_PEEKDATA, pid, ptr_addr, NULL);
    if (errno != 0) {
      fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
      break;
    }

    if (ptr == 0) {
      result[i] = NULL;
      break;
    }

    result[i] = malloc(ARG_MAX);
    if (!result[i]) {
      fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
      exit(1);
    }

    if (!result[i]) {
      for (int j = 0; j < i; j++) {
        free(result[j]);
      }
      free(result);
      return;
    }

    read_string_arg(&result[i], pid, ptr);
    ptr_addr += sizeof(long);
  }

  result[count] = NULL;
  *buffer = result;
}

void array_to_string(char **buffer, char **arr) {
  if (!arr) {
    snprintf(*buffer, ARG_MAX, "NULL");
    return;
  }

  size_t offset = 0;
  offset += snprintf(*buffer + offset, ARG_MAX - offset, "[");

  for (int i = 0; arr[i] != NULL && offset < ARG_MAX - 1; i++) {
    if (i > 0) {
      offset += snprintf(*buffer + offset, ARG_MAX - offset, ", ");
    }
    offset += snprintf(*buffer + offset, ARG_MAX - offset, "\"%s\"", arr[i]);
  }

  snprintf(*buffer + offset, ARG_MAX - offset, "]");
}
