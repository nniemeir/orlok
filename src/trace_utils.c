#include "trace.h"
#include <string.h>
#include <sys/ptrace.h>

void read_string_arg(char *buffer, pid_t pid, unsigned long addr) {
  int i = 0;
  long word;
  while (i < 4096) {
    word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    if (word == -1)
      break;
    memcpy(buffer + i, &word, sizeof(word));
    if (memchr(&word, 0, sizeof(word)))
      break;
    i += sizeof(word);
  }
}
