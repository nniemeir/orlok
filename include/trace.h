#ifndef TRACE_H
#define TRACE_H

#include <sys/types.h>

void read_string_arg(char *buffer, pid_t pid, unsigned long addr);
void trace_child(pid_t child);

#endif
