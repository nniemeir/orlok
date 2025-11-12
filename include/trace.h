#ifndef TRACE_H
#define TRACE_H

#include <sys/types.h>

void read_string_arg(char **buffer, pid_t pid, unsigned long addr);
void read_string_array(char ***buffer, pid_t pid, unsigned long addr);
void array_to_string(char **buffer, char **arr);

void trace_child(pid_t child);

#endif
