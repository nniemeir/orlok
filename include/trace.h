/**
 * trace.h
 *
 * Functions that handle the tracing of syscalls after the process has been
 * hooked and the parsing of captured register data.
 */

#ifndef TRACE_H
#define TRACE_H

#include <sys/types.h>

// Tracing Utilities
void read_string_arg(char **buffer, pid_t pid, unsigned long addr);
void read_string_array(char ***buffer, pid_t pid, unsigned long addr);
void array_to_string(char **buffer, char **arr);

// Post-hook tracing setup and tracing loop
void trace_child(pid_t child, int isAttached);

#endif
