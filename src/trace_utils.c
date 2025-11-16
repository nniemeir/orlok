/**
 * trace_utils.c
 *
 * Utility functions for reading data from a traced process's address space.
 *
 * OVERVIEW:
 * System calls often take pointers as parameters. Reading these from our parent
 * process is not as simple as dereferencing the pointer because the address is for
 * the traced process's address space, not the parent's. This is where PEEKDATA
 * comes in, PEEKDATA allows us to read memory from another process's address
 * space.
 *
 * Checking for errors with PEEKDATA is kind of wacky though, as it sets errno
 * on error but does not indicate error through its return value (-1 can be
 * returned on success). We handle this by setting errno to 0 and checking
 * if it changes after PEEKDATA runs.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "syscall_types.h"
#include "trace.h"

/**
 * read_string_arg - Read null-terminated string from traced process
 * @buffer: Pointer to buffer (allocated by caller)
 * @pid: PID of traced process
 * @addr: Address of string in traced process's memory
 *
 * Reads a C string from another process's memory using PTRACE_PEEKDATA.
 * We read 8 bytes at a time until we find a null terminator or hit ARG_MAX.
 */
void read_string_arg(char **buffer, pid_t pid, unsigned long addr) {
  int i = 0;
  long word;
  while (i < ARG_MAX) {
    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    if (errno != 0) {
      fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
      break;
    }

    // Copy this 8-byte word into the buffer
    memcpy(*buffer + i, &word, sizeof(word));

    // Check if any of the bytes is the null terminator, we are done if it is
    if (memchr(&word, 0, sizeof(word))) {
      break;
    }

    i += sizeof(word); // Move to the next 8 bytes
  }
}

/**
 * read_string_array - Read array of string pointers from traced process
 * @buffer: Pointer to char** (allocated and filled by this function)
 * @pid: PID of traced process
 * @addr: Address of pointer array in traced process's memory
 *
 * Reads a NULL-terminated array of string pointers (like argv or envp).
 */
void read_string_array(char ***buffer, pid_t pid, unsigned long addr) {
  // We cannot proceed if addr is a NULL pointer
  if (addr == 0) {
    return;
  }

  // We count the number of elements in the array
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

    /*
     * Limiting the function to arrays with less than 1025 elements is more than
     * adequate in this context.
     */
    if (count > 1024) {
      break;
    }
  }

  /*
   * System calls expect the last element in the string arrays that they work
   * with to be NULL, so we allocate count + 1 to leave room to end with NULL.
   */
  char **result = malloc((count + 1) * sizeof(char *));
  if (!result) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
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

    // Allocate space for the string
    result[i] = malloc(ARG_MAX);
    if (!result[i]) {
      fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
      exit(1);
    }

    // Read the string that the pointer points to into result[i]
    read_string_arg(&result[i], pid, ptr);
    ptr_addr += sizeof(long);
  }

  result[count] = NULL;
  *buffer = result;
}

/**
 * array_to_string - Convert string array into a formatted string
 * @buffer: Output buffer (allocated by caller)
 * @arr: NULL-terminated array of strings
 *
 * This is used to conveniently print arrays that syscalls work with in our
 * output.
 *
 */
void array_to_string(char **buffer, char **arr) {
  if (!arr) {
    snprintf(*buffer, ARG_MAX, "NULL");
    return;
  }

  size_t offset = 0;
  offset += snprintf(*buffer + offset, ARG_MAX - offset, "[");

  for (int i = 0; arr[i] != NULL && offset < ARG_MAX - 1; i++) {
    // Separate elements with a comma
    if (i > 0) {
      offset += snprintf(*buffer + offset, ARG_MAX - offset, ", ");
    }
    // Add quoted string
    offset += snprintf(*buffer + offset, ARG_MAX - offset, "\"%s\"", arr[i]);
  }

  snprintf(*buffer + offset, ARG_MAX - offset, "]");
}
