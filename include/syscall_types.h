/**
 * syscall_types.h
 *
 * Defines structs used to capture syscall arguments and return values during
 * tracing.
 *
 * The syscalls_state struct encapsulates the other structs for easier access.
 */

#ifndef SYSCALL_TYPES_H
#define SYSCALL_TYPES_H

#include <sys/types.h>
#include <unistd.h>

#define ARG_MAX 4096

// -------------------- FILE DESCRIPTORS --------------------
typedef struct {
  int oldfd;
  int ret_value;
} syscall_dup_values;

typedef struct {
  int oldfd;
  int newfd;
  int ret_value;
} syscall_dup2_values;

typedef struct {
  pid_t ret_value;
} syscall_getpid_getppid_values;

// -------------------- FILE I/O ----------------------------
typedef struct {
  char *pathname;
  int mode;
  int ret_value;
} syscall_access_values;

typedef struct {
  char *path;
  int ret_value;
} syscall_chdir_values;

typedef struct {
  unsigned int fd;
  long ret_value;
} syscall_close_values;

typedef struct {
  int fd;
  void *statbuf;
  int ret_value;
} syscall_fstat_values;

typedef struct {
  size_t size;
  char *buf;
  char *ret_value;
} syscall_getcwd_values;

typedef struct {
  int fd;
  off_t offset;
  unsigned int whence;
  off_t ret_value;
} syscall_lseek_values;

typedef struct {
  char *filename;
  void *statbuf;
  int ret_value;
} syscall_lstat_stat_values;

typedef struct {
  int dfd;
  char *filename;
  int flags;
  mode_t mode;
  int ret_value;
} syscall_openat_values;

typedef struct {
  int *pipefd;
  int ret_value;
} syscall_pipe_values;

typedef struct {
  unsigned int fd;
  size_t count;
  char *buffer;
  long ret_value;
} syscall_read_write_values;

// -------------------- NETWORKING --------------------------
typedef struct {
  int sockfd;
  void *addr;
  socklen_t addrlen;
  int ret_value;
} syscall_accept_connect_values;

typedef struct {
  int sockfd;
  void *addr;
  socklen_t addrlen;
  int ret_value;
} syscall_bind_values;

typedef struct {
  int sockfd;
  int backlog;
  int ret_value;
} syscall_listen_values;

typedef struct {
  int domain;
  int type;
  int protocol;
  int ret_value;
} syscall_socket_values;

// -------------------- PROCESSES ---------------------------
typedef struct {
  unsigned long addr;
  int ret_value;
} syscall_brk_values;

typedef struct {
  unsigned long flags;
  void *stack;
  int parent_tid;
  int child_tid;
  unsigned long tls;
  long ret_value;
} syscall_clone_values;

typedef struct {
  char *pathname;
  char *argv;
  char *envp;
  int ret_value;
} syscall_execve_values;

typedef struct {
  int error_code;
} syscall_exit_exitgroup_values;

typedef struct {
  pid_t ret_value;
} syscall_fork_values;

typedef struct {
  unsigned long addr;
  size_t length;
  int prot;
  int flags;
  int fd;
  off_t offset;
  void *ret_value;
} syscall_mmap_values;

typedef struct {
  unsigned long addr;
  size_t length;
  int ret_value;
} syscall_munmap_values;

typedef struct {
  // FILE DESCRIPTORS
  syscall_dup_values dup_values;
  syscall_dup2_values dup2_values;
  syscall_getpid_getppid_values getpid_getppid_values;
  // FILE I/O
  syscall_access_values access_values;
  syscall_chdir_values chdir_values;
  syscall_close_values close_values;
  syscall_fstat_values fstat_values;
  syscall_getcwd_values getcwd_values;
  syscall_lseek_values lseek_values;
  syscall_lstat_stat_values lstat_stat_values;
  syscall_openat_values openat_values;
  syscall_pipe_values pipe_values;
  syscall_read_write_values read_write_values;
  // NETWORKING
  syscall_accept_connect_values accept_connect_values;
  syscall_bind_values bind_values;
  syscall_listen_values listen_values;
  syscall_socket_values socket_values;
  // PROCESSES
  syscall_brk_values brk_values;
  syscall_clone_values clone_values;
  syscall_execve_values execve_values;
  syscall_exit_exitgroup_values exit_exitgroup_values;
  syscall_fork_values fork_values;
  syscall_mmap_values mmap_values;
  syscall_munmap_values munmap_values;
} syscalls_state;

#endif
