#ifndef SYSCALL_HANDLERS_H
#define SYSCALL_HANDLERS_H

#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

typedef struct {
  unsigned int fd;
  size_t count;
  char *buffer;
  long ret_value;
  char *errno_value;
} syscall_read_values;

typedef struct {
  unsigned int fd;
  long ret_value;
  char *errno_value;
} syscall_close_values;

typedef struct {
  int dfd;
  char *filename;
  int flags;
  mode_t mode;
  int ret_value;
  char *errno_value;
} syscall_openat_values;

typedef struct {
  int fd;
  off_t offset;
  unsigned int whence;
  off_t ret_value;
  char *errno_value;
} syscall_lseek_values;

typedef struct {
  unsigned long addr;
  int ret_value;
  char *errno_value;
} syscall_brk_values;

typedef struct {
  unsigned long addr;
  size_t length;
  int prot;
  int flags;
  int fd;
  off_t offset;
  void *ret_value;
  char *errno_value;
} syscall_mmap_values;

typedef struct {
  unsigned long addr;
  size_t length;
  int ret_value;
  char *errno_value;
} syscall_munmap_values;

typedef struct {
  int error_code;
} syscall_exit_values;

typedef struct {
  pid_t ret_value;
} syscall_getpid_values;

typedef struct {
  pid_t ret_value;
  char *errno_value;
} syscall_fork_values;

typedef struct {
  unsigned long flags;
  void *stack;
  int parent_tid;
  int child_tid;
  unsigned long tls;
  long ret_value;
  char *errno_value;
} syscall_clone_values;

typedef struct {
  char *pathname;
  char **argv;
  char **envp;
  int ret_value;
  char *errno_value;
} syscall_execve_values;

typedef struct {
  char *filename;
  void *statbuf;
  int ret_value;
  char *errno_value;
} syscall_stat_values;

typedef struct {
  int fd;
  void *statbuf;
  int ret_value;
  char *errno_value;
} syscall_fstat_values;

typedef struct {
  char *pathname;
  int mode;
  int ret_value;
  char *errno_value;
} syscall_access_values;

typedef struct {
  size_t size;
  char *buf;
  char *ret_value;
  char *errno_value;
} syscall_getcwd_values;

typedef struct {
  char *path;
  int ret_value;
  char *errno_value;
} syscall_chdir_values;

typedef struct {
  int domain;
  int type;
  int protocol;
  int ret_value;
  char *errno_value;
} syscall_socket_values;

typedef struct {
  int sockfd;
  void *addr;
  socklen_t addrlen;
  int ret_value;
  char *errno_value;
} syscall_bind_values;

typedef struct {
  int sockfd;
  int backlog;
  int ret_value;
  char *errno_value;
} syscall_listen_values;

typedef struct {
  int sockfd;
  void *addr;
  socklen_t addrlen;
  int ret_value;
  char *errno_value;
} syscall_accept_values;

typedef struct {
  int *pipefd;
  int ret_value;
  char *errno_value;
} syscall_pipe_values;

typedef struct {
  int oldfd;
  int ret_value;
  char *errno_value;
} syscall_dup_values;

typedef struct {
  int oldfd;
  int newfd;
  int ret_value;
  char *errno_value;
} syscall_dup2_values;

syscall_read_values read_values;
syscall_read_values write_values;
syscall_close_values close_values;
syscall_openat_values openat_values;
syscall_lseek_values lseek_values;
syscall_brk_values brk_values;
syscall_mmap_values mmap_values;
syscall_munmap_values munmap_values;
syscall_exit_values exit_values;
syscall_getpid_values getpid_values;
syscall_fork_values fork_values;
syscall_clone_values clone_values;
syscall_execve_values execve_values;
syscall_stat_values stat_values;
syscall_fstat_values fstat_values;
syscall_access_values access_values;
syscall_getcwd_values getcwd_values;
syscall_chdir_values chdir_values;
syscall_socket_values socket_values;
syscall_bind_values bind_values;
syscall_listen_values listen_values;
syscall_accept_values accept_values;
syscall_pipe_values pipe_values;
syscall_dup_values dup_values;
syscall_dup2_values dup2_values;

void handle_read_write_entry(pid_t pid, struct user_regs_struct *regs);
void handle_close_entry(pid_t pid, struct user_regs_struct *regs);
void handle_openat_entry(pid_t pid, struct user_regs_struct *regs);
void handle_lseek_entry(pid_t pid, struct user_regs_struct *regs);
void handle_brk_entry(pid_t pid, struct user_regs_struct *regs);
void handle_mmap_entry(pid_t pid, struct user_regs_struct *regs);
void handle_munmap_entry(pid_t pid, struct user_regs_struct *regs);
void handle_exit_entry(pid_t pid, struct user_regs_struct *regs);
void handle_getpid_entry(pid_t pid, struct user_regs_struct *regs);
void handle_fork_entry(pid_t pid, struct user_regs_struct *regs);
void handle_clone_entry(pid_t pid, struct user_regs_struct *regs);
void handle_execve_entry(pid_t pid, struct user_regs_struct *regs);
void handle_stat_entry(pid_t pid, struct user_regs_struct *regs);
void handle_fstat_entry(pid_t pid, struct user_regs_struct *regs);
void handle_lstat_entry(pid_t pid, struct user_regs_struct *regs);
void handle_access_entry(pid_t pid, struct user_regs_struct *regs);
void handle_getcwd_entry(pid_t pid, struct user_regs_struct *regs);
void handle_chdir_entry(pid_t pid, struct user_regs_struct *regs);
void handle_socket_entry(pid_t pid, struct user_regs_struct *regs);
void handle_bind_entry(pid_t pid, struct user_regs_struct *regs);
void handle_listen_entry(pid_t pid, struct user_regs_struct *regs);
void handle_accept_entry(pid_t pid, struct user_regs_struct *regs);
void handle_connect_entry(pid_t pid, struct user_regs_struct *regs);
void handle_pipe_entry(pid_t pid, struct user_regs_struct *regs);
void handle_dup_entry(pid_t pid, struct user_regs_struct *regs);
void handle_dup2_entry(pid_t pid, struct user_regs_struct *regs);

void handle_read_write_exit(pid_t pid, struct user_regs_struct *regs);
void handle_close_exit(pid_t pid, struct user_regs_struct *regs);
void handle_openat_exit(pid_t pid, struct user_regs_struct *regs);
void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs);
void handle_brk_exit(pid_t pid, struct user_regs_struct *regs);
void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs);
void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs);
void handle_exit_exit(pid_t pid, struct user_regs_struct *regs);
void handle_getpid_exit(pid_t pid, struct user_regs_struct *regs);
void handle_fork_exit(pid_t pid, struct user_regs_struct *regs);
void handle_clone_exit(pid_t pid, struct user_regs_struct *regs);
void handle_execve_exit(pid_t pid, struct user_regs_struct *regs);
void handle_stat_exit(pid_t pid, struct user_regs_struct *regs);
void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs);
void handle_lstat_exit(pid_t pid, struct user_regs_struct *regs);
void handle_access_exit(pid_t pid, struct user_regs_struct *regs);
void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs);
void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs);
void handle_socket_exit(pid_t pid, struct user_regs_struct *regs);
void handle_bind_exit(pid_t pid, struct user_regs_struct *regs);
void handle_listen_exit(pid_t pid, struct user_regs_struct *regs);
void handle_accept_exit(pid_t pid, struct user_regs_struct *regs);
void handle_connect_exit(pid_t pid, struct user_regs_struct *regs);
void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs);
void handle_dup_exit(pid_t pid, struct user_regs_struct *regs);
void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs);

#endif
