
#include "trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

void handle_read_write_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned int fd = regs->rdi;
  char *buffer = malloc(4096);
  read_string_arg(buffer, pid, regs->rsi);
  size_t count = regs->rdx;
  long ret_value = (long)regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_read) {
    printf("read(%u, %s, %zu) = %ld (%s)\n", fd, buffer, count, ret_value,
           errno_value);
  } else {
    printf("write(%u, %s, %zu) = %ld (%s)\n", fd, buffer, count, ret_value,
           errno_value);
  }
  free(buffer);
}

void handle_close_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned int fd = regs->rdi;
  long ret_value = (long)regs->rax;
  printf("close(%u) = %ld\n", fd, ret_value);
}

void handle_openat_in(pid_t pid, struct user_regs_struct *regs) {
  int dfd = regs->rdi;
  char *filename = malloc(4096);
  read_string_arg(filename, pid, regs->rsi);
  int flags = regs->rdx;
  mode_t mode = regs->r10;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("openat(%u, %s, %d, %u) = %d (%s)\n", dfd, filename, flags, mode, ret_value,
         errno_value);
  free(filename);
}

void handle_lseek_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned int fd = regs->rdi;
  off_t offset = regs->rsi;
  unsigned int whence = regs->rdx;
  off_t ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("lseek(%u, %ld, %d) = %ld (%s)\n", fd, offset, whence, ret_value,
         errno_value);
}

void handle_brk_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned long addr = regs->rdi;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("brk(%lu) = %d (%s)\n", addr, ret_value, errno_value);
}

void handle_mmap_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned long addr = regs->rdi;
  size_t length = regs->rsi;
  int prot = regs->rdx;
  int flags = regs->r10;
  int fd = regs->r8;
  off_t offset = regs->r9;
  void *ret_value = (void *)regs->rax;
  char *errno_value = "N/A";
  if (ret_value == (void *)-1) {
    errno_value = strerror(-(long)ret_value);
  }
  printf("mmap(%lu, %lu, %d, %d, %d, %ld) = %p (%s)\n", addr, length, prot,
         flags, fd, offset, ret_value, errno_value);
}

void handle_munmap_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned long addr = regs->rdi;
  size_t length = regs->rsi;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("munmap(%lu, %lu) = %d (%s)\n", addr, length, ret_value, errno_value);
}

void handle_exit_in(pid_t pid, struct user_regs_struct *regs) {
  int error_code = regs->rdi;
  if (regs->orig_rax == SYS_exit) {
    printf("exit(%d)\n", error_code);
  } else {
    printf("exit_group(%d)\n", error_code);
  }
}

void handle_getpid_in(pid_t pid, struct user_regs_struct *regs) {
  pid_t ret_value = regs->rax;
  if (regs->orig_rax == SYS_getpid) {
    printf("getpid() = %d\n", ret_value);
  } else {
    printf("getppid() = %d\n", ret_value);
  }
}

void handle_fork_in(pid_t pid, struct user_regs_struct *regs) {
  pid_t ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("fork() = %d (%s)\n", ret_value, errno_value);
}

void handle_clone_in(pid_t pid, struct user_regs_struct *regs) {
  unsigned long flags = regs->rdi;
  void *stack = (void *)regs->rsi;
  int *parent_tid = (int *)regs->rdx;
  int *child_tid = (int *)regs->r10;
  unsigned long tls = regs->r8;
  long ret_value = (long)regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("clone(%lu, %p, %p, %p, %lu) = %ld (%s)\n", flags, stack,
         (void *)parent_tid, (void *)child_tid, tls, ret_value, errno_value);
}

void handle_execve_in(pid_t pid, struct user_regs_struct *regs) {
  char *filename = malloc(4096);
  read_string_arg(filename, pid, regs->rdi);
  // ARGV AND ENVP ARE CHAR ARRAY ARRAYS, FIX THIS
  char *argv = malloc(4096);
  read_string_arg(argv, pid, regs->rsi);
  char *envp = malloc(4096);
  read_string_arg(envp, pid, regs->rdx);
  int ret_value = (int)regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("execve(%s, %s, %s) = %d (%s)\n", filename, argv, envp, ret_value,
         errno_value);
  free(filename);
  free(argv);
  free(envp);
}

void handle_stat_in(pid_t pid, struct user_regs_struct *regs) {
  char *filename = malloc(4096);
  read_string_arg(filename, pid, regs->rdi);
  void *statbuf = (void *)regs->rsi;
  int ret_value = (int)regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_stat) {
    printf("stat(%s, %p) = %d (%s)\n", filename, statbuf, ret_value,
           errno_value);
  } else {
    printf("lstat(%s, %p) = %d (%s)\n", filename, statbuf, ret_value,
           errno_value);
  }
  free(filename);
}

void handle_fstat_in(pid_t pid, struct user_regs_struct *regs) {
  int fd = (int)regs->rdi;
  void *statbuf = (void *)regs->rsi;
  int ret_value = (int)regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("fstat(%d, %p) = %d (%s)\n", fd, statbuf, ret_value, errno_value);
}

void handle_access_in(pid_t pid, struct user_regs_struct *regs) {
  char *pathname = malloc(4096);
  read_string_arg(pathname, pid, regs->rdi);
  int mode = (int)regs->rsi;
  int ret_value = (int)regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("access(%s, %d) = %d (%s)\n", pathname, mode, ret_value, errno_value);
  free(pathname);
}

void handle_getcwd_in(pid_t pid, struct user_regs_struct *regs) {
  char *buf = malloc(4096);
  read_string_arg(buf, pid, regs->rdi);
  size_t size = (size_t)regs->rsi;
  char *ret_value = malloc(4096);
  read_string_arg(ret_value, pid, regs->rax);
  char *errno_value = "N/A";
  if (ret_value == NULL) {
    errno_value = strerror(-regs->rax);
  }
  printf("getcwd(%s, %lu) = %s (%s)\n", buf, size, ret_value, errno_value);
  free(buf);
  free(ret_value);
}

void handle_chdir_in(pid_t pid, struct user_regs_struct *regs) {
  char *path = malloc(4096);
  read_string_arg(path, pid, regs->rdi);
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("chdir(%s) = %d, (%s)\n", path, ret_value, errno_value);
  free(path);
}

void handle_socket_in(pid_t pid, struct user_regs_struct *regs) {
  int domain = regs->rdi;
  int type = regs->rsi;
  int protocol = regs->rdx;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("socket(%d, %d, %d) = %d, (%s)\n", domain, type, protocol, ret_value,
         errno_value);
}

void handle_bind_in(pid_t pid, struct user_regs_struct *regs) {
  int sockfd = regs->rdi;
  void *addr = (void *)regs->rsi;
  socklen_t addrlen = regs->rdx;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("bind(%d, %p, %u) = %d (%s)\n", sockfd, addr, addrlen, ret_value,
         errno_value);
}

void handle_listen_in(pid_t pid, struct user_regs_struct *regs) {
  int sockfd = regs->rdi;
  int backlog = regs->rsi;
  int ret_value = regs->rax;

  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("listen(%d, %d) = %d (%s)\n", sockfd, backlog, ret_value, errno_value);
}

void handle_accept_in(pid_t pid, struct user_regs_struct *regs) {
  int sockfd = regs->rdi;
  void *addr = (void *)regs->rsi;
  socklen_t addrlen = regs->rdx;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_accept) {
    printf("accept(%d, %p, %u) = %d (%s)", sockfd, addr, addrlen, ret_value,
           errno_value);
  } else {
    printf("connect(%d, %p, %u) = %d (%s)", sockfd, addr, addrlen, ret_value,
           errno_value);
  }
}

void handle_pipe_in(pid_t pid, struct user_regs_struct *regs) {
  int pipefd[2];
  pipefd[0] = ptrace(PTRACE_PEEKDATA, pid, regs->rdi, NULL);
  pipefd[1] = ptrace(PTRACE_PEEKDATA, pid, regs->rdi + sizeof(int), NULL);

  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("pipe([%d, %d]) = %d (%s)", pipefd[0], pipefd[1], ret_value,
         errno_value);
}

void handle_dup_in(pid_t pid, struct user_regs_struct *regs) {
  int oldfd = regs->rdi;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("dup(%d) = %d (%s)", oldfd, ret_value, errno_value);
}

void handle_dup2_in(pid_t pid, struct user_regs_struct *regs) {
  int oldfd = regs->rdi;
  int newfd = regs->rsi;
  int ret_value = regs->rax;
  char *errno_value = "N/A";
  if (ret_value < 0) {
    errno_value = strerror(-regs->rax);
  }
  printf("dup2(%d, %d) = %d (%s)", oldfd, newfd, ret_value, errno_value);
}
