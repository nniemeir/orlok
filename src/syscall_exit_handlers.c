#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "syscall_handlers.h"
#include "syscall_types.h"
#include "trace.h"

// Raw syscalls return -errno on error (e.g. -2 for ENOENT)
// Their glibc wrappers return -1 on error and set errno
void print_errno(unsigned long long rax) {
  if ((long)rax < 0) {
    printf("(%s)\n", strerror(-(int)rax));
  } else {
    printf("\n");
  }
}

void handle_read_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  state->read_values.buffer = malloc(ARG_MAX);
  if (!state->read_values.buffer) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->read_values.buffer, pid, regs->rsi);
  state->read_values.ret_value = (long)regs->rax;
  printf("read(%u, \"%s\", %zu) = %ld ", state->read_values.fd,
         state->read_values.buffer, state->read_values.count,
         state->read_values.ret_value);
  print_errno(regs->rax);
  free(state->read_values.buffer);
}

void handle_write_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->write_values.ret_value = (long)regs->rax;
  printf("write(%u, \"%s\", %zu) = %ld ", state->write_values.fd,
         state->write_values.buffer, state->write_values.count,
         state->write_values.ret_value);
  print_errno(regs->rax);
  free(state->write_values.buffer);
}

void handle_close_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->close_values.ret_value = (long)regs->rax;
  printf("close(%u) = %ld ", state->close_values.fd,
         state->close_values.ret_value);
  print_errno(regs->rax);
}

void handle_openat_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->openat_values.ret_value = (int)regs->rax;
  printf("openat(%u, \"%s\", %d, %u) = %d ", state->openat_values.dfd,
         state->openat_values.filename, state->openat_values.flags,
         state->openat_values.mode, state->openat_values.ret_value);
  print_errno(regs->rax);
  free(state->openat_values.filename);
}

void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->lseek_values.ret_value = (off_t)regs->rax;
  printf("lseek(%u, %ld, %d) = %ld ", state->lseek_values.fd,
         state->lseek_values.offset, state->lseek_values.whence,
         state->lseek_values.ret_value);
  print_errno(regs->rax);
}

void handle_brk_exit(pid_t pid, struct user_regs_struct *regs,
                     syscalls_state *state) {
  (void)pid;
  state->brk_values.ret_value = (int)regs->rax;
  printf("brk(%lu) = %d ", state->brk_values.addr, state->brk_values.ret_value);
  print_errno(regs->rax);
}

void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->mmap_values.ret_value = (void *)regs->rax;
  printf("mmap(%lu, %lu, %d, %d, %d, %ld) = %p ", state->mmap_values.addr,
         state->mmap_values.length, state->mmap_values.prot,
         state->mmap_values.flags, state->mmap_values.fd,
         state->mmap_values.offset, state->mmap_values.ret_value);
  print_errno(regs->rax);
}

void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->munmap_values.ret_value = (int)regs->rax;
  printf("munmap(%lu, %lu) = %d ", state->munmap_values.addr,
         state->munmap_values.length, state->munmap_values.ret_value);
  print_errno(regs->rax);
}

void handle_exit_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  if (regs->orig_rax == SYS_exit) {
    printf("exit(%d)\n", state->exit_values.error_code);
  } else {
    printf("exit_group(%d)\n", state->exit_values.error_code);
  }
}

void handle_getpid_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->getpid_values.ret_value = (pid_t)regs->rax;
  if (regs->orig_rax == SYS_getpid) {
    printf("getpid() = %d\n", state->getpid_values.ret_value);
  } else {
    printf("getppid() = %d\n", state->getpid_values.ret_value);
  }
}

void handle_fork_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->fork_values.ret_value = (pid_t)regs->rax;
  printf("fork() = %d ", state->fork_values.ret_value);
  print_errno(regs->rax);
}

void handle_clone_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->clone_values.ret_value = (long)regs->rax;
  printf("clone(%lu, %p, %d, %d, %lu) = %ld ", state->clone_values.flags,
         state->clone_values.stack, state->clone_values.parent_tid,
         state->clone_values.child_tid, state->clone_values.tls,
         state->clone_values.ret_value);
  print_errno(regs->rax);
}

void handle_execve_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->execve_values.ret_value = (int)regs->rax;
  printf("execve(\"%s\", %s, %s) = %d ", state->execve_values.pathname,
         state->execve_values.argv, state->execve_values.envp,
         state->execve_values.ret_value);
  print_errno(regs->rax);
  free(state->execve_values.pathname);
}

void handle_stat_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->stat_values.statbuf = (void *)regs->rsi;
  state->stat_values.ret_value = (int)regs->rax;
  if (regs->orig_rax == SYS_stat) {
    printf("stat(\"%s\", %p) = %d ", state->stat_values.filename,
           state->stat_values.statbuf, state->stat_values.ret_value);
  } else {
    printf("lstat(\"%s\", %p) = %d ", state->stat_values.filename,
           state->stat_values.statbuf, state->stat_values.ret_value);
  }
  print_errno(regs->rax);
  free(state->stat_values.filename);
}

void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->fstat_values.statbuf = (void *)regs->rsi;
  state->fstat_values.ret_value = (int)regs->rax;
  printf("fstat(%d, %p) = %d ", state->fstat_values.fd,
         state->fstat_values.statbuf, state->fstat_values.ret_value);
  print_errno(regs->rax);
}

void handle_access_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->access_values.ret_value = (int)regs->rax;
  printf("access(\"%s\", %d) = %d ", state->access_values.pathname,
         state->access_values.mode, state->access_values.ret_value);
  print_errno(regs->rax);
  free(state->access_values.pathname);
}

void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  state->getcwd_values.buf = malloc(ARG_MAX);
  if (!state->getcwd_values.buf) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->getcwd_values.buf, pid, regs->rdi);
  state->getcwd_values.ret_value = malloc(ARG_MAX);
  if (!state->getcwd_values.ret_value) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->getcwd_values.ret_value, pid, regs->rax);
  printf("getcwd(\"%s\", %lu) = %s ", state->getcwd_values.buf,
         state->getcwd_values.size, state->getcwd_values.ret_value);
  print_errno(regs->rax);
  free(state->getcwd_values.buf);
  free(state->getcwd_values.ret_value);
}

void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->chdir_values.ret_value = (int)regs->rax;
  printf("chdir(\"%s\") = %d ", state->chdir_values.path,
         state->chdir_values.ret_value);
  print_errno(regs->rax);
  free(state->chdir_values.path);
}

void handle_socket_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->socket_values.ret_value = (int)regs->rax;
  printf("socket(%d, %d, %d) = %d ", state->socket_values.domain,
         state->socket_values.type, state->socket_values.protocol,
         state->socket_values.ret_value);
  print_errno(regs->rax);
}

void handle_bind_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->bind_values.ret_value = (int)regs->rax;
  printf("bind(%d, %p, %u) = %d ", state->bind_values.sockfd,
         state->bind_values.addr, state->bind_values.addrlen,
         state->bind_values.ret_value);
  print_errno(regs->rax);
}

void handle_listen_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->listen_values.ret_value = (int)regs->rax;
  printf("listen(%d, %d) = %d ", state->listen_values.sockfd,
         state->listen_values.backlog, state->listen_values.ret_value);
  print_errno(regs->rax);
}

void handle_accept_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->accept_values.ret_value = (int)regs->rax;
  if (regs->orig_rax == SYS_accept) {
    printf("accept(%d, %p, %u) = %d ", state->accept_values.sockfd,
           state->accept_values.addr, state->accept_values.addrlen,
           state->accept_values.ret_value);
  } else {
    printf("connect(%d, %p, %u) = %d ", state->accept_values.sockfd,
           state->accept_values.addr, state->accept_values.addrlen,
           state->accept_values.ret_value);
  }
  print_errno(regs->rax);
}

void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  errno = 0;
  state->pipe_values.pipefd[0] =
      (int)ptrace(PTRACE_PEEKDATA, pid, regs->rdi, NULL);
  if (errno != 0) {
    fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
  }
  errno = 0;
  state->pipe_values.pipefd[1] =
      (int)ptrace(PTRACE_PEEKDATA, pid, regs->rdi + sizeof(int), NULL);
  if (errno != 0) {
    fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
  }
  state->pipe_values.ret_value = (int)regs->rax;
  printf("pipe([%d, %d]) = %d ", state->pipe_values.pipefd[0],
         state->pipe_values.pipefd[1], state->pipe_values.ret_value);
  print_errno(regs->rax);
}

void handle_dup_exit(pid_t pid, struct user_regs_struct *regs,
                     syscalls_state *state) {
  (void)pid;
  state->dup_values.ret_value = (int)regs->rax;
  printf("dup(%d) = %d ", state->dup_values.oldfd, state->dup_values.ret_value);
  print_errno(regs->rax);
}

void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->dup2_values.ret_value = (int)regs->rax;
  printf("dup2(%d, %d) = %d ", state->dup2_values.oldfd,
         state->dup2_values.newfd, state->dup2_values.ret_value);
  print_errno(regs->rax);
}
