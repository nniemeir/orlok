#include "syscall_handlers.h"
#include "syscalls_table.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void handle_syscalls_in(pid_t child, struct user_regs_struct *regs) {
  switch (regs->orig_rax) {
  case SYS_read:
  case SYS_write:
    handle_read_write_in(child, regs);
    break;
  case SYS_close:
    handle_close_in(child, regs);
    break;
  case SYS_exit:
  case SYS_exit_group:
    handle_exit_in(child, regs);
    break;
  case SYS_openat:
    handle_openat_in(child, regs);
    break;
  case SYS_lseek:
    handle_lseek_in(child, regs);
    break;
  case SYS_mmap:
    handle_mmap_in(child, regs);
    break;
  case SYS_munmap:
    handle_munmap_in(child, regs);
    break;
  case SYS_brk:
    handle_brk_in(child, regs);
    break;
  case SYS_getpid:
  case SYS_getppid:
    handle_getpid_in(child, regs);
    break;
  case SYS_fork:
    handle_fork_in(child, regs);
    break;
  case SYS_execve:
    handle_execve_in(child, regs);
    break;
  case SYS_stat:
  case SYS_lstat:
    handle_stat_in(child, regs);
    break;
  case SYS_fstat:
    handle_fstat_in(child, regs);
    break;
  case SYS_access:
    handle_access_in(child, regs);
    break;
  case SYS_getcwd:
    handle_getcwd_in(child, regs);
    break;
  case SYS_chdir:
    handle_chdir_in(child, regs);
    break;
  case SYS_socket:
    handle_socket_in(child, regs);
    break;
  case SYS_bind:
    handle_bind_in(child, regs);
    break;
  case SYS_listen:
    handle_listen_in(child, regs);
    break;
  case SYS_accept:
  case SYS_connect:
    handle_accept_in(child, regs);
    break;
  case SYS_pipe:
    handle_pipe_in(child, regs);
    break;
  case SYS_dup:
    handle_dup_in(child, regs);
    break;
  case SYS_dup2:
    handle_dup2_in(child, regs);
    break;
  }
}

void handle_syscalls_out(pid_t child, struct user_regs_struct *regs) {
  switch (regs->orig_rax) {
  case SYS_read:
  case SYS_write:
    handle_read_write_out(child, regs);
    break;
  case SYS_close:
    handle_close_out(child, regs);
    break;
  case SYS_exit:
  case SYS_exit_group:
    handle_exit_out(child, regs);
    break;
  case SYS_openat:
    handle_openat_out(child, regs);
    break;
  case SYS_lseek:
    handle_lseek_out(child, regs);
    break;
  case SYS_mmap:
    handle_mmap_out(child, regs);
    break;
  case SYS_munmap:
    handle_munmap_out(child, regs);
    break;
  case SYS_brk:
    handle_brk_out(child, regs);
    break;
  case SYS_getpid:
  case SYS_getppid:
    handle_getpid_out(child, regs);
    break;
  case SYS_fork:
    handle_fork_out(child, regs);
    break;
  case SYS_execve:
    handle_execve_out(child, regs);
    break;
  case SYS_stat:
  case SYS_lstat:
    handle_stat_out(child, regs);
    break;
  case SYS_fstat:
    handle_fstat_out(child, regs);
    break;
  case SYS_access:
    handle_access_out(child, regs);
    break;
  case SYS_getcwd:
    handle_getcwd_out(child, regs);
    break;
  case SYS_chdir:
    handle_chdir_out(child, regs);
    break;
  case SYS_socket:
    handle_socket_out(child, regs);
    break;
  case SYS_bind:
    handle_bind_out(child, regs);
    break;
  case SYS_listen:
    handle_listen_out(child, regs);
    break;
  case SYS_accept:
  case SYS_connect:
    handle_accept_out(child, regs);
    break;
  case SYS_pipe:
    handle_pipe_out(child, regs);
    break;
  case SYS_dup:
    handle_dup_out(child, regs);
    break;
  case SYS_dup2:
    handle_dup2_out(child, regs);
    break;
  }
}

void trace_child(pid_t child) {
  int status;
  bool entering_syscall = false;
  while (1) {
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    wait(&status);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      break;
    }
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    if (entering_syscall == true) {
      handle_syscalls_in(child, &regs);
    } else {
      handle_syscalls_out(child, &regs);
    }
    entering_syscall = !entering_syscall;
  }
}
