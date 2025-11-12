#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "syscall_handlers.h"
#include "syscall_types.h"

void handle_syscalls_entry(pid_t child, struct user_regs_struct *regs,
                           syscalls_state *state) {
  switch (regs->orig_rax) {
  case SYS_read:
    handle_read_entry(child, regs, state);
    break;
  case SYS_write:
    handle_write_entry(child, regs, state);
    break;
  case SYS_close:
    handle_close_entry(child, regs, state);
    break;
  case SYS_exit:
  case SYS_exit_group:
    handle_exit_entry(child, regs, state);
    break;
  case SYS_openat:
    handle_openat_entry(child, regs, state);
    break;
  case SYS_lseek:
    handle_lseek_entry(child, regs, state);
    break;
  case SYS_mmap:
    handle_mmap_entry(child, regs, state);
    break;
  case SYS_munmap:
    handle_munmap_entry(child, regs, state);
    break;
  case SYS_brk:
    handle_brk_entry(child, regs, state);
    break;
  case SYS_execve:
    handle_execve_entry(child, regs, state);
    break;
  case SYS_stat:
  case SYS_lstat:
    handle_stat_entry(child, regs, state);
    break;
  case SYS_fstat:
    handle_fstat_entry(child, regs, state);
    break;
  case SYS_access:
    handle_access_entry(child, regs, state);
    break;
  case SYS_getcwd:
    handle_getcwd_entry(child, regs, state);
    break;
  case SYS_chdir:
    handle_chdir_entry(child, regs, state);
    break;
  case SYS_socket:
    handle_socket_entry(child, regs, state);
    break;
  case SYS_bind:
    handle_bind_entry(child, regs, state);
    break;
  case SYS_listen:
    handle_listen_entry(child, regs, state);
    break;
  case SYS_accept:
  case SYS_connect:
    handle_accept_entry(child, regs, state);
    break;
  case SYS_dup:
    handle_dup_entry(child, regs, state);
    break;
  case SYS_dup2:
    handle_dup2_entry(child, regs, state);
    break;
  }
}

void handle_syscalls_exit(pid_t child, struct user_regs_struct *regs,
                          syscalls_state *state) {
  switch (regs->orig_rax) {
  case SYS_read:
    handle_read_exit(child, regs, state);
    break;
  case SYS_write:
    handle_write_exit(child, regs, state);
    break;
  case SYS_close:
    handle_close_exit(child, regs, state);
    break;
  case SYS_exit:
  case SYS_exit_group:
    handle_exit_exit(child, regs, state);
    break;
  case SYS_openat:
    handle_openat_exit(child, regs, state);
    break;
  case SYS_lseek:
    handle_lseek_exit(child, regs, state);
    break;
  case SYS_mmap:
    handle_mmap_exit(child, regs, state);
    break;
  case SYS_munmap:
    handle_munmap_exit(child, regs, state);
    break;
  case SYS_brk:
    handle_brk_exit(child, regs, state);
    break;
  case SYS_getpid:
  case SYS_getppid:
    handle_getpid_exit(child, regs, state);
    break;
  case SYS_fork:
    handle_fork_exit(child, regs, state);
    break;
  case SYS_execve:
    handle_execve_exit(child, regs, state);
    break;
  case SYS_stat:
  case SYS_lstat:
    handle_stat_exit(child, regs, state);
    break;
  case SYS_fstat:
    handle_fstat_exit(child, regs, state);
    break;
  case SYS_access:
    handle_access_exit(child, regs, state);
    break;
  case SYS_getcwd:
    handle_getcwd_exit(child, regs, state);
    break;
  case SYS_chdir:
    handle_chdir_exit(child, regs, state);
    break;
  case SYS_socket:
    handle_socket_exit(child, regs, state);
    break;
  case SYS_bind:
    handle_bind_exit(child, regs, state);
    break;
  case SYS_listen:
    handle_listen_exit(child, regs, state);
    break;
  case SYS_accept:
  case SYS_connect:
    handle_accept_exit(child, regs, state);
    break;
  case SYS_pipe:
    handle_pipe_exit(child, regs, state);
    break;
  case SYS_dup:
    handle_dup_exit(child, regs, state);
    break;
  case SYS_dup2:
    handle_dup2_exit(child, regs, state);
    break;
  }
}

void trace_child(pid_t child) {
  int status;
  bool entering_syscall = true;
  syscalls_state state;
  while (1) {
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    wait(&status);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      break;
    }
    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
      continue;
    }
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);

    if (entering_syscall) {
      handle_syscalls_entry(child, &regs, &state);
      if (regs.orig_rax == SYS_execve) {
      } else {
        entering_syscall = !entering_syscall;
      }
    } else {
      handle_syscalls_exit(child, &regs, &state);
      entering_syscall = !entering_syscall;
    }
  }
}
