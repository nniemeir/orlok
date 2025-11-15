#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "syscall_handlers.h"
#include "syscall_types.h"

static void handle_syscalls_entry(pid_t child, struct user_regs_struct *regs,
                                  syscalls_state *state) {
  switch (regs->orig_rax) {
  // -------------------- FILE DESCRIPTORS --------------------
  case SYS_dup:
    handle_dup_entry(child, regs, state);
    break;
  case SYS_dup2:
    handle_dup2_entry(child, regs, state);
    break;

  // -------------------- FILE I/O --------------------
  case SYS_access:
    handle_access_entry(child, regs, state);
    break;
  case SYS_chdir:
    handle_chdir_entry(child, regs, state);
    break;
  case SYS_close:
    handle_close_entry(child, regs, state);
    break;
  case SYS_fstat:
    handle_fstat_entry(child, regs, state);
    break;
  case SYS_getcwd:
    handle_getcwd_entry(child, regs, state);
    break;
  case SYS_lseek:
    handle_lseek_entry(child, regs, state);
    break;
  case SYS_lstat:
  case SYS_stat:
    handle_lstat_stat_entry(child, regs, state);
    break;
  case SYS_openat:
    handle_openat_entry(child, regs, state);
    break;
  case SYS_read:
    handle_read_entry(child, regs, state);
    break;
  case SYS_write:
    handle_write_entry(child, regs, state);
    break;

  // -------------------- NETWORKING --------------------
  case SYS_accept:
  case SYS_connect:
    handle_accept_connect_entry(child, regs, state);
    break;
  case SYS_bind:
    handle_bind_entry(child, regs, state);
    break;
  case SYS_listen:
    handle_listen_entry(child, regs, state);
    break;
  case SYS_socket:
    handle_socket_entry(child, regs, state);
    break;

  // -------------------- PROCESSES --------------------
  case SYS_brk:
    handle_brk_entry(child, regs, state);
    break;
  case SYS_clone:
    handle_clone_entry(child, regs, state);
    break;
  case SYS_execve:
    handle_execve_entry(child, regs, state);
    break;
  case SYS_exit:
  case SYS_exit_group:
    handle_exit_exitgroup_entry(child, regs, state);
    break;
  case SYS_mmap:
    handle_mmap_entry(child, regs, state);
    break;
  case SYS_munmap:
    handle_munmap_entry(child, regs, state);
    break;
  }
}
static void handle_syscalls_exit(pid_t child, struct user_regs_struct *regs,
                                 syscalls_state *state) {
  switch (regs->orig_rax) {
  // FILE DESCRIPTORS
  case SYS_dup:
    handle_dup_exit(child, regs, state);
    break;
  case SYS_dup2:
    handle_dup2_exit(child, regs, state);
    break;
  case SYS_getpid:
  case SYS_getppid:
    handle_getpid_getppid_exit(child, regs, state);
    break;

  // FILE I/O
  case SYS_access:
    handle_access_exit(child, regs, state);
    break;
  case SYS_chdir:
    handle_chdir_exit(child, regs, state);
    break;
  case SYS_close:
    handle_close_exit(child, regs, state);
    break;
  case SYS_fstat:
    handle_fstat_exit(child, regs, state);
    break;
  case SYS_getcwd:
    handle_getcwd_exit(child, regs, state);
    break;
  case SYS_lseek:
    handle_lseek_exit(child, regs, state);
    break;
  case SYS_lstat:
  case SYS_stat:
    handle_lstat_stat_exit(child, regs, state);
    break;
  case SYS_openat:
    handle_openat_exit(child, regs, state);
    break;
  case SYS_pipe:
    handle_pipe_exit(child, regs, state);
    break;
  case SYS_read:
    handle_read_exit(child, regs, state);
    break;
  case SYS_write:
    handle_write_exit(child, regs, state);
    break;

  // NETWORKING
  case SYS_accept:
  case SYS_connect:
    handle_accept_connect_exit(child, regs, state);
    break;
  case SYS_bind:
    handle_bind_exit(child, regs, state);
    break;
  case SYS_listen:
    handle_listen_exit(child, regs, state);
    break;
  case SYS_socket:
    handle_socket_exit(child, regs, state);
    break;

  // PROCESSES
  case SYS_brk:
    handle_brk_exit(child, regs, state);
    break;
  case SYS_clone:
    handle_clone_exit(child, regs, state);
    break;
  case SYS_execve:
    handle_execve_exit(child, regs, state);
    break;
  case SYS_exit:
  case SYS_exit_group:
    handle_exit_exitgroup_exit(child, regs, state);
    break;
  case SYS_fork:
    handle_fork_exit(child, regs, state);
    break;
  case SYS_mmap:
    handle_mmap_exit(child, regs, state);
    break;
  case SYS_munmap:
    handle_munmap_exit(child, regs, state);
    break;
  }
}

void trace_child(pid_t child, int isAttached) {
  int status;
  bool entering_syscall = false;
  bool first_stop = true;
  syscalls_state state = {0};

  while (1) {
    // PTRACE_SYSCALL requests that ptrace stop twice per syscall (entry & exit)
    // ESRCH (No Such Process) is ignored as wait will handle reaping zombie
    // processes.
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1 && errno != ESRCH) {
      fprintf(stderr, "PTRACE_SYSCALL Failed: %s\n", strerror(errno));
      return;
    }

    if (wait(&status) == -1) {
      fprintf(stderr, "Wait Failed: %s\n", strerror(errno));
      return;
    }

    // The trace ceases if the process exits
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      break;
    }

    /* The kernel encodes ptrace event codes in the status returned by wait().
     The signal number is in the low 8 bits, and the ptrace codes are in the
     higher bits. When execve is run, it sends a SIGTRAP signal that triggers
     ptrace to stop. This stop doesn't provide relevant data to analyze, so we
     ignore it and continue.
    */
    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
      entering_syscall = !entering_syscall;
      continue;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
      fprintf(stderr, "PTRACE_GETREGS Failed: %s\n", strerror(errno));
      return;
    }

    // The tracer is first notified when execve has successfully replaced the
    // process image, before the new program begins execution
    if (first_stop && !isAttached) {
      first_stop = false;
      entering_syscall = !entering_syscall;
      continue;
    }

    if (entering_syscall) {
      handle_syscalls_entry(child, &regs, &state);
    } else {
      handle_syscalls_exit(child, &regs, &state);
    }

    entering_syscall = !entering_syscall;
  }
}
