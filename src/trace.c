/*
 * trace.c
 *
 * Core tracing loop for monitoring system calls made by the traced process.
 *
 * OVERVIEW:
 * This file implements the main tracing logic used by Linux's ptrace per stop.
 * Ptrace allows the parent process to observe and control execution of the
 * child process.
 *
 * KEY CONCEPTS:
 * - ptrace stops the traced process twice per syscall when run with the
 * PTRACE_SYSCALL option
 *
 * - At entry, we capture arguments from parameters that will not be modified
 * when the syscall is run
 *
 * - At exit, we capture the return value and any parameters that the syscall
 * modified
 *
 * REGISTER USAGE (x86_64 calling convention):
 * - rax: syscall number (orig_rax) and return value
 * - rdi: 1st argument
 * - rsi: 2nd argument
 * - rdx: 3rd argument
 * - r10: 4th argument
 * - r8:  5th argument
 * - r9:  6th argument
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "syscall_handlers.h"
#include "syscall_types.h"

/**
 * handle_syscalls_entry - Process syscall at entry point
 * @child: PID of the traced process
 * @regs: CPU register state at syscall entry
 * @state: Stores captured register values in the types
 * specified by the call's manual
 *
 * Called when the traced process enters a system call, before the kernel
 * has executed it. At this point, registers contain the original arguments
 * passed by the program. Some syscalls (like read) have a buffer parameter that
 * only contains useful data at exit, so the handling logic for a syscall can
 * differ vastly based on it's implementation.
 *
 * We capture arguments here because:
 * 1. Register values may be overwritten during syscall execution
 * 2. Pointers in registers may become invalid after the syscall
 * 3. We need the "before" state to pair with the "after" state at exit
 *
 * Note: Not all syscalls have entry handlers (e.g., fork and getpid take no
 * parameters)
 */
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

  // -------------------- FILE I/O ----------------------------
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

  // -------------------- NETWORKING --------------------------
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

  // -------------------- PROCESSES ---------------------------
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

/**
 * handle_syscalls_exit - Process syscall at exit point
 * @child: PID of the traced process
 * @regs: CPU register state at syscall exit
 * @state: Stores captured register values in the types
 * specified by the call's manual
 *
 * Called when the traced process exits a system call, after the kernel
 * has executed it. At this point, we parse the register values for what the
 * syscall returned and the parameters that it modified. Once all values have
 * been parsed, we print the data we've gathered in the following format:
 *
 * CALL_NAME(arg1, arg2, arg3) = ret_value
 *
 * If the syscall returns a negative value, indicating error, the string
 * corresponding to errno is appended to the output before a newline.
 */
static void handle_syscalls_exit(pid_t child, struct user_regs_struct *regs,
                                 syscalls_state *state) {
  switch (regs->orig_rax) {
  // -------------------- FILE DESCRIPTORS --------------------
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

  // -------------------- NETWORKING --------------------
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

/**
 * trace_child - Main tracing loop
 * @child: PID of the traced process
 * @isAttached: true if attached to existing process, false if we started a new
 * one
 *
 * This implements the tracing loop that monitors all system calls made by the
 * traced process. It runs until the process exits or is terminated by the
 * kernel.
 *
 * PTRACE_SYSCALL stops twice per syscall:
 * - Once when entering (before kernel executes it)
 * - Once when exiting (after kernel executes it)
 *
 * OTHER STOPS:
 * Besides syscall stops, other events can trigger a stop. For the purposes of
 * this project, only the stop generated by the process calling execve is
 * considered.
 *
 */
void trace_child(pid_t child, bool isAttached) {
  int status;                    // Status returned by wait()
  bool entering_syscall = false; // Toggle between entry and exit
  bool first_stop = true;
  syscalls_state state = {0}; // Persistent state for syscall arguments

  while (1) {
    /*
     * PTRACE_SYSCALL requests that ptrace stop twice per syscall (entry and
     * exit). The process will run until the next syscall boundary or until it
     * exits/receives a signal.
     *
     * Arguments:
     *   PTRACE_SYSCALL: Request syscall-stop mode
     *   child: PID of traced process
     *   NULL: Not used for PTRACE_SYSCALL
     *   NULL: Signal to deliver (0 = none)
     *
     * ESRCH (No Such Process) errors can occur if the process exited
     * between our last check and now. These are ignored because wait()
     * will handle reaping the zombie process.
     */
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1 && errno != ESRCH) {
      fprintf(stderr, "PTRACE_SYSCALL Failed: %s\n", strerror(errno));
      return;
    }
    /*
     * wait() blocks until the traced process stops. It returns the PID
     * of the process that stopped and fills status with information
     * about why it stopped.
     *
     * Possible stop reasons:
     * - Syscall entry (due to PTRACE_SYSCALL)
     * - Syscall exit (due to PTRACE_SYSCALL)
     * - Signal delivery (SIGTRAP for ptrace events, or other signals)
     * - Process exit
     */
    if (wait(&status) == -1) {
      fprintf(stderr, "Wait Failed: %s\n", strerror(errno));
      return;
    }

    /*
     * We cease tracing if the process has been terminated.
     * WIFEXITED returns true if the process calls exit() or returns from main.
     * WIFSIGNALED returns true if the process was terminated by a signal.
     */
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
    /*
     * PTRACE_GETREGS fills the user_regs_struct with the current values
     * of all CPU registers at the stop point.
     */
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

    // We dispatch to the appropriate handler
    if (entering_syscall) {
      // At entry, we read input parameters into our state
      handle_syscalls_entry(child, &regs, &state);
    } else {
      /*
       * At exit, we read any output parameters and the return value into our
       * state. We then print the information we've gathered for the syscall,
       * including the relevant errno string if the call fails.
       */
      handle_syscalls_exit(child, &regs, &state);
    }
    /*
     * Flip the entry/exit state so we process the next stop correctly.
     * This works because PTRACE_SYSCALL guarantees stops alternate
     * between entry and exit.
     */
    entering_syscall = !entering_syscall;
  }
}
