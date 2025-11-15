/**
 * syscall_handlers.h
 *
 * Handler functions for system call entry and exit points during process
 * tracing.
 *
 * Entry handlers grab the register values representing arguments that
 * won't change when the syscall runs.
 *
 * Exit handlers read return values and any
 * modified register values after completion.
 *
 * Some syscalls share handling
 * functions, as they behave identically from the perspective of the tracer.
 */

#ifndef SYSCALL_HANDLERS_H
#define SYSCALL_HANDLERS_H

#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include "syscall_types.h"

// -------------------- FILE DESCRIPTORS --------------------
// Entry Handlers
void handle_dup_entry(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_dup2_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
// Exit Handlers
void handle_dup_exit(pid_t pid, struct user_regs_struct *regs,
                     syscalls_state *state);
void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_getpid_getppid_exit(pid_t pid, struct user_regs_struct *regs,
                                syscalls_state *state);
// -------------------- FILE I/O ----------------------------
// Entry Handlers
void handle_access_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
void handle_chdir_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_close_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_fstat_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_getcwd_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
void handle_lseek_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_lstat_stat_entry(pid_t pid, struct user_regs_struct *regs,
                             syscalls_state *state);
void handle_openat_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
void handle_read_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_write_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
// Exit Handlers
void handle_access_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_close_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_lstat_stat_exit(pid_t pid, struct user_regs_struct *regs,
                            syscalls_state *state);
void handle_openat_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_read_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_write_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
// -------------------- NETWORKING --------------------------
// Entry Handlers
void handle_accept_connect_entry(pid_t pid, struct user_regs_struct *regs,
                                 syscalls_state *state);
void handle_bind_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_listen_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
void handle_socket_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
// Exit Handlers
void handle_accept_connect_exit(pid_t pid, struct user_regs_struct *regs,
                                syscalls_state *state);
void handle_bind_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_listen_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_socket_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
// -------------------- PROCESSES ---------------------------
// Entry Handlers
void handle_brk_entry(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_clone_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_execve_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
void handle_exit_exitgroup_entry(pid_t pid, struct user_regs_struct *regs,
                                 syscalls_state *state);
void handle_mmap_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_munmap_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state);
// Exit Handlers
void handle_brk_exit(pid_t pid, struct user_regs_struct *regs,
                     syscalls_state *state);
void handle_clone_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state);
void handle_execve_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);
void handle_exit_exitgroup_exit(pid_t pid, struct user_regs_struct *regs,
                                syscalls_state *state);
void handle_fork_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state);
void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state);

#endif
