#ifndef SYSCALL_HANDLERS_H
#define SYSCALL_HANDLERS_H

#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include "syscall_types.h"

void handle_read_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_write_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_close_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_openat_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_lseek_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_brk_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_mmap_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_munmap_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_exit_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_clone_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_execve_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_stat_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_fstat_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_lstat_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_access_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_getcwd_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_chdir_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_socket_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_bind_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_listen_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_accept_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_connect_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_dup_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_dup2_entry(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);

void handle_read_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_write_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_close_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_openat_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_brk_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_exit_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_getpid_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_fork_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_clone_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_execve_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_stat_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_lstat_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_access_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_socket_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_bind_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_listen_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_accept_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_connect_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_dup_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);
void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs, syscalls_state *state);

#endif
