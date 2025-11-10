#ifndef SYSCALL_HANDLERS_H
#define SYSCALL_HANDLERS_H

#include <sys/types.h>
#include <sys/user.h>

void handle_read_write_in(pid_t pid, struct user_regs_struct *regs);
void handle_close_in(pid_t pid, struct user_regs_struct *regs);
void handle_openat_in(pid_t pid, struct user_regs_struct *regs);
void handle_lseek_in(pid_t pid, struct user_regs_struct *regs);
void handle_brk_in(pid_t pid, struct user_regs_struct *regs);
void handle_mmap_in(pid_t pid, struct user_regs_struct *regs);
void handle_munmap_in(pid_t pid, struct user_regs_struct *regs);
void handle_exit_in(pid_t pid, struct user_regs_struct *regs);
void handle_getpid_in(pid_t pid, struct user_regs_struct *regs);
void handle_fork_in(pid_t pid, struct user_regs_struct *regs);
void handle_clone_in(pid_t pid, struct user_regs_struct *regs);
void handle_execve_in(pid_t pid, struct user_regs_struct *regs);
void handle_stat_in(pid_t pid, struct user_regs_struct *regs);
void handle_fstat_in(pid_t pid, struct user_regs_struct *regs);
void handle_lstat_in(pid_t pid, struct user_regs_struct *regs);
void handle_access_in(pid_t pid, struct user_regs_struct *regs);
void handle_getcwd_in(pid_t pid, struct user_regs_struct *regs);
void handle_chdir_in(pid_t pid, struct user_regs_struct *regs);
void handle_socket_in(pid_t pid, struct user_regs_struct *regs);
void handle_bind_in(pid_t pid, struct user_regs_struct *regs);
void handle_listen_in(pid_t pid, struct user_regs_struct *regs);
void handle_accept_in(pid_t pid, struct user_regs_struct *regs);
void handle_connect_in(pid_t pid, struct user_regs_struct *regs);
void handle_pipe_in(pid_t pid, struct user_regs_struct *regs);
void handle_dup_in(pid_t pid, struct user_regs_struct *regs);
void handle_dup2_in(pid_t pid, struct user_regs_struct *regs);

void handle_read_write_out(pid_t pid, struct user_regs_struct *regs);
void handle_close_out(pid_t pid, struct user_regs_struct *regs);
void handle_openat_out(pid_t pid, struct user_regs_struct *regs);
void handle_lseek_out(pid_t pid, struct user_regs_struct *regs);
void handle_brk_out(pid_t pid, struct user_regs_struct *regs);
void handle_mmap_out(pid_t pid, struct user_regs_struct *regs);
void handle_munmap_out(pid_t pid, struct user_regs_struct *regs);
void handle_exit_out(pid_t pid, struct user_regs_struct *regs);
void handle_getpid_out(pid_t pid, struct user_regs_struct *regs);
void handle_fork_out(pid_t pid, struct user_regs_struct *regs);
void handle_clone_out(pid_t pid, struct user_regs_struct *regs);
void handle_execve_out(pid_t pid, struct user_regs_struct *regs);
void handle_stat_out(pid_t pid, struct user_regs_struct *regs);
void handle_fstat_out(pid_t pid, struct user_regs_struct *regs);
void handle_lstat_out(pid_t pid, struct user_regs_struct *regs);
void handle_access_out(pid_t pid, struct user_regs_struct *regs);
void handle_getcwd_out(pid_t pid, struct user_regs_struct *regs);
void handle_chdir_out(pid_t pid, struct user_regs_struct *regs);
void handle_socket_out(pid_t pid, struct user_regs_struct *regs);
void handle_bind_out(pid_t pid, struct user_regs_struct *regs);
void handle_listen_out(pid_t pid, struct user_regs_struct *regs);
void handle_accept_out(pid_t pid, struct user_regs_struct *regs);
void handle_connect_out(pid_t pid, struct user_regs_struct *regs);
void handle_pipe_out(pid_t pid, struct user_regs_struct *regs);
void handle_dup_out(pid_t pid, struct user_regs_struct *regs);
void handle_dup2_out(pid_t pid, struct user_regs_struct *regs);

#endif
