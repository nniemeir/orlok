
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include "trace.h"

void handle_read_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_write_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_close_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_openat_exit(pid_t pid, struct user_regs_struct *regs) {
 
}

void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_brk_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs) {
 
}

void handle_exit_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_getpid_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_fork_exit(pid_t pid, struct user_regs_struct *regs) {

}

void handle_clone_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_execve_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_stat_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_access_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_socket_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_bind_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_listen_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_accept_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_dup_exit(pid_t pid, struct user_regs_struct *regs) {
    
}

void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs) {
    
}
