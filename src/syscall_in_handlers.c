#include "syscall_handlers.h"
#include "trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

syscall_read_values read_values;
syscall_read_values write_values;
syscall_close_values close_values;
syscall_openat_values openat_values;
syscall_lseek_values lseek_values;
syscall_brk_values brk_values;
syscall_mmap_values mmap_values;
syscall_munmap_values munmap_values;
syscall_exit_values exit_values;
syscall_getpid_values getpid_values;
syscall_fork_values fork_values;
syscall_clone_values clone_values;
syscall_execve_values execve_values;
syscall_stat_values stat_values;
syscall_fstat_values fstat_values;
syscall_access_values access_values;
syscall_getcwd_values getcwd_values;
syscall_chdir_values chdir_values;
syscall_socket_values socket_values;
syscall_bind_values bind_values;
syscall_listen_values listen_values;
syscall_accept_values accept_values;
syscall_pipe_values pipe_values;
syscall_dup_values dup_values;
syscall_dup2_values dup2_values;

void handle_read_entry(pid_t pid, struct user_regs_struct *regs) {
  read_values.fd = regs->rdi;
  read_values.count = regs->rdx;
}

void handle_write_entry(pid_t pid, struct user_regs_struct *regs) {
  read_values.fd = regs->rdi;
  read_values.buffer = malloc(4096);
  read_string_arg(read_values.buffer, pid, regs->rsi);
  read_values.count = regs->rdx;
}

void handle_close_entry(pid_t pid, struct user_regs_struct *regs) {
  close_values.fd = regs->rdi;
}

void handle_openat_entry(pid_t pid, struct user_regs_struct *regs) {
  openat_values.dfd = regs->rdi;
  openat_values.filename = malloc(4096);
  read_string_arg(openat_values.filename, pid, regs->rsi);
  openat_values.flags = regs->rdx;
  openat_values.mode = regs->r10;
}

void handle_lseek_entry(pid_t pid, struct user_regs_struct *regs) {
  lseek_values.fd = regs->rdi;
  lseek_values.offset = regs->rsi;
  lseek_values.whence = regs->rdx;
}

void handle_brk_entry(pid_t pid, struct user_regs_struct *regs) {
  brk_values.addr = regs->rdi;
}

void handle_mmap_entry(pid_t pid, struct user_regs_struct *regs) {
  mmap_values.addr = regs->rdi;
  mmap_values.length = regs->rsi;
  mmap_values.prot = regs->rdx;
  mmap_values.flags = regs->r10;
  mmap_values.fd = regs->r8;
  mmap_values.offset = regs->r9;
}

void handle_munmap_entry(pid_t pid, struct user_regs_struct *regs) {
  munmap_values.addr = regs->rdi;
  munmap_values.length = regs->rsi;
}

void handle_exit_entry(pid_t pid, struct user_regs_struct *regs) {
  exit_values.error_code = regs->rdi;
}

void handle_clone_entry(pid_t pid, struct user_regs_struct *regs) {
  clone_values.flags = regs->rdi;
  clone_values.stack = (void *)regs->rsi;
  clone_values.parent_tid = ptrace(PTRACE_PEEKDATA, pid, regs->rdx, NULL);
  clone_values.child_tid = ptrace(PTRACE_PEEKDATA, pid, regs->r10, NULL);
  clone_values.tls = regs->r8;
}

void handle_execve_entry(pid_t pid, struct user_regs_struct *regs) {
  execve_values.pathname = malloc(4096);
  read_string_arg(execve_values.pathname, pid, regs->rdi);
  // ARGV AND ENVP ARE CHAR ARRAY ARRAYS, FIX THIS
  execve_values.argv = malloc(4096);
  // read_string_arg(argv, pid, regs->rsi);
  execve_values.envp = malloc(4096);
  // read_string_arg(envp, pid, regs->rdx);
}

void handle_stat_entry(pid_t pid, struct user_regs_struct *regs) {
  stat_values.filename = malloc(4096);
  read_string_arg(stat_values.filename, pid, regs->rdi);
}

void handle_fstat_entry(pid_t pid, struct user_regs_struct *regs) {
  fstat_values.fd = (int)regs->rdi;
}

void handle_access_entry(pid_t pid, struct user_regs_struct *regs) {
  access_values.pathname = malloc(4096);
  read_string_arg(access_values.pathname, pid, regs->rdi);
  access_values.mode = (int)regs->rsi;
}

void handle_getcwd_entry(pid_t pid, struct user_regs_struct *regs) {
  getcwd_values.size = (size_t)regs->rsi;
}

void handle_chdir_entry(pid_t pid, struct user_regs_struct *regs) {
  chdir_values.path = malloc(4096);
  read_string_arg(chdir_values.path, pid, regs->rdi);
}

void handle_socket_entry(pid_t pid, struct user_regs_struct *regs) {
  socket_values.domain = regs->rdi;
  socket_values.type = regs->rsi;
  socket_values.protocol = regs->rdx;
}

void handle_bind_entry(pid_t pid, struct user_regs_struct *regs) {
  bind_values.sockfd = regs->rdi;
  bind_values.addr = (void *)regs->rsi;
  bind_values.addrlen = regs->rdx;
}

void handle_listen_entry(pid_t pid, struct user_regs_struct *regs) {
  listen_values.sockfd = regs->rdi;
  listen_values.backlog = regs->rsi;
}

void handle_accept_entry(pid_t pid, struct user_regs_struct *regs) {
  accept_values.sockfd = regs->rdi;
  accept_values.addr = (void *)regs->rsi;
  accept_values.addrlen = regs->rdx;
}

void handle_dup_entry(pid_t pid, struct user_regs_struct *regs) {
  dup_values.oldfd = regs->rdi;
}

void handle_dup2_entry(pid_t pid, struct user_regs_struct *regs) {
  dup2_values.oldfd = regs->rdi;
  dup2_values.newfd = regs->rsi;
}
