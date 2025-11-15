#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "syscall_handlers.h"
#include "syscall_types.h"
#include "trace.h"

// -------------------- FILE DESCRIPTORS --------------------
void handle_dup_entry(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->dup_values.oldfd = (int)regs->rdi;
}

void handle_dup2_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->dup2_values.oldfd = (int)regs->rdi;
  state->dup2_values.newfd = (int)regs->rsi;
}

// -------------------- FILE I/O ----------------------------

void handle_access_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  state->access_values.pathname = malloc(ARG_MAX);
  if (!state->access_values.pathname) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->access_values.pathname, pid, regs->rdi);
  state->access_values.mode = (int)regs->rsi;
}

void handle_chdir_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  state->chdir_values.path = malloc(ARG_MAX);
  if (!state->chdir_values.path) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->chdir_values.path, pid, regs->rdi);
}

void handle_close_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->close_values.fd = (unsigned int)regs->rdi;
}

void handle_fstat_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->fstat_values.fd = (int)regs->rdi;
}

void handle_getcwd_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  (void)pid;
  state->getcwd_values.size = (size_t)regs->rsi;
}

void handle_lseek_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->lseek_values.fd = (int)regs->rdi;
  state->lseek_values.offset = (off_t)regs->rsi;
  state->lseek_values.whence = (unsigned int)regs->rdx;
}

void handle_lstat_stat_entry(pid_t pid, struct user_regs_struct *regs,
                             syscalls_state *state) {
  state->lstat_stat_values.filename = malloc(ARG_MAX);
  if (!state->lstat_stat_values.filename) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->lstat_stat_values.filename, pid, regs->rdi);
}

void handle_openat_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  state->openat_values.dfd = (int)regs->rdi;
  state->openat_values.filename = malloc(ARG_MAX);
  if (!state->openat_values.filename) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->openat_values.filename, pid, regs->rsi);
  state->openat_values.flags = (int)regs->rdx;
  state->openat_values.mode = (mode_t)regs->r10;
}

void handle_write_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  state->read_write_values.fd = (unsigned int)regs->rdi;
  state->read_write_values.buffer = malloc(ARG_MAX);
  if (!state->read_write_values.buffer) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->read_write_values.buffer, pid, regs->rsi);
  state->read_write_values.count = (size_t)regs->rdx;
}

void handle_read_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  // The members of user_regs_struct are unsigned long long (64 bit uints)
  // As such, casting to the actual type that was passed in is essential for
  // parsing
  state->read_write_values.fd = (unsigned int)regs->rdi;
  state->read_write_values.count = (size_t)regs->rdx;
}

// -------------------- NETWORKING --------------------------
void handle_accept_connect_entry(pid_t pid, struct user_regs_struct *regs,
                                 syscalls_state *state) {
  (void)pid;
  state->accept_connect_values.sockfd = (int)regs->rdi;
  state->accept_connect_values.addr = (void *)regs->rsi;
  state->accept_connect_values.addrlen = (socklen_t)regs->rdx;
}

void handle_bind_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->bind_values.sockfd = (int)regs->rdi;
  state->bind_values.addr = (void *)regs->rsi;
  state->bind_values.addrlen = (socklen_t)regs->rdx;
}

void handle_listen_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  (void)pid;
  state->listen_values.sockfd = (int)regs->rdi;
  state->listen_values.backlog = (int)regs->rsi;
}

void handle_socket_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  (void)pid;
  state->socket_values.domain = (int)regs->rdi;
  state->socket_values.type = (int)regs->rsi;
  state->socket_values.protocol = (int)regs->rdx;
}

// -------------------- PROCESSES ---------------------------
void handle_brk_entry(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->brk_values.addr = (unsigned long)regs->rdi;
}

void handle_clone_entry(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  state->clone_values.flags = (unsigned long)regs->rdi;
  state->clone_values.stack = (void *)regs->rsi;

  errno = 0;
  state->clone_values.parent_tid =
      (int)ptrace(PTRACE_PEEKDATA, pid, regs->rdx, NULL);
  if (errno != 0) {
    fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
  }
  errno = 0;

  state->clone_values.child_tid =
      (int)ptrace(PTRACE_PEEKDATA, pid, regs->r10, NULL);
  if (errno != 0) {
    fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
  }

  state->clone_values.tls = (unsigned long)regs->r8;
}

void handle_execve_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  state->execve_values.pathname = malloc(ARG_MAX);
  if (!state->execve_values.pathname) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }

  read_string_arg(&state->execve_values.pathname, pid, regs->rdi);

  char **argv_arr = NULL;
  read_string_array(&argv_arr, pid, regs->rsi);
  state->execve_values.argv = malloc(ARG_MAX);
  if (!state->execve_values.argv) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  array_to_string(&state->execve_values.argv, argv_arr);
  free(argv_arr);

  char **envp_arr = NULL;
  read_string_array(&envp_arr, pid, regs->rdx);
  state->execve_values.envp = malloc(ARG_MAX);
  if (!state->execve_values.envp) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  array_to_string(&state->execve_values.envp, envp_arr);
  free(envp_arr);
}

void handle_exit_exitgroup_entry(pid_t pid, struct user_regs_struct *regs,
                                 syscalls_state *state) {
  (void)pid;
  state->exit_exitgroup_values.error_code = (int)regs->rdi;
}

void handle_mmap_entry(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->mmap_values.addr = (unsigned long)regs->rdi;
  state->mmap_values.length = (size_t)regs->rsi;
  state->mmap_values.prot = (int)regs->rdx;
  state->mmap_values.flags = (int)regs->r10;
  state->mmap_values.fd = (int)regs->r8;
  state->mmap_values.offset = (off_t)regs->r9;
}

void handle_munmap_entry(pid_t pid, struct user_regs_struct *regs,
                         syscalls_state *state) {
  (void)pid;
  state->munmap_values.addr = (unsigned long)regs->rdi;
  state->munmap_values.length = (size_t)regs->rsi;
}
