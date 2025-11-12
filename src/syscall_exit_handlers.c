#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "syscall_handlers.h"
#include "syscall_types.h"
#include "trace.h"

void handle_read_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  state->read_values.buffer = malloc(ARG_MAX);
  if (!state->read_values.buffer) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->read_values.buffer, pid, regs->rsi);
  state->read_values.ret_value = (long)regs->rax;
  state->read_values.errno_value = "N/A";
  if (state->read_values.ret_value < 0) {
    state->read_values.errno_value = strerror(-regs->rax);
  }
  printf("read(%u, %s, %zu) = %ld (%s)\n", state->read_values.fd,
         state->read_values.buffer, state->read_values.count,
         state->read_values.ret_value, state->read_values.errno_value);
  free(state->read_values.buffer);
}

void handle_write_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->write_values.ret_value = (long)regs->rax;
  state->write_values.errno_value = "N/A";
  if (state->write_values.ret_value < 0) {
    state->write_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_read) {
    printf("read(%u, %s, %zu) = %ld (%s)\n", state->write_values.fd,
           state->write_values.buffer, state->write_values.count,
           state->write_values.ret_value, state->write_values.errno_value);
  } else {
    printf("write(%u, %s, %zu) = %ld (%s)\n", state->write_values.fd,
           state->write_values.buffer, state->write_values.count,
           state->write_values.ret_value, state->write_values.errno_value);
  }
  free(state->write_values.buffer);
}

void handle_close_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->close_values.ret_value = (long)regs->rax;
  state->close_values.errno_value = "N/A";
  if (state->close_values.ret_value < 0) {
    state->close_values.errno_value = strerror(-regs->rax);
  }
  printf("close(%u) = %ld\n", state->close_values.fd,
         state->close_values.ret_value);
}

void handle_openat_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->openat_values.ret_value = (int)regs->rax;
  state->openat_values.errno_value = "N/A";
  if (state->openat_values.ret_value < 0) {
    state->openat_values.errno_value = strerror(-regs->rax);
  }
  printf("openat(%u, %s, %d, %u) = %d (%s)\n", state->openat_values.dfd,
         state->openat_values.filename, state->openat_values.flags,
         state->openat_values.mode, state->openat_values.ret_value,
         state->openat_values.errno_value);
  free(state->openat_values.filename);
}

void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->lseek_values.ret_value = (off_t)regs->rax;
  state->lseek_values.errno_value = "N/A";
  if (state->lseek_values.ret_value < 0) {
    state->lseek_values.errno_value = strerror(-regs->rax);
  }
  printf("lseek(%u, %ld, %d) = %ld (%s)\n", state->lseek_values.fd,
         state->lseek_values.offset, state->lseek_values.whence,
         state->lseek_values.ret_value, state->lseek_values.errno_value);
}

void handle_brk_exit(pid_t pid, struct user_regs_struct *regs,
                     syscalls_state *state) {
  (void)pid;
  state->brk_values.ret_value = (int)regs->rax;
  state->brk_values.errno_value = "N/A";
  if (state->brk_values.ret_value < 0) {
    state->brk_values.errno_value = strerror(-regs->rax);
  }
  printf("brk(%lu) = %d (%s)\n", state->brk_values.addr,
         state->brk_values.ret_value, state->brk_values.errno_value);
}

void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->mmap_values.ret_value = (void *)regs->rax;
  state->mmap_values.errno_value = "N/A";
  if (state->mmap_values.ret_value == (void *)-1) {
    state->mmap_values.errno_value =
        strerror(-(long)state->mmap_values.ret_value);
  }
  printf("mmap(%lu, %lu, %d, %d, %d, %ld) = %p (%s)\n", state->mmap_values.addr,
         state->mmap_values.length, state->mmap_values.prot,
         state->mmap_values.flags, state->mmap_values.fd,
         state->mmap_values.offset, state->mmap_values.ret_value,
         state->mmap_values.errno_value);
}

void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->munmap_values.ret_value = (int)regs->rax;
  state->munmap_values.errno_value = "N/A";
  if (state->munmap_values.ret_value < 0) {
    state->munmap_values.errno_value = strerror(-regs->rax);
  }
  printf("munmap(%lu, %lu) = %d (%s)\n", state->munmap_values.addr,
         state->munmap_values.length, state->munmap_values.ret_value,
         state->munmap_values.errno_value);
}

void handle_exit_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  if (regs->orig_rax == SYS_exit) {
    printf("exit(%d)\n", state->exit_values.error_code);
  } else {
    printf("exit_group(%d)\n", state->exit_values.error_code);
  }
}

void handle_getpid_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->getpid_values.ret_value = (pid_t)regs->rax;
  if (regs->orig_rax == SYS_getpid) {
    printf("getpid() = %d\n", state->getpid_values.ret_value);
  } else {
    printf("getppid() = %d\n", state->getpid_values.ret_value);
  }
}

void handle_fork_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->fork_values.ret_value = (pid_t)regs->rax;
  state->fork_values.errno_value = "N/A";
  if (state->fork_values.ret_value < 0) {
    state->fork_values.errno_value = strerror(-regs->rax);
  }
  printf("fork() = %d (%s)\n", state->fork_values.ret_value,
         state->fork_values.errno_value);
}

void handle_clone_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->clone_values.ret_value = (long)regs->rax;
  state->clone_values.errno_value = "N/A";
  if (state->clone_values.ret_value < 0) {
    state->clone_values.errno_value = strerror(-regs->rax);
  }
  printf("clone(%lu, %p, %d, %d, %lu) = %ld (%s)\n", state->clone_values.flags,
         state->clone_values.stack, state->clone_values.parent_tid,
         state->clone_values.child_tid, state->clone_values.tls,
         state->clone_values.ret_value, state->clone_values.errno_value);
}

void handle_execve_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->execve_values.ret_value = (int)regs->rax;
  state->execve_values.errno_value = "N/A";
  if (state->execve_values.ret_value < 0) {
    state->execve_values.errno_value = strerror(-regs->rax);
  }
  printf("execve(%s, %s, %s) = %d (%s)\n", state->execve_values.pathname,
         state->execve_values.argv, state->execve_values.envp,
         state->execve_values.ret_value, state->execve_values.errno_value);
  free(state->execve_values.pathname);
}

void handle_stat_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->stat_values.statbuf = (void *)regs->rsi;
  state->stat_values.ret_value = (int)regs->rax;
  state->stat_values.errno_value = "N/A";
  if (state->stat_values.ret_value < 0) {
    state->stat_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_stat) {
    printf("stat(%s, %p) = %d (%s)\n", state->stat_values.filename,
           state->stat_values.statbuf, state->stat_values.ret_value,
           state->stat_values.errno_value);
  } else {
    printf("lstat(%s, %p) = %d (%s)\n", state->stat_values.filename,
           state->stat_values.statbuf, state->stat_values.ret_value,
           state->stat_values.errno_value);
  }
  free(state->stat_values.filename);
}

void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->fstat_values.statbuf = (void *)regs->rsi;
  state->fstat_values.ret_value = (int)regs->rax;
  state->fstat_values.errno_value = "N/A";
  if (state->fstat_values.ret_value < 0) {
    state->fstat_values.errno_value = strerror(-regs->rax);
  }
  printf("fstat(%d, %p) = %d (%s)\n", state->fstat_values.fd,
         state->fstat_values.statbuf, state->fstat_values.ret_value,
         state->fstat_values.errno_value);
}

void handle_access_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->access_values.ret_value = (int)regs->rax;
  state->access_values.errno_value = "N/A";
  if (state->access_values.ret_value < 0) {
    state->access_values.errno_value = strerror(-regs->rax);
  }
  printf("access(%s, %d) = %d (%s)\n", state->access_values.pathname,
         state->access_values.mode, state->access_values.ret_value,
         state->access_values.errno_value);
  free(state->access_values.pathname);
}

void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  state->getcwd_values.buf = malloc(ARG_MAX);
  if (!state->getcwd_values.buf) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->getcwd_values.buf, pid, regs->rdi);
  state->getcwd_values.ret_value = malloc(ARG_MAX);
  if (!state->getcwd_values.ret_value) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  read_string_arg(&state->getcwd_values.ret_value, pid, regs->rax);
  state->getcwd_values.errno_value = "N/A";
  if (state->getcwd_values.ret_value == NULL) {
    state->getcwd_values.errno_value = strerror(-regs->rax);
  }
  printf("getcwd(%s, %lu) = %s (%s)\n", state->getcwd_values.buf,
         state->getcwd_values.size, state->getcwd_values.ret_value,
         state->getcwd_values.errno_value);
  free(state->getcwd_values.buf);
  free(state->getcwd_values.ret_value);
}

void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs,
                       syscalls_state *state) {
  (void)pid;
  state->chdir_values.ret_value = (int)regs->rax;
  state->chdir_values.errno_value = "N/A";
  if (state->chdir_values.ret_value < 0) {
    state->chdir_values.errno_value = strerror(-regs->rax);
  }
  printf("chdir(%s) = %d, (%s)\n", state->chdir_values.path,
         state->chdir_values.ret_value, state->chdir_values.errno_value);
  free(state->chdir_values.path);
}

void handle_socket_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->socket_values.ret_value = (int)regs->rax;
  state->socket_values.errno_value = "N/A";
  if (state->socket_values.ret_value < 0) {
    state->socket_values.errno_value = strerror(-regs->rax);
  }
  printf("socket(%d, %d, %d) = %d, (%s)\n", state->socket_values.domain,
         state->socket_values.type, state->socket_values.protocol,
         state->socket_values.ret_value, state->socket_values.errno_value);
}

void handle_bind_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->bind_values.ret_value = (int)regs->rax;
  state->bind_values.errno_value = "N/A";
  if (state->bind_values.ret_value < 0) {
    state->bind_values.errno_value = strerror(-regs->rax);
  }
  printf("bind(%d, %p, %u) = %d (%s)\n", state->bind_values.sockfd,
         state->bind_values.addr, state->bind_values.addrlen,
         state->bind_values.ret_value, state->bind_values.errno_value);
}

void handle_listen_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->listen_values.ret_value = (int)regs->rax;
  state->listen_values.errno_value = "N/A";
  if (state->listen_values.ret_value < 0) {
    state->listen_values.errno_value = strerror(-regs->rax);
  }
  printf("listen(%d, %d) = %d (%s)\n", state->listen_values.sockfd,
         state->listen_values.backlog, state->listen_values.ret_value,
         state->listen_values.errno_value);
}

void handle_accept_exit(pid_t pid, struct user_regs_struct *regs,
                        syscalls_state *state) {
  (void)pid;
  state->accept_values.ret_value = (int)regs->rax;
  state->accept_values.errno_value = "N/A";
  if (state->accept_values.ret_value < 0) {
    state->accept_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_accept) {
    printf("accept(%d, %p, %u) = %d (%s)", state->accept_values.sockfd,
           state->accept_values.addr, state->accept_values.addrlen,
           state->accept_values.ret_value, state->accept_values.errno_value);
  } else {
    printf("connect(%d, %p, %u) = %d (%s)", state->accept_values.sockfd,
           state->accept_values.addr, state->accept_values.addrlen,
           state->accept_values.ret_value, state->accept_values.errno_value);
  }
}

void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  errno = 0;
  state->pipe_values.pipefd[0] =
      (int)ptrace(PTRACE_PEEKDATA, pid, regs->rdi, NULL);
  if (errno != 0) {
    fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
  }
  errno = 0;
  state->pipe_values.pipefd[1] =
      (int)ptrace(PTRACE_PEEKDATA, pid, regs->rdi + sizeof(int), NULL);
  if (errno != 0) {
    fprintf(stderr, "PTRACE_PEEKDATA Failed: %s\n", strerror(errno));
  }
  state->pipe_values.ret_value = (int)regs->rax;
  state->pipe_values.errno_value = "N/A";
  if (state->pipe_values.ret_value < 0) {
    state->pipe_values.errno_value = strerror(-regs->rax);
  }
  printf("pipe([%d, %d]) = %d (%s)", state->pipe_values.pipefd[0],
         state->pipe_values.pipefd[1], state->pipe_values.ret_value,
         state->pipe_values.errno_value);
}

void handle_dup_exit(pid_t pid, struct user_regs_struct *regs,
                     syscalls_state *state) {
  (void)pid;
  state->dup_values.ret_value = (int)regs->rax;
  state->dup_values.errno_value = "N/A";
  if (state->dup_values.ret_value < 0) {
    state->dup_values.errno_value = strerror(-regs->rax);
  }
  printf("dup(%d) = %d (%s)", state->dup_values.oldfd,
         state->dup_values.ret_value, state->dup_values.errno_value);
}

void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs,
                      syscalls_state *state) {
  (void)pid;
  state->dup2_values.ret_value = (int)regs->rax;
  state->dup2_values.errno_value = "N/A";
  if (state->dup2_values.ret_value < 0) {
    state->dup2_values.errno_value = strerror(-regs->rax);
  }
  printf("dup2(%d, %d) = %d (%s)", state->dup2_values.oldfd,
         state->dup2_values.newfd, state->dup2_values.ret_value,
         state->dup2_values.errno_value);
}
