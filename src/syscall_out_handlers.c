#include "syscall_handlers.h"
#include "trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>

void handle_read_exit(pid_t pid, struct user_regs_struct *regs) {
  read_values.buffer = malloc(4096);
  read_string_arg(read_values.buffer, pid, regs->rsi);
  read_values.ret_value = (long)regs->rax;
  read_values.errno_value = "N/A";
  if (read_values.ret_value < 0) {
    read_values.errno_value = strerror(-regs->rax);
  }
  printf("read(%u, %s, %zu) = %ld (%s)\n", read_values.fd, read_values.buffer,
         read_values.count, read_values.ret_value, read_values.errno_value);
  free(read_values.buffer);
}

void handle_write_exit(pid_t pid, struct user_regs_struct *regs) {
  read_values.ret_value = (long)regs->rax;
  read_values.errno_value = "N/A";
  if (read_values.ret_value < 0) {
    read_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_read) {
    printf("read(%u, %s, %zu) = %ld (%s)\n", read_values.fd, read_values.buffer,
           read_values.count, read_values.ret_value, read_values.errno_value);
  } else {
    printf("write(%u, %s, %zu) = %ld (%s)\n", read_values.fd,
           read_values.buffer, read_values.count, read_values.ret_value,
           read_values.errno_value);
  }
  free(read_values.buffer);
}

void handle_close_exit(pid_t pid, struct user_regs_struct *regs) {
  close_values.ret_value = (long)regs->rax;
  close_values.errno_value = "N/A";
  if (close_values.ret_value < 0) {
    close_values.errno_value = strerror(-regs->rax);
  }
  printf("close(%u) = %ld\n", close_values.fd, close_values.ret_value);
}

void handle_openat_exit(pid_t pid, struct user_regs_struct *regs) {
  openat_values.ret_value = regs->rax;
  openat_values.errno_value = "N/A";
  if (openat_values.ret_value < 0) {
    openat_values.errno_value = strerror(-regs->rax);
  }
  printf("openat(%u, %s, %d, %u) = %d (%s)\n", openat_values.dfd,
         openat_values.filename, openat_values.flags, openat_values.mode,
         openat_values.ret_value, openat_values.errno_value);
  free(openat_values.filename);
}

void handle_lseek_exit(pid_t pid, struct user_regs_struct *regs) {
  lseek_values.ret_value = regs->rax;
  lseek_values.errno_value = "N/A";
  if (lseek_values.ret_value < 0) {
    lseek_values.errno_value = strerror(-regs->rax);
  }
  printf("lseek(%u, %ld, %d) = %ld (%s)\n", lseek_values.fd,
         lseek_values.offset, lseek_values.whence, lseek_values.ret_value,
         lseek_values.errno_value);
}

void handle_brk_exit(pid_t pid, struct user_regs_struct *regs) {
  brk_values.ret_value = regs->rax;
  brk_values.errno_value = "N/A";
  if (brk_values.ret_value < 0) {
    brk_values.errno_value = strerror(-regs->rax);
  }
  printf("brk(%lu) = %d (%s)\n", brk_values.addr, brk_values.ret_value,
         brk_values.errno_value);
}

void handle_mmap_exit(pid_t pid, struct user_regs_struct *regs) {
  mmap_values.ret_value = (void *)regs->rax;
  mmap_values.errno_value = "N/A";
  if (mmap_values.ret_value == (void *)-1) {
    mmap_values.errno_value = strerror(-(long)mmap_values.ret_value);
  }
  printf("mmap(%lu, %lu, %d, %d, %d, %ld) = %p (%s)\n", mmap_values.addr,
         mmap_values.length, mmap_values.prot, mmap_values.flags,
         mmap_values.fd, mmap_values.offset, mmap_values.ret_value,
         mmap_values.errno_value);
}

void handle_munmap_exit(pid_t pid, struct user_regs_struct *regs) {
  munmap_values.ret_value = regs->rax;
  munmap_values.errno_value = "N/A";
  if (munmap_values.ret_value < 0) {
    munmap_values.errno_value = strerror(-regs->rax);
  }
  printf("munmap(%lu, %lu) = %d (%s)\n", munmap_values.addr,
         munmap_values.length, munmap_values.ret_value,
         munmap_values.errno_value);
}

void handle_exit_exit(pid_t pid, struct user_regs_struct *regs) {
  if (regs->orig_rax == SYS_exit) {
    printf("exit(%d)\n", exit_values.error_code);
  } else {
    printf("exit_group(%d)\n", exit_values.error_code);
  }
}

void handle_getpid_exit(pid_t pid, struct user_regs_struct *regs) {
  getpid_values.ret_value = regs->rax;
  if (regs->orig_rax == SYS_getpid) {
    printf("getpid() = %d\n", getpid_values.ret_value);
  } else {
    printf("getppid() = %d\n", getpid_values.ret_value);
  }
}

void handle_fork_exit(pid_t pid, struct user_regs_struct *regs) {
  fork_values.ret_value = regs->rax;
  fork_values.errno_value = "N/A";
  if (fork_values.ret_value < 0) {
    fork_values.errno_value = strerror(-regs->rax);
  }
  printf("fork() = %d (%s)\n", fork_values.ret_value, fork_values.errno_value);
}

void handle_clone_exit(pid_t pid, struct user_regs_struct *regs) {
  clone_values.ret_value = (long)regs->rax;
  clone_values.errno_value = "N/A";
  if (clone_values.ret_value < 0) {
    clone_values.errno_value = strerror(-regs->rax);
  }
  printf("clone(%lu, %p, %d, %d, %lu) = %ld (%s)\n", clone_values.flags,
         clone_values.stack, clone_values.parent_tid, clone_values.child_tid,
         clone_values.tls, clone_values.ret_value, clone_values.errno_value);
}

void handle_execve_exit(pid_t pid, struct user_regs_struct *regs) {
  execve_values.ret_value = (int)regs->rax;
  execve_values.errno_value = "N/A";
  if (execve_values.ret_value < 0) {
    execve_values.errno_value = strerror(-regs->rax);
  }
  printf("execve(%s, %s, %s) = %d (%s)\n", execve_values.pathname,
         execve_values.argv, execve_values.envp, execve_values.ret_value,
         execve_values.errno_value);
  free(execve_values.pathname);
  free(execve_values.argv);
  free(execve_values.envp);
}

void handle_stat_exit(pid_t pid, struct user_regs_struct *regs) {
  stat_values.statbuf = (void *)regs->rsi;
  stat_values.ret_value = (int)regs->rax;
  stat_values.errno_value = "N/A";
  if (stat_values.ret_value < 0) {
    stat_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_stat) {
    printf("stat(%s, %p) = %d (%s)\n", stat_values.filename,
           stat_values.statbuf, stat_values.ret_value, stat_values.errno_value);
  } else {
    printf("lstat(%s, %p) = %d (%s)\n", stat_values.filename,
           stat_values.statbuf, stat_values.ret_value, stat_values.errno_value);
  }
  free(stat_values.filename);
}

void handle_fstat_exit(pid_t pid, struct user_regs_struct *regs) {
  fstat_values.statbuf = (void *)regs->rsi;
  fstat_values.ret_value = (int)regs->rax;
  fstat_values.errno_value = "N/A";
  if (fstat_values.ret_value < 0) {
    fstat_values.errno_value = strerror(-regs->rax);
  }
  printf("fstat(%d, %p) = %d (%s)\n", fstat_values.fd, fstat_values.statbuf,
         fstat_values.ret_value, fstat_values.errno_value);
}

void handle_access_exit(pid_t pid, struct user_regs_struct *regs) {
  access_values.ret_value = (int)regs->rax;
  access_values.errno_value = "N/A";
  if (access_values.ret_value < 0) {
    access_values.errno_value = strerror(-regs->rax);
  }
  printf("access(%s, %d) = %d (%s)\n", access_values.pathname,
         access_values.mode, access_values.ret_value,
         access_values.errno_value);
  free(access_values.pathname);
}

void handle_getcwd_exit(pid_t pid, struct user_regs_struct *regs) {
  getcwd_values.buf = malloc(4096);
  read_string_arg(getcwd_values.buf, pid, regs->rdi);
  getcwd_values.ret_value = malloc(4096);
  read_string_arg(getcwd_values.ret_value, pid, regs->rax);
  getcwd_values.errno_value = "N/A";
  if (getcwd_values.ret_value == NULL) {
    getcwd_values.errno_value = strerror(-regs->rax);
  }
  printf("getcwd(%s, %lu) = %s (%s)\n", getcwd_values.buf, getcwd_values.size,
         getcwd_values.ret_value, getcwd_values.errno_value);
  free(getcwd_values.buf);
  free(getcwd_values.ret_value);
}

void handle_chdir_exit(pid_t pid, struct user_regs_struct *regs) {
  chdir_values.ret_value = regs->rax;
  chdir_values.errno_value = "N/A";
  if (chdir_values.ret_value < 0) {
    chdir_values.errno_value = strerror(-regs->rax);
  }
  printf("chdir(%s) = %d, (%s)\n", chdir_values.path, chdir_values.ret_value,
         chdir_values.errno_value);
  free(chdir_values.path);
}

void handle_socket_exit(pid_t pid, struct user_regs_struct *regs) {
  socket_values.ret_value = regs->rax;
  socket_values.errno_value = "N/A";
  if (socket_values.ret_value < 0) {
    socket_values.errno_value = strerror(-regs->rax);
  }
  printf("socket(%d, %d, %d) = %d, (%s)\n", socket_values.domain,
         socket_values.type, socket_values.protocol, socket_values.ret_value,
         socket_values.errno_value);
}

void handle_bind_exit(pid_t pid, struct user_regs_struct *regs) {
  bind_values.ret_value = regs->rax;
  bind_values.errno_value = "N/A";
  if (bind_values.ret_value < 0) {
    bind_values.errno_value = strerror(-regs->rax);
  }
  printf("bind(%d, %p, %u) = %d (%s)\n", bind_values.sockfd, bind_values.addr,
         bind_values.addrlen, bind_values.ret_value, bind_values.errno_value);
}

void handle_listen_exit(pid_t pid, struct user_regs_struct *regs) {
  listen_values.ret_value = regs->rax;
  listen_values.errno_value = "N/A";
  if (listen_values.ret_value < 0) {
    listen_values.errno_value = strerror(-regs->rax);
  }
  printf("listen(%d, %d) = %d (%s)\n", listen_values.sockfd,
         listen_values.backlog, listen_values.ret_value,
         listen_values.errno_value);
}

void handle_accept_exit(pid_t pid, struct user_regs_struct *regs) {
  accept_values.ret_value = regs->rax;
  accept_values.errno_value = "N/A";
  if (accept_values.ret_value < 0) {
    accept_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_accept) {
    printf("accept(%d, %p, %u) = %d (%s)", accept_values.sockfd,
           accept_values.addr, accept_values.addrlen, accept_values.ret_value,
           accept_values.errno_value);
  } else {
    printf("connect(%d, %p, %u) = %d (%s)", accept_values.sockfd,
           accept_values.addr, accept_values.addrlen, accept_values.ret_value,
           accept_values.errno_value);
  }
}

void handle_pipe_exit(pid_t pid, struct user_regs_struct *regs) {
  pipe_values.pipefd[0] = ptrace(PTRACE_PEEKDATA, pid, regs->rdi, NULL);
  pipe_values.pipefd[1] =
      ptrace(PTRACE_PEEKDATA, pid, regs->rdi + sizeof(int), NULL);

  pipe_values.ret_value = regs->rax;
  pipe_values.errno_value = "N/A";
  if (pipe_values.ret_value < 0) {
    pipe_values.errno_value = strerror(-regs->rax);
  }
  printf("pipe([%d, %d]) = %d (%s)", pipe_values.pipefd[0],
         pipe_values.pipefd[1], pipe_values.ret_value, pipe_values.errno_value);
}

void handle_dup_exit(pid_t pid, struct user_regs_struct *regs) {
  dup_values.ret_value = regs->rax;
  dup_values.errno_value = "N/A";
  if (dup_values.ret_value < 0) {
    dup_values.errno_value = strerror(-regs->rax);
  }
  printf("dup(%d) = %d (%s)", dup_values.oldfd, dup_values.ret_value,
         dup_values.errno_value);
}

void handle_dup2_exit(pid_t pid, struct user_regs_struct *regs) {
  dup2_values.ret_value = regs->rax;
  dup2_values.errno_value = "N/A";
  if (dup2_values.ret_value < 0) {
    dup2_values.errno_value = strerror(-regs->rax);
  }
  printf("dup2(%d, %d) = %d (%s)", dup2_values.oldfd, dup2_values.newfd,
         dup2_values.ret_value, dup2_values.errno_value);
}
