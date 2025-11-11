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
  // ENTRY
  read_values.fd = regs->rdi;
  read_values.count = regs->rdx;
  // EXIT
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

void handle_write_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  read_values.fd = regs->rdi;
  read_values.buffer = malloc(4096);
  read_string_arg(read_values.buffer, pid, regs->rsi);
  read_values.count = regs->rdx;
  // EXIT
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

void handle_close_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  close_values.fd = regs->rdi;
  // EXIT
  close_values.ret_value = (long)regs->rax;
  close_values.errno_value = "N/A";
  if (close_values.ret_value < 0) {
    close_values.errno_value = strerror(-regs->rax);
  }
  printf("close(%u) = %ld\n", close_values.fd, close_values.ret_value);
}

void handle_openat_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  openat_values.dfd = regs->rdi;
  openat_values.filename = malloc(4096);
  read_string_arg(openat_values.filename, pid, regs->rsi);
  openat_values.flags = regs->rdx;
  openat_values.mode = regs->r10;
  // EXIT
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

void handle_lseek_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  lseek_values.fd = regs->rdi;
  lseek_values.offset = regs->rsi;
  lseek_values.whence = regs->rdx;
  // EXIT
  lseek_values.ret_value = regs->rax;
  lseek_values.errno_value = "N/A";
  if (lseek_values.ret_value < 0) {
    lseek_values.errno_value = strerror(-regs->rax);
  }
  printf("lseek(%u, %ld, %d) = %ld (%s)\n", lseek_values.fd,
         lseek_values.offset, lseek_values.whence, lseek_values.ret_value,
         lseek_values.errno_value);
}

void handle_brk_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  brk_values.addr = regs->rdi;
  // EXIT
  brk_values.ret_value = regs->rax;
  brk_values.errno_value = "N/A";
  if (brk_values.ret_value < 0) {
    brk_values.errno_value = strerror(-regs->rax);
  }
  printf("brk(%lu) = %d (%s)\n", brk_values.addr, brk_values.ret_value,
         brk_values.errno_value);
}

void handle_mmap_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  mmap_values.addr = regs->rdi;
  mmap_values.length = regs->rsi;
  mmap_values.prot = regs->rdx;
  mmap_values.flags = regs->r10;
  mmap_values.fd = regs->r8;
  mmap_values.offset = regs->r9;
  // EXIT
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

void handle_munmap_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  munmap_values.addr = regs->rdi;
  munmap_values.length = regs->rsi;
  // EXIT
  munmap_values.ret_value = regs->rax;
  munmap_values.errno_value = "N/A";
  if (munmap_values.ret_value < 0) {
    munmap_values.errno_value = strerror(-regs->rax);
  }
  printf("munmap(%lu, %lu) = %d (%s)\n", munmap_values.addr,
         munmap_values.length, munmap_values.ret_value,
         munmap_values.errno_value);
}

void handle_exit_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  exit_values.error_code = regs->rdi;
  // EXIT
  if (regs->orig_rax == SYS_exit) {
    printf("exit(%d)\n", exit_values.error_code);
  } else {
    printf("exit_group(%d)\n", exit_values.error_code);
  }
}

void handle_getpid_entry(pid_t pid, struct user_regs_struct *regs) {
  // EXIT
  getpid_values.ret_value = regs->rax;
  if (regs->orig_rax == SYS_getpid) {
    printf("getpid() = %d\n", getpid_values.ret_value);
  } else {
    printf("getppid() = %d\n", getpid_values.ret_value);
  }
}

void handle_fork_entry(pid_t pid, struct user_regs_struct *regs) {
  // EXIT
  fork_values.ret_value = regs->rax;
  fork_values.errno_value = "N/A";
  if (fork_values.ret_value < 0) {
    fork_values.errno_value = strerror(-regs->rax);
  }
  printf("fork() = %d (%s)\n", fork_values.ret_value, fork_values.errno_value);
}

void handle_clone_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  clone_values.flags = regs->rdi;
  clone_values.stack = (void *)regs->rsi;
  // TODO
  // PEEK INTO THIS TO ACTUALLY GET THE DATA
  clone_values.parent_tid = (int)regs->rdx;
  clone_values.child_tid = (int)regs->r10;
  clone_values.tls = regs->r8;
  // EXIT
  clone_values.ret_value = (long)regs->rax;
  clone_values.errno_value = "N/A";
  if (clone_values.ret_value < 0) {
    clone_values.errno_value = strerror(-regs->rax);
  }
  printf("clone(%lu, %p, %d, %d, %lu) = %ld (%s)\n", clone_values.flags,
         clone_values.stack, clone_values.parent_tid, clone_values.child_tid,
         clone_values.tls, clone_values.ret_value, clone_values.errno_value);
}

void handle_execve_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  execve_values.pathname = malloc(4096);
  read_string_arg(execve_values.pathname, pid, regs->rdi);
  // ARGV AND ENVP ARE CHAR ARRAY ARRAYS, FIX THIS
  execve_values.argv = malloc(4096);
  // read_string_arg(argv, pid, regs->rsi);
  execve_values.envp = malloc(4096);
  // read_string_arg(envp, pid, regs->rdx);
  // EXIT
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

void handle_stat_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  stat_values.filename = malloc(4096);
  read_string_arg(stat_values.filename, pid, regs->rdi);
  // EXIT
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

void handle_fstat_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  fstat_values.fd = (int)regs->rdi;
  // EXIT
  fstat_values.statbuf = (void *)regs->rsi;
  fstat_values.ret_value = (int)regs->rax;
  fstat_values.errno_value = "N/A";
  if (fstat_values.ret_value < 0) {
    fstat_values.errno_value = strerror(-regs->rax);
  }
  printf("fstat(%d, %p) = %d (%s)\n", fstat_values.fd, fstat_values.statbuf,
         fstat_values.ret_value, fstat_values.errno_value);
}

void handle_access_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  access_values.pathname = malloc(4096);
  read_string_arg(access_values.pathname, pid, regs->rdi);
  access_values.mode = (int)regs->rsi;
  // EXIT
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

void handle_getcwd_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  getcwd_values.size = (size_t)regs->rsi;
  // EXIT
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

void handle_chdir_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  chdir_values.path = malloc(4096);
  read_string_arg(chdir_values.path, pid, regs->rdi);
  // EXIT
  chdir_values.ret_value = regs->rax;
  chdir_values.errno_value = "N/A";
  if (chdir_values.ret_value < 0) {
    chdir_values.errno_value = strerror(-regs->rax);
  }
  printf("chdir(%s) = %d, (%s)\n", chdir_values.path, chdir_values.ret_value,
         chdir_values.errno_value);
  free(chdir_values.path);
}

void handle_socket_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  socket_values.domain = regs->rdi;
  socket_values.type = regs->rsi;
  socket_values.protocol = regs->rdx;
  // EXIT
  socket_values.ret_value = regs->rax;
  socket_values.errno_value = "N/A";
  if (socket_values.ret_value < 0) {
    socket_values.errno_value = strerror(-regs->rax);
  }
  printf("socket(%d, %d, %d) = %d, (%s)\n", socket_values.domain,
         socket_values.type, socket_values.protocol, socket_values.ret_value,
         socket_values.errno_value);
}

void handle_bind_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  bind_values.sockfd = regs->rdi;
  bind_values.addr = (void *)regs->rsi;
  bind_values.addrlen = regs->rdx;
  // EXIT
  bind_values.ret_value = regs->rax;
  bind_values.errno_value = "N/A";
  if (bind_values.ret_value < 0) {
    bind_values.errno_value = strerror(-regs->rax);
  }
  printf("bind(%d, %p, %u) = %d (%s)\n", bind_values.sockfd, bind_values.addr,
         bind_values.addrlen, bind_values.ret_value, bind_values.errno_value);
}

void handle_listen_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  listen_values.sockfd = regs->rdi;
  listen_values.backlog = regs->rsi;
  // EXIT
  listen_values.ret_value = regs->rax;
  listen_values.errno_value = "N/A";
  if (listen_values.ret_value < 0) {
    listen_values.errno_value = strerror(-regs->rax);
  }
  printf("listen(%d, %d) = %d (%s)\n", listen_values.sockfd, listen_values.backlog, listen_values.ret_value, listen_values.errno_value);
}

void handle_accept_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  accept_values.sockfd = regs->rdi;
  accept_values.addr = (void *)regs->rsi;
  accept_values.addrlen = regs->rdx;
  // EXIT
  accept_values.ret_value = regs->rax;
  accept_values.errno_value = "N/A";
  if (accept_values.ret_value < 0) {
    accept_values.errno_value = strerror(-regs->rax);
  }
  if (regs->orig_rax == SYS_accept) {
    printf("accept(%d, %p, %u) = %d (%s)", accept_values.sockfd, accept_values.addr, accept_values.addrlen, accept_values.ret_value,
           accept_values.errno_value);
  } else {
    printf("connect(%d, %p, %u) = %d (%s)", accept_values.sockfd, accept_values.addr, accept_values.addrlen, accept_values.ret_value,
           accept_values.errno_value);
  }
}

void handle_pipe_entry(pid_t pid, struct user_regs_struct *regs) {
  // EXIT
  pipe_values.pipefd[0] = ptrace(PTRACE_PEEKDATA, pid, regs->rdi, NULL);
  pipe_values.pipefd[1] = ptrace(PTRACE_PEEKDATA, pid, regs->rdi + sizeof(int), NULL);

  pipe_values.ret_value = regs->rax;
  pipe_values.errno_value = "N/A";
  if (pipe_values.ret_value < 0) {
    pipe_values.errno_value = strerror(-regs->rax);
  }
  printf("pipe([%d, %d]) = %d (%s)", pipe_values.pipefd[0], pipe_values.pipefd[1], pipe_values.ret_value,
         pipe_values.errno_value);
}

void handle_dup_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  dup_values.oldfd = regs->rdi;
  // EXIT
  dup_values.ret_value = regs->rax;
  dup_values.errno_value = "N/A";
  if (dup_values.ret_value < 0) {
    dup_values.errno_value = strerror(-regs->rax);
  }
  printf("dup(%d) = %d (%s)", dup_values.oldfd, dup_values.ret_value, dup_values.errno_value);
}

void handle_dup2_entry(pid_t pid, struct user_regs_struct *regs) {
  // ENTRY
  dup2_values.oldfd = regs->rdi;
  dup2_values.newfd = regs->rsi;
  // EXIT
  dup2_values.ret_value = regs->rax;
  dup2_values.errno_value = "N/A";
  if (dup2_values.ret_value < 0) {
    dup2_values.errno_value = strerror(-regs->rax);
  }
  printf("dup2(%d, %d) = %d (%s)", dup2_values.oldfd, dup2_values.newfd, dup2_values.ret_value, dup2_values.errno_value);
}
