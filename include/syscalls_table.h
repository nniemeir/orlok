#ifndef SYSCALLS_TABLE_H
#define SYSCALLS_TABLE_H

typedef struct {
  int number;
  const char *name;
} syscall_entry;

extern syscall_entry syscall_table[381];

#endif
