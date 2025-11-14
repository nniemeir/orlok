# Orlok
A basic strace-like process tracing utility for x86_64 systems, created for educational purposes,

## Dependencies
* GCC
* GNU make

## Installation
Compile the project
```
make
```
Install the compiled binary
```
make install
```

### Make Targets 
- `make` - Compile the binary
- `make install` – Install binary
- `make clean` – Remove build objects
- `make fclean` - Remove build objects and binary

### Supported Syscalls
**File I/O:** read, write, openat, close, lseek, stat, lstat, fstat, access, getcwd, chdir, brk

**Process:** execve, exit, exit_group

**Memory:** mmap munmap

**Networking:** socket, bind, listen, accept, connect

**File Descriptors:** dup, dup2

## Usage
```
orlok [OPTIONS]
```

### Options
```
-h                     Display program usage
-n <program_path>      Specify path of executable to run
-p <pid>               Specify PID of the process to hook
```

## License
GNU General Public License V2

Copyright (c) 2025 Jacob Niemeir
