/**
 * main.c
 *
 * Entry point for the program.
 *
 * OVERVIEW:
 * This handles command-line argument parsing and the initial setup steps
 * that differ based on the tracing mode.
 *
 * MODES:
 * 1. PTRACE_TRACEME (selected with -n flag):
 *    - Fork a new child process
 *    - Child calls PTRACE_TRACEME to allow the parent to trace it
 *    - Child executes the specified program
 *    - Parent begins tracing immediately from program start
 *
 * 2. PTRACE_ATTACH (selected with -p flag):
 *    - Attach to an existing process by PID
 *    - Target process is stopped when we attach
 *    - Begin tracing from current execution point
 *    - Detaches when finished tracing to allow process to continue normally
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "trace.h"

/**
 * process_args - Parse command-line arguments
 * @argc: Argument count passed from main
 * @argv: Argument array passed from main
 * @program_path: Output parameter for path to executable (if -n used)
 * @isAttached: Output parameter set to true if -p used, false if -n used
 * @child: Output parameter for PID (only set if -p used)
 *
 * This function processes the command-line options to determine what mode
 * we're operating in. It supports three options:
 *
 * -h: Display program usage
 * -n <program_path>: Specify path of executable to run
 * -p <pid>: Specify PID of the process to hook
 *
 * The function uses getopt() to parse options in a standard UNIX manner.
 * It sets the output parameters based on which mode is selected.
 *
 * Memory Management:
 * If -n is used, this function allocates memory for program_path using
 * strdup(). program_path must be freed in main before exiting.
 */
static void process_args(int argc, char *argv[], char **program_path,
                         bool *isAttached, pid_t *child) {
  int c;

  /*
   * Adding a colon after the letter in getopt's shortopts parameter indicates
   * that the option requires an argument (accessed through optarg).
   * getopt returns -1 when it has finished reading option characters.
   */
  while ((c = getopt(argc, argv, "hn:p:")) != -1) {
    switch (c) {
    case 'h':
      printf("-h\tDisplay program usage\n");
      printf("-n[PATH]\tSpecify path of executable to run\n");
      printf("-p[PID]\tSpecify process ID to hook\n");
      exit(EXIT_SUCCESS);

    case 'n':
      /*
       * TRACEME mode:
       * We'll attempt to start a new process using the specified path.
       */
      *program_path = strdup(optarg);
      if (!*program_path) {
        fprintf(stderr, "Failed to duplicate string to program_path: %s",
                strerror(errno));
        exit(EXIT_FAILURE);
      }
      break;

    case 'p':
      /*
       * ATTACH mode:
       * We'll attempt to connect to the process at the specified PID.
       */
      *child = atoi(optarg);
      *isAttached = true;
      break;

    /*
     * getopt returns '?' if it encounters an unknown option (e.g, if we tried
     *  using -q without including it in shortopts). optopt is the actual
     *  character provided.
     */
    case '?':
      fprintf(stderr, "Unknown option '-%c'. Run with -h for options.\n",
              optopt);
      exit(EXIT_FAILURE);
    }
  }
}

/**
 * main - Entry point for the program
 * @argc: Argument count
 * @argv: Argument array
 *
 * Handles setup and execution of the tracing session.
 *
 * 1. Parse command-line arguments to determine mode
 * 2. Set up the tracing relationship using ptrace
 * 3. Call trace_child() to perform the actual tracing
 * 4. Perform any necessary cleanup and exit
 *
 * Return: 0 on success, exits with error otherwise
 */
int main(int argc, char *argv[]) {
  pid_t child;               // PID of the process to trace
  char *program_path = NULL; // Path to executable (only used for TRACEME)
  bool isAttached = false;   // True if ATTACH mode, false otherwise

  process_args(argc, argv, &program_path, &isAttached, &child);

  if (isAttached) {
    /*
     * PTRACE_ATTACH attempts to stop the process with the specified PID by
     * sending SIGSTOP and hook it.
     *
     * Requirements:
     * - The caller must be root or have the same UID as the user that started
     * said process.
     *
     * - The target process must not already be traced
     * - The target must not be a kernel thread
     *
     * After hooking a process, the tracer must call wait() to receive
     * the stop signal before proceeding. This step occurs in trace_child since
     * it and the rest of the tracing process are the same for both modes.
     */
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
      fprintf(stderr, "ATTACH Failed: %s\n", strerror(errno));
      free(program_path);
      exit(EXIT_FAILURE);
    }
  } else {
    // TRACEME Mode
    if (!program_path) {
      fprintf(stderr, "Must specify program path\n");
      exit(EXIT_FAILURE);
    }

    /*
     * fork() creates a new process by duplicating the calling process
     * fork() returns:
     * - 0 in the child process
     * - child's PID in the parent process
     * - -1 if duplication fails
     */
    child = fork();

    if (child == 0) {
      /*
       * TRACEME attempts to hook this child process for the parent. We call
       * this before executing the specified program so that tracing begins from
       * the start of execution.
       */
      if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        fprintf(stderr, "TRACEME Failed: %s\n", strerror(errno));
        free(program_path);
        exit(EXIT_FAILURE);
      }

      /*
       * execl() replaces the current process image with a new program
       *
       * Arguments:
       *   1. program_path: Path to executable
       *   2. program_path: argv[0] (program name)
       *   3. NULL: End of argument list
       *
       * If execl() succeeds, this code never returns (the process
       * image is replaced). If it returns at all, an error occurred.
       */
      if (execl(program_path, program_path, NULL) == -1) {
        fprintf(stderr, "Failed to execute file: %s\n", strerror(errno));
        free(program_path);
        exit(EXIT_FAILURE);
      }
    } else if (child == -1) {
      // Tracing can not continue we are unable to fork the parent process
      fprintf(stderr, "Failed to fork process: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  // We free the program_path allocated in process_args()
  // If we are in ATTACH mode, this tries to free NULL, which does nothing
  free(program_path);

  trace_child(child, isAttached);

  if (isAttached) {
    /*
     * In ATTACH mode, we must explicitly detach from the process to allow it to
     * continue executing normally when we're done tracing it.
     */
    if (ptrace(PTRACE_DETACH, child, NULL, NULL) == -1) {
      fprintf(stderr, "DETACH Failed: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  exit(0);
}
