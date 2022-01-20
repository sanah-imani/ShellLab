/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * The shell takes in either builtin commands or executes files. The builtin
 * commands include quiting the shell, resuming jobs in the
 * background/foregound, and listing background jobs. This initial processing of
 * what is being entered in the interface is done by an eval funciton. If not we
 * use execve instead a child process, adding the process to a list of jobs,
 * waiting for the child process to terminate, and repeaing zombies where we
 * delete the job from the list.
 *
 * In terms of handlers, we have three: SIGINT, SIGTSTP, and SIGCHLD. Details of
 * each are given below. SIGCHLD handler is where we zeap the zombie children,
 * and SIGTSTP/SIGINT is used for termination of foreground processes.
 *
 * The tsh helper file lays out the important structures and global variables
 * used. The job_t contains an id, set, and the command line tokens. The command
 * line tokens and other details are parsed using the parseline instruction.
 *
 * @Sanah Imani <simani@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * main - sets up the interactive interface, does some initial parsing,
 * initialises the jobs list, installs the handlers, and has a continuous
 * read/eval loop.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/*
 *
 * a way to block sll signals using sigprocmask
 *
 * param[in] s the signal set mask that we use for the blocking
 * param[in] p the signal set mask use to later unblock the same signals
 *
 */
static void block_all(sigset_t *s, sigset_t *p) {
    // initialize sigset pointers
    sigemptyset(s);
    sigemptyset(p);
    // the mask contains all signals
    sigfillset(s);
    // blocking them
    sigprocmask(SIG_BLOCK, s, p);
    return;
}

/*
 *
 * as long as there passed in process is in the foreground we
 * do busy-waiting using sigsuspend
 *
 * param[in] pid a process id for the current job being waited to terminate
 * param[in] pAll a sigset pointer that serves as the mask for sigsuspend
 *
 */
static void foreground_wait(pid_t pid, sigset_t *pAll) {
    jid_t jid = job_from_pid(pid);

    while (job_exists(jid) && job_get_state(jid) == FG) {
        sigsuspend(pAll);
    }

    if (verbose) {
        printf("waitfg: Process (%d) no longer the fg process\n", (int)pid);
    }

    sigprocmask(SIG_SETMASK, pAll, NULL);
    return;
}

// a safe way to open files
// returns a file descriptor
static int safe_file_open(char *file_p, bool in_file) {
    int fd = -1;
    if (in_file) {
        fd = open(file_p, O_RDONLY);
    } else {
        fd = open(file_p, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    }
    return fd;
}

// a safe method to close files
static void safe_file_close(int fileno) {
    if (close(fileno) == -1) {
        perror("");
    }
}

/**
 *
 * Forking of the child and execution happens here
 *
 * param[in] token a structure containing important tokens after parsing the
 * command line param[in] cmdline what was typed into the interface param[in] bg
 * a bool indicating if the user has specified a background process
 * */
static void child_eval(struct cmdline_tokens token, const char *cmdline,
                       bool bg) {
    pid_t pid;
    sigset_t m1, p1;
    int fd_in = -1;
    int fd_out = -1;
    block_all(&m1, &p1);
    if ((pid = fork()) == 0) {
        // set up a process group whose group ID is identical to the child's PID
        if (setpgid(0, 0) < 0) {
            perror("Could not start process group");
            return;
        }

        // input/output direction
        if (token.infile != NULL) {
            fd_in = safe_file_open(token.infile, true);
            if (fd_in != -1) {
                // fd_in -> stdin
                dup2(fd_in, STDIN_FILENO);
            } else {
                fprintf(stderr, "%s: ", token.infile);
                perror("");
                sigprocmask(SIG_SETMASK, &p1, NULL);
                exit(0);
            }
        }
        if (token.outfile != NULL) {
            fd_out = safe_file_open(token.outfile, false);
            if (fd_out != -1) {
                // fd_out -> stdout
                dup2(fd_out, STDOUT_FILENO);
            } else {
                fprintf(stderr, "%s: ", token.outfile);
                perror("");
                sigprocmask(SIG_SETMASK, &p1, NULL);
                exit(0);
            }
        }
        // need to unblock all signals before execve
        sigprocmask(SIG_SETMASK, &p1, NULL);
        if (execve(token.argv[0], token.argv, environ) < 0) {
            fprintf(stderr, "%s: ", token.argv[0]);
            perror("");
            exit(0);
        }
    }

    // error handling for waitpid
    if (pid < 0) {
        perror("fork error");
        return;
    }

    // parent process
    // casing based on background job indication present or not. We don't need
    // to busy wait for backgroundjobs and they can run in the background.
    if (bg) {
        // add job to list as a background job
        add_job(pid, BG, cmdline);
        printf("[%d] (%d) %s\n", (int)job_from_pid(pid), (int)pid, cmdline);
        sigprocmask(SIG_SETMASK, &p1, NULL);
    } else {
        // add job to list as a foreground job
        add_job(pid, FG, cmdline);
        // wait here
        foreground_wait(pid, &p1);
    }
    return;
}

// checking if all characters in the char* are digits
static bool check_numeric(char *argv) {
    int i = 0;
    while (argv[i] != '\0') {
        if (!isdigit(argv[i])) {
            return false;
        }
        i++;
    }
    return true;
}

// checking if jid is only numeric
static bool check_valid_jid(char *argv) {
    if (!check_numeric(argv + 1)) {
        return false;
    }
    return true;
}

// seeing if process exists and if it is identified by a numerical value
static bool check_valid_pid(char *argv) {
    if (!check_numeric(argv)) {
        return false;
    }
    /* convert to pid */
    pid_t pid = (pid_t)atoi(argv);
    jid_t jid = job_from_pid(pid);
    if (jid == 0) {
        return false;
    }
    return true;
}

/*
 * Implementing the builtin bg and fg job commands.
 *
 * The bg job command resumes job by sending it a SIGCONT signal, and then runs
 * it in the background.
 *
 * The fg job command resumes job by sending it a SIGCONT signal, and then runs
 * it in the foreground.
 *
 * param[in] token a struct containing the tokens from a processed command line
 * instruction
 *
 * @returns a job id referring to the process that needs to be resumed
 */

static jid_t bgfgbuilt_in(struct cmdline_tokens token) {
    pid_t pid = -1;
    jid_t jd = 0;
    // need at least two arguments
    if (token.argc >= 2) {
        char **argv = token.argv;
        // the first character of the argument needs to be a digit or %
        if (!isdigit(argv[1][0]) && argv[1][0] != '%') {
            printf("%s: argument must be a PID or %%jobid\n", argv[0]);
            return jd;
        } else if (argv[1][0] == '%') {
            // basic validation checks for jid
            if (!check_valid_jid(&argv[1][1])) {
                printf("%s: invalid jid", argv[1]);
                return jd;
            }
            jd = atoi(argv[1] + 1);
            if (!job_exists(jd)) {
                printf("%s: No such job\n", argv[1]);
                return (jid_t)0;
            }
        } else {
            if (!check_valid_pid(argv[1])) {
                printf("%s: No such process\n", argv[1]);
                return jd;
            }
            pid = (pid_t)atoi(argv[1]);
        }
    } else {
        printf("%s command requires PID or %%jobid argument\n", token.argv[0]);
        return jd;
    }
    if (pid != -1) {
        jd = job_from_pid(pid);
    }
    return jd;
}

/**
 * @brief <What does eval do?>
 *
 * eval is responsible for parsing, interpreting, and executing the command line
 *
 * params[in] cmdline a char pointer to what was written to the shell
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t s, p;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    // directly return if nothing to process
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    // we exit the process (the shell) here
    if (token.builtin == BUILTIN_QUIT)
        exit(1);
    else if (token.builtin == BUILTIN_NONE) {
        // if its not a built-in function we need to execute a command by
        // forking a child
        if (parse_result == PARSELINE_FG || parse_result == PARSELINE_BG) {
            child_eval(token, cmdline, (parse_result == PARSELINE_BG));
        }
    } else if (token.builtin == BUILTIN_JOBS) {
        // get the appropriate file descriptor for list_jobs function
        if (token.outfile == NULL) {
            block_all(&s, &p);
            list_jobs(STDOUT_FILENO);
            sigprocmask(SIG_SETMASK, &p, NULL);
        } else {
            /*is the mode correct */
            int file = safe_file_open(token.outfile, false);
            if (file == -1) {
                fprintf(stderr, "%s: ", token.outfile);
                perror("");
                return;
            }
            block_all(&s, &p);
            list_jobs(file);
            safe_file_close(file);
            sigprocmask(SIG_SETMASK, &p, NULL);
        }
    } else if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        block_all(&s, &p);
        /** after extracting the correct arguments we use SIGCONT to resume
         * jobs**/
        jid_t jd;
        if ((jd = bgfgbuilt_in(token)) >= 1) {
            pid_t pid = job_get_pid(jd);
            // bg case
            if (token.builtin == BUILTIN_BG) {
                job_set_state(jd, BG);
                // -pid to send to the process group
                kill(-pid, SIGCONT);
                printf("[%d] (%d) %s\n", (int)jd, (int)pid,
                       job_get_cmdline(jd));
                sigprocmask(SIG_SETMASK, &p, NULL);
            } else {
                // fg case
                job_set_state(jd, FG);
                kill(-pid, SIGCONT);
                // wait and ensure job terminates
                foreground_wait(pid, &p);
            }
        } else {
            sigprocmask(SIG_SETMASK, &p, NULL);
        }
        return;
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * handles the SIGCHLD signals
 * need to reap all the zombie child processes
 *
 * param[in] sig an integer representing the signal
 */
void sigchld_handler(int sig) {
    if (verbose) {
        sio_printf("sigchld_handler: entering\n");
    }
    pid_t pid;
    int status;
    sigset_t s, p;
    int olderrno = errno;
    // waitpid obstains status information pertaining to one of the caller's
    // status functions
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        // no interruptions
        block_all(&s, &p);
        // casing on the status
        if (WIFEXITED(status)) {
            jid_t jd = job_from_pid(pid);
            // need to delete the job
            delete_job(jd);
            if (verbose) {
                sio_printf("sigchld_handler: Job [%d] (%d) deleted\n", (int)jd,
                           (int)pid);
                sio_printf("sigchld_handler: Job [%d] (%d) terminated normally "
                           "(status %d)\n",
                           (int)jd, (int)pid, WEXITSTATUS(status));
            }
        }

        if (WIFSIGNALED(status)) {
            jid_t jd = job_from_pid(pid);
            // need to delete the job
            delete_job(job_from_pid(pid));
            if (verbose) {
                sio_printf("sigchld_handler: Job [%d] (%d) deleted\n", (int)jd,
                           (int)pid);
            }
            sio_printf("Job [%d] (%d) terminated by signal %d\n", (int)jd,
                       (int)pid, WTERMSIG(status));
        }
        if (WIFSTOPPED(status)) {
            jid_t jid = job_from_pid(pid);
            // do not delete the job but instead change its status
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", (int)jid,
                       (int)pid, WSTOPSIG(status));
        }

        // unblock all
        sigprocmask(SIG_SETMASK, &p, NULL);
    }

    // checking if waitpid worked
    if (pid != 0 && errno != ECHILD) {
        perror("waitpid error");
        exit(1);
    }
    if (verbose) {
        sio_printf("sigchld_handler: exiting\n");
    }

    errno = olderrno;
    return;
}

/**
 * @brief <What does sigint_handler do?>
 *
 * handles the signal caused by a terminal interrupt character (Ctlr + C)
 *
 * param[in] sig the integer representing the signal being handles
 */
void sigint_handler(int sig) {
    if (verbose)
        sio_printf("sigint_handler: entering.");
    int olderrno = errno;
    sigset_t s, p;
    // no interruptions
    block_all(&s, &p);
    jid_t jd = fg_job();
    // ensure that there is a foreground job
    if (jd != 0) {
        pid_t pid = job_get_pid(jd);
        // we know that the pid for the shell in the foreground process group is
        // not 0 (is invalid otherwise)
        if (pid != 0) {
            // then sig is sent to every process in the process group
            kill(-pid, sig);
        }
    }
    // unblock
    sigprocmask(SIG_SETMASK, &p, NULL);
    // restoring errno
    errno = olderrno;
    if (verbose)
        sio_printf("sigint_handler: exiting.");
    return;
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * handles SIGSTP signals
 * Eg- Ctlr + Z
 *
 * param[in] sig the integer representing the signal being handles
 */
void sigtstp_handler(int sig) {
    if (verbose)
        sio_printf("sigtstp_handler: entering.");
    int olderrno = errno;
    sigset_t s, p;
    // blocking signals
    block_all(&s, &p);
    jid_t jd = fg_job();
    // checking if there is a foreground job
    if (jd != 0) {
        pid_t pid = job_get_pid(jd);
        // we know that the pid for the shell in the foreground process group is
        // not 0.
        if (pid != 0) {
            // then sig is sent to every process in the process group
            kill(-pid, SIGTSTP);
        }
    }
    // unblocking
    sigprocmask(SIG_SETMASK, &p, NULL);
    // restoring errno
    errno = olderrno;
    if (verbose)
        sio_printf("sigtstp_handler: exiting");
    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
