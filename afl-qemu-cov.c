#define AFL_MAIN
#include "include/alloc-inl.h"
#include "include/config.h"
#include "include/debug.h"
#include "include/types.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CASE_PREFIX "id:"

s32 forksrv_pid,                        /* PID of the fork server           */
    child_pid;                          /* PID of the tested program        */

s32 fsrv_ctl_fd,                        /* Fork server control pipe (write) */
    fsrv_st_fd;                         /* Fork server status pipe (read)   */

u8 *in_dir, *output_file, *out_file;

s32 out_fd;                           /* Persistent fd for out_file         */

static u32 total_execs,                /* Total number of execs             */
    missed_hangs,                      /* Misses due to hangs               */
    missed_crashes;                    /* Misses due to crashes             */
u32 exec_tmout = EXEC_TIMEOUT;         /* Exec timeout (ms)                 */

u8 use_stdin = 1;                      /* Use stdin for program input?      */

s32 dev_null_fd = -1;                  /* FD to /dev/null                   */

u8 *target_path;                        /* Path to target binary            */
u8 *target_path_orig;                   /* Path to target binary            */

static volatile u8 stop_soon;          /* Ctrl-C pressed?                   */

u8 child_timed_out;

static u8 run_target(char **argv, u8 *mem, u32 len, u32 testcase_id);

static void collect_coverage(char **argv) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8 *fn;

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again.\n");

    PFATAL("Unable to open '%s'", in_dir);

  }

  for (i = 0; i < nl_cnt; ++i) {

    u32 testcase_id;

    if (nl[i]->d_name[0] == '.' ||
        sscanf(nl[i]->d_name, CASE_PREFIX "%06u", &testcase_id) != 1)
      continue;

    SAYF("%d/%d\t%s\n", testcase_id, nl_cnt - 2, nl[i]->d_name);

    struct stat st;

    u8 *fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);

    free(nl[i]);

    s32 fd = open(fn, O_RDONLY);                             /* not tracked */

    if (fstat(fd, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {

      ck_free(fn);
      continue;

    }

    u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED)
      PFATAL("Unable to mmap '%s'", fn);

    run_target(argv, mem, st.st_size, testcase_id);

    munmap(mem, st.st_size);

    if (stop_soon)
      break;

  }

  free(nl);                                                  /* not tracked */

}

/* Write modified data to file for testing. If use_stdin is clear, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void *mem, u32 len) {

  s32 fd = out_fd;

  if (!use_stdin) {

    unlink(out_file);                                     /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0)
      PFATAL("Unable to create '%s'", out_file);

  } else

    lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (use_stdin) {

    if (ftruncate(fd, len))
      PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else

    close(fd);

}

/* Execute target application. Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 run_target(char **argv, u8 *mem, u32 len, u32 testcase_id) {

  static struct itimerval it;
  int status = 0;

  write_to_testcase(mem, len);

  s32 res;

  /* we have the fork server up and running, so simply
     tell it to have at it, and then read back PID. */

  if ((res = write(fsrv_ctl_fd, &testcase_id, 4)) != 4) {

    if (stop_soon)
      return 0;
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

    if (stop_soon)
      return 0;
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if (child_pid <= 0)
    FATAL("Fork server is misbehaving (OOM?)");

  /* Configure timeout, wait for child, cancel timeout. */

  if (exec_tmout) {

    it.it_value.tv_sec = (exec_tmout / 1000);
    it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

    if (stop_soon)
      return 0;
    RPFATAL(res, "Unable to communicate with fork server (OOM?)");

  }

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ Aborted by user +++\n" cRST);
    exit(1);

  }

  /* Always discard inputs that time out. */

  if (child_timed_out) {

    missed_hangs++;
    return 0;

  }

  return 0;

}

/* start the app and it's forkserver */

static void init_forkserver(char **argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status = 0;
  s32 rlen;

  ACTF("Spinning up the fork server...");
  if (pipe(st_pipe) || pipe(ctl_pipe))
    PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0)
    PFATAL("fork() failed");

  if (!forksrv_pid) {

    if (dup2(use_stdin ? out_fd : dev_null_fd, 0) < 0 ||
        dup2(dev_null_fd, 1) < 0) {

      PFATAL("dup2() failed");

    }

    if (output_file && dup2(dev_null_fd, 2) < 0)
      PFATAL("dup2() failed");

    close(dev_null_fd);
    close(out_fd);

    setsid();

    // Set up control and status pipes, close the unneeded original fds.

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0)
      PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0)
      PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    execv(target_path, argv);

    exit(0);

  }

  // Close the unneeded endpoints.

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd = st_pipe[0];

  // Configure timeout, wait for child, cancel timeout.

  if (exec_tmout) {

    child_timed_out = 0;
    it.it_value.tv_sec = (exec_tmout * FORK_WAIT_MULT / 1000);
    it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  // If we have a four-byte "hello" message from the server, we're all set.
  // Otherwise, try to figure out what went wrong.

  if (rlen == 4) {

    ACTF("All right - fork server is up.");
    return;

  }

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  u8 child_crashed;

  if (WIFSIGNALED(status))
    child_crashed = 1;

  if (child_timed_out)
    SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
  else if (stop_soon)
    SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);
  else if (child_crashed)
    SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST, WTERMSIG(status));

}

/* Find binary. */

static void find_binary(u8 *fname) {

  u8 *env_path = 0;
  struct stat st;

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);

    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else

        cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4)
        break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path)
      FATAL("Program '%s' not found or not executable", fname);

  }

}

void detect_file_args(char **argv, u8 *prog_in) {

  u32 i = 0;
#ifdef __GLIBC__
  u8 *cwd = getcwd(NULL, 0);                /* non portable glibc extension */
#else
  u8 *cwd;
  char *buf;
  long size = pathconf(".", _PC_PATH_MAX);
  if ((buf = (char *)malloc((size_t)size)) != NULL) {

    cwd = getcwd(buf, (size_t)size);                    /* portable version */

  } else {

    PFATAL("getcwd() failed");
    cwd = 0;                                          /* for dumb compilers */

  }

#endif

  if (!cwd)
    PFATAL("getcwd() failed");

  while (argv[i]) {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      if (!prog_in)
        FATAL("@@ syntax is not supported by this tool.");

      /* Be sure that we're always using fully-qualified paths. */

      if (prog_in[0] == '/')
        aa_subst = prog_in;
      else
        aa_subst = alloc_printf("%s/%s", cwd, prog_in);

      use_stdin = 0;

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (prog_in[0] != '/')
        ck_free(aa_subst);

    }

    i++;

  }

  free(cwd);                                                 /* not tracked */

}

char **get_qemu_argv(u8 *own_loc, char **argv, int argc) {

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char *) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";
  target_path_orig = target_path;

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-cov-tracer", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-cov-tracer", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else

    ck_free(own_copy);

  /*if (!access(BIN_PATH "/afl-qemu-cov-tracer", X_OK)) {

    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-cov-tracer");
    return new_argv;

  }*/

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary.\n"
       "    If you already have the binary installed, you may need to specify\n"
       "    AFL_PATH in the environment.\n\n");

  FATAL("Failed to locate 'afl-qemu-cov-tracer'.");

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (child_pid > 0)
    kill(child_pid, SIGKILL);

}

/* Handle timeout signal. */

static void handle_timeout(int sig) {

  if (child_pid > 0) {

    child_timed_out = 1;
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    child_timed_out = 1;
    kill(forksrv_pid, SIGKILL);

  }

}

/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

}

/* Get rid of temp files (atexit handler). */

static void at_exit_handler(void) {

  if (out_file)
    unlink(out_file);                                      /* Ignore errors */

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

  u8 *x;

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0)
    PFATAL("Unable to open /dev/null");

  if (!out_file) {

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = getenv("TMPDIR");
      if (!use_dir)
        use_dir = "/tmp";

    }

    out_file = alloc_printf("%s/.afl-qemu-cov-temp-%u", use_dir, getpid());

  }

  unlink(out_file);

  out_fd = open(out_file, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0)
    PFATAL("Unable to create '%s'", out_file);

  if (getenv("AFL_PRELOAD")) {

    u8 *qemu_preload = getenv("QEMU_SET_ENV");
    u8 *afl_preload = getenv("AFL_PRELOAD");
    u8 *buf;

    s32 i, afl_preload_size = strlen(afl_preload);
    for (i = 0; i < afl_preload_size; ++i) {

      if (afl_preload[i] == ',')
        PFATAL("Comma (',') is not allowed in AFL_PRELOAD when -Q is "
               "specified!");

    }

    if (qemu_preload)
      buf = alloc_printf("%s,LD_PRELOAD=%s", qemu_preload, afl_preload);
    else
      buf = alloc_printf("LD_PRELOAD=%s", afl_preload);

    setenv("QEMU_SET_ENV", buf, 1);

    ck_free(buf);

  }

}

/* Display usage hints. */

static void usage(u8 *argv0) {

  SAYF("\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i file       - input directory\n"
       "  -o file       - output CSV\n\n"

       "Execution control settings:\n\n"

       "  -f file       - input file read by the tested program (stdin)\n"
       "  -t msec       - timeout for each run (%d ms)\n\n"

       "For additional tips, please consult README.md.\n\n",

       argv0, EXEC_TIMEOUT);

  exit(1);

}

/* Main entry point */

int main(int argc, char **argv) {

  s32 opt;
  u8 timeout_given = 0;
  char **use_argv;

  SAYF(cCYA "afl-qemu-cov" VERSION cRST
            " by Andrea Fioraldi <andreafioraldi@gmail.com>\n");

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:B:xeQUWh")) > 0)

    switch (opt) {

    case 'i':

      if (in_dir)
        FATAL("Multiple -i options not supported");
      in_dir = optarg;
      break;

    case 'o':

      if (output_file)
        FATAL("Multiple -o options not supported");
      output_file = optarg;

      if (strcmp(output_file, "-"))
        setenv("BB_LOG_FILE", output_file, 1);
      else
        output_file = NULL; // stderr

      break;

    case 'f':

      if (out_file)
        FATAL("Multiple -f options not supported");
      use_stdin = 0;
      out_file = optarg;
      break;

    case 't':

      if (timeout_given)
        FATAL("Multiple -t options not supported");
      timeout_given = 1;

      exec_tmout = atoi(optarg);

      if (exec_tmout < 10 || optarg[0] == '-')
        FATAL("Dangerously low value of -t");

      break;

    case 'h':
      usage(argv[0]);
      return -1;
      break;

    default:
      usage(argv[0]);

    }

  if (optind == argc || !in_dir)
    usage(argv[0]);

  atexit(at_exit_handler);
  setup_signal_handlers();

  set_up_environment();
  find_binary(argv[optind]);
  detect_file_args(argv + optind, out_file);

  use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);

  SAYF("\n");

  init_forkserver(use_argv);

  collect_coverage(use_argv);

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

