/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include "../include/config.h"
#include "exec/cpu_ldst.h"

#define PERSISTENT_DEFAULT_MAX_CNT 1000

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2         \
  do {                                \
                                      \
    if (itb->pc == afl_entry_point) { \
                                      \
      afl_setup();                    \
      afl_forkserver(cpu);            \
                                      \
    }                                 \
                                      \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

struct map_entry {
  u64 addr;
  struct map_entry* next;
};

/* This is equivalent to afl-as.h: */

struct map_entry *afl_area[MAP_SIZE];          /* Exported for afl_gen_trace */

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point,                      /* ELF entry point (_start) */
    afl_start_code,                             /* .text start pointer      */
    afl_end_code;                               /* .text end pointer        */

// This structure is used for tracking which
// code is to be instrumented via afl_instr_code.
struct vmrange {
  target_ulong start, end;
  char* name;
  bool exclude; // Exclude this region rather than include it
  struct vmrange* next;
};

struct vmrange* afl_instr_code;

/* Set in the child process in forkserver mode: */

static int forkserver_installed = 0;
static int shmem_setupped = 0;

unsigned char afl_fork_child;
unsigned int  afl_forksrv_pid;

FILE* out_file;
u32 testcase_id;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUState *);

static void afl_wait_tsl(CPUState *, int);
static void afl_request_tsl(target_ulong, target_ulong, uint32_t, uint32_t,
                            TranslationBlock *, int);

/* Data structures passed around by the translate handlers: */

struct afl_tb {

  target_ulong pc;
  target_ulong cs_base;
  uint32_t     flags;
  uint32_t     cf_mask;

};

struct afl_tsl {

  struct afl_tb tb;
  char          is_chain;

};

struct afl_chain {

  struct afl_tb last_tb;
  uint32_t      cf_mask;
  int           tb_exit;

};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState *, target_ulong, target_ulong,
                                   uint32_t, uint32_t);
static inline TranslationBlock *tb_find(CPUState *, TranslationBlock *, int,
                                        uint32_t);
static inline void              tb_add_jump(TranslationBlock *tb, int n,
                                            TranslationBlock *tb_next);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

static inline int is_valid_addr(target_ulong addr) {

  int          l, flags;
  target_ulong page;
  void *       p;

  page = addr & TARGET_PAGE_MASK;
  l = (page + TARGET_PAGE_SIZE) - addr;

  flags = page_get_flags(page);
  if (!(flags & PAGE_VALID) || !(flags & PAGE_READ)) return 0;

  return 1;

}

static inline int afl_must_instrument(target_ulong addr) {

  // Reject any exclusion regions
  for (struct vmrange* n = afl_instr_code; n; n = n->next) {
    if (n->exclude && addr < n->end && addr >= n->start)
      return 0;
  }

  // Check for inclusion in instrumentation regions
  if (addr < afl_end_code && addr >= afl_start_code)
    return 1;

  for (struct vmrange* n = afl_instr_code; n; n = n->next) {
    if (!n->exclude && addr < n->end && addr >= n->start)
      return 1;
  }

  return 0;

}

static void update_afl_htable(target_ulong pc) {

  if (!afl_must_instrument(pc)) return;
  
  if (!is_valid_addr(pc)) return;
  
  target_ulong cur_loc = pc;
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;
  
  struct map_entry* e = afl_area[cur_loc];
  while (e && e->addr != pc)
    e = e->next;
  
  if (!e) {
    struct map_entry* ne = malloc(sizeof(struct map_entry));
    ne->next = afl_area[cur_loc];
    ne->addr = pc;
    afl_area[cur_loc] = ne;
    
    fprintf(out_file, "%ld, 0x%lx\n", testcase_id, pc);
  }

}

static void afl_setup(void) {

  if (shmem_setupped == 1) return;
  shmem_setupped = 1;

  if (getenv("BB_LOG_FILE")) {
    out_file = fopen(getenv("BB_LOG_FILE"), "w");
  } else {
    out_file = stderr;
  }
  fprintf(out_file, "# testcase_id, bb_address\n");

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code = (abi_ulong)-1;

  }
  
  if (getenv("AFL_CODE_START"))
    afl_start_code = strtoll(getenv("AFL_CODE_START"), NULL, 16);
  if (getenv("AFL_CODE_END"))
    afl_end_code = strtoll(getenv("AFL_CODE_END"), NULL, 16);

  int have_names = 0;
  if (getenv("AFL_QEMU_INST_RANGES")) {
    char *str = getenv("AFL_QEMU_INST_RANGES");
    char *saveptr1, *saveptr2 = NULL, *save_pt1 = NULL;
    char *pt1, *pt2, *pt3 = NULL;
    
    while (1) {

      pt1 = strtok_r(str, ",", &saveptr1);
      if (pt1 == NULL) break;
      str = NULL;
      save_pt1 = strdup(pt1);
      
      pt2 = strtok_r(pt1, "-", &saveptr2);
      pt3 = strtok_r(NULL, "-", &saveptr2);
      
      struct vmrange* n = calloc(1, sizeof(struct vmrange));
      n->next = afl_instr_code;

      if (pt3 == NULL) { // filename
        have_names = 1;
        n->start = (target_ulong)-1;
        n->end = 0;
        n->name = save_pt1;
      } else {
        n->start = strtoull(pt2, NULL, 16);
        n->end = strtoull(pt3, NULL, 16);
        if (n->start && n->end) {
          n->name = NULL;
          free(save_pt1);
        } else {
          have_names = 1;
          n->start = (target_ulong)-1;
          n->end = 0;
          n->name = save_pt1;
        }
      }
      
      afl_instr_code = n;

    }
  }

  if (getenv("AFL_QEMU_EXCLUDE_RANGES")) {
    char *str = getenv("AFL_QEMU_EXCLUDE_RANGES");
    char *saveptr1, *saveptr2 = NULL, *save_pt1;
    char *pt1, *pt2, *pt3 = NULL;

    while (1) {

      pt1 = strtok_r(str, ",", &saveptr1);
      if (pt1 == NULL) break;
      str = NULL;
      save_pt1 = strdup(pt1);

      pt2 = strtok_r(pt1, "-", &saveptr2);
      pt3 = strtok_r(NULL, "-", &saveptr2);

      struct vmrange* n = calloc(1, sizeof(struct vmrange));
      n->exclude = true; // These are "exclusion" regions.
      n->next = afl_instr_code;

      if (pt3 == NULL) { // filename
        have_names = 1;
        n->start = (target_ulong)-1;
        n->end = 0;
        n->name = save_pt1;
      } else {
        n->start = strtoull(pt2, NULL, 16);
        n->end = strtoull(pt3, NULL, 16);
        if (n->start && n->end) {
          n->name = NULL;
          free(save_pt1);
        } else {
          have_names = 1;
          n->start = (target_ulong)-1;
          n->end = 0;
          n->name = save_pt1;
        }
      }

      afl_instr_code = n;

    }
  }

  if (have_names) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/proc/self/maps", "r");

    while ((read = getline(&line, &len, fp)) != -1) {
        int fields, dev_maj, dev_min, inode;
        uint64_t min, max, offset;
        char flag_r, flag_w, flag_x, flag_p;
        char path[512] = "";
        fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
                        " %512s", &min, &max, &flag_r, &flag_w, &flag_x,
                        &flag_p, &offset, &dev_maj, &dev_min, &inode, path);

        if ((fields < 10) || (fields > 11)) {
            continue;
        }
        if (h2g_valid(min)) {
            int flags = page_get_flags(h2g(min));
            max = h2g_valid(max - 1) ? max : (uintptr_t)g2h(GUEST_ADDR_MAX) + 1;
            if (page_check_range(h2g(min), max - min, flags) == -1) {
                continue;
            }
            
            // Now that we have a valid guest address region, compare its
            // name against the names we care about:
            target_ulong gmin = h2g(min);
            target_ulong gmax = h2g(max);

            struct vmrange* n = afl_instr_code;
            while (n) {
              if (n->name && strstr(path, n->name)) {
                if (gmin < n->start) n->start = gmin;
                if (gmax > n->end) n->end = gmax;
                break;
              }
              n = n->next;
            }
        }
    }

    free(line);
    fclose(fp);
  }
  
  if (getenv("AFL_DEBUG") && afl_instr_code) {
    struct vmrange* n = afl_instr_code;
    while (n) {
      if (n->exclude) {
        fprintf(stderr, "Exclude range: 0x%lx-0x%lx (%s)\n",
                (unsigned long)n->start, (unsigned long)n->end,
                n->name ? n->name : "<noname>");
      } else {
        fprintf(stderr, "Instrument range: 0x%lx-0x%lx (%s)\n",
                (unsigned long)n->start, (unsigned long)n->end,
                n->name ? n->name : "<noname>");
      }
      n = n->next;
    }
  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}

static void print_mappings(void) {

  u8    buf[MAX_LINE];
  FILE *f = fopen("/proc/self/maps", "r");

  if (!f) return;

  while (fgets(buf, MAX_LINE, f))
    printf("%s", buf);

  fclose(f);

}

/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {

  if (forkserver_installed == 1) return;
  forkserver_installed = 1;
  
  if (getenv("AFL_QEMU_DEBUG_MAPS")) print_mappings();

  if (write(FORKSRV_FD + 1, &testcase_id, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, &testcase_id, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it, or when it
   decides to chain two TBs together. When this happens, we tell the parent to
   mirror the operation, so that the next fork() has a cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags,
                            uint32_t cf_mask, TranslationBlock *last_tb,
                            int tb_exit) {

  struct afl_tsl   t;
  struct afl_chain c;

  if (!afl_fork_child) {
  
    afl_setup();
    update_afl_htable(pc);
    if (last_tb != NULL)
      update_afl_htable(last_tb->pc);

    return;
  
  }

  t.tb.pc = pc;
  t.tb.cs_base = cb;
  t.tb.flags = flags;
  t.tb.cf_mask = cf_mask;
  t.is_chain = (last_tb != NULL);

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

  if (t.is_chain) {

    c.last_tb.pc = last_tb->pc;
    c.last_tb.cs_base = last_tb->cs_base;
    c.last_tb.flags = last_tb->flags;
    c.cf_mask = cf_mask;
    c.tb_exit = tb_exit;

    if (write(TSL_FD, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
      return;

  }

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl    t;
  struct afl_chain  c;
  TranslationBlock *tb, *last_tb;

  while (1) {

    u8 invalid_pc = 0;

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) break;

    /* Exit command for persistent */

    if (t.tb.pc == (target_ulong)(-1)) return;
    
    update_afl_htable(t.tb.pc);

    tb = tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);

    if (!tb) {

      /* The child may request to transate a block of memory that is not
         mapped in the parent (e.g. jitted code or dlopened code).
         This causes a SIGSEV in gen_intermediate_code() and associated
         subroutines. We simply avoid caching of such blocks. */

      if (is_valid_addr(t.tb.pc)) {

        mmap_lock();
        tb = tb_gen_code(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);
        mmap_unlock();

      } else {

        invalid_pc = 1;

      }

    }

    if (t.is_chain) {

      if (read(fd, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
        break;
        
      update_afl_htable(c.last_tb.pc);

      if (!invalid_pc) {

        last_tb = tb_htable_lookup(cpu, c.last_tb.pc, c.last_tb.cs_base,
                                   c.last_tb.flags, c.cf_mask);
        if (last_tb) { tb_add_jump(last_tb, c.tb_exit, tb); }

      }

    }

  }

  close(fd);

}

