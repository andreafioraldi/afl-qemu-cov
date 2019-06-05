/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include "../config.h"
#include "tcg-op.h"

/* Declared in afl-qemu-cpu-inl.h */
extern int log_fd;
extern abi_ulong afl_start_code, afl_end_code;

void tcg_gen_afl_callN(void *func, TCGTemp *ret, int nargs, TCGTemp **args);

void afl_maybe_log(abi_ulong cur_loc) {

  char buf[32];
  sprintf(buf, "%llx\n", cur_loc);

  write(log_fd, buf, strlen(buf));
}


/* Generates TCG code for AFL's tracing instrumentation. */
static void afl_gen_trace(target_ulong cur_loc) {

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !log_fd)
    return;

  TCGTemp *args[1] = { tcgv_i64_temp( tcg_const_tl(cur_loc) ) };
  tcg_gen_afl_callN(afl_maybe_log, NULL, 1, args);
  
}
