#!/usr/bin/env python3

import sys
import os
import uuid
import time
import signal
import subprocess

from sortedcontainers import SortedList

def usage():
    print ("usage: python3 bb_cov.py <AFL queue dir> <output file> -- ./binary <args>\n")
    exit(1)

if len(sys.argv) < 5:
    usage()

queue_dir = sys.argv[1]
out_file = os.path.realpath(sys.argv[2])

if sys.argv[3] != "--":
    usage()

qemu = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bb-trace-qemu")
if not os.path.exists(qemu):
    print("error: bb-trace-qemu binary not found in %s" % os.path.dirname(os.path.realpath(__file__)))
    exit(1)

args = [qemu] + sys.argv[4:]

use_stdin = True
arg_input_idx = -1
if "@@" in args:
    use_stdin = False
    arg_input_idx = args.index("@@")

cov_file = "/tmp/bv-cov-%s" % uuid.uuid4()

env = os.environ.copy()
env["BB_LOG_FILE"] = cov_file

bbs = SortedList()
yet_processed = SortedList()

def handle_sigint(signum, frame):
    os.unlink(cov_file)
    print("\nTotal number of basic blocks: %d\n" % len(bbs))
    exit(0)

signal.signal(signal.SIGINT, handle_sigint)

out_file = open(out_file, "a")
out_file.write("# unix_time, bbs_cnt\n")
out_file.flush()

while True:
    slot = None

    try:
        dirlist = os.listdir(queue_dir)
    except FileNotFoundError:
      print("queue folder does not exists")
      time.sleep(0.2)
      continue
    for testcase in dirlist:
        if not testcase.startswith("id:"):
            continue
        if testcase in yet_processed:
            continue
        if slot is None:
            slot = time.time()
            print (" new slot: %d, current # of bbs: %d" % (slot, len(bbs)))
        print(" new testcase: %s" % testcase)
        yet_processed.add(testcase)
        fname = os.path.join(queue_dir, testcase)
        if use_stdin:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, env=env)
            with open(fname, "rb") as f:
                p.stdin.write(f.read())
            p.stdin.close()
            p.wait()
        else:
            args_new = args[:]
            args_new[arg_input_idx] = fname
            p = subprocess.Popen(args_new, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, env=env)
            p.wait()
        
        with open(cov_file) as f:
            for addr in f:
                addr = int(addr, 16)
                if addr not in bbs:
                    bbs.add(addr)
    
    if slot is not None:
        out_file.write("%d, %d\n" % (slot, len(bbs)))
        out_file.flush()
        if int(slot) == int(time.time()):
            time.sleep(1)

