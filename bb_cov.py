#!/usr/bin/env python3

import sys
import os
import uuid
import subprocess
import progressbar

def usage():
    print ("usage: python3 bb_cov.py <AFL queue dir> -- ./binary <args>\n")
    exit(1)

if len(sys.argv) < 4:
    usage()

queue_dir = sys.argv[1]

if not os.path.isdir(queue_dir):
    usage()
if sys.argv[2] != "--":
    usage()

qemu = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bb-trace-qemu")
if not os.path.exists(qemu):
    print("error: bb-trace-qemu binary not found in %s" % os.path.dirname(os.path.realpath(__file__)))
    exit(1)

args = [qemu] + sys.argv[3:]

use_stdin = True
arg_input_idx = -1
if "@@" in args:
    use_stdin = False
    arg_input_idx = args.index("@@")

cov_file = "/tmp/bv-cov-%s" % uuid.uuid4()

env = os.environ.copy()
env["BB_LOG_FILE"] = cov_file

bbs = set()

testcases = os.listdir(queue_dir)

for i in progressbar.progressbar(range(len(testcases))):
    if not testcases[i].startswith("id:"):
        continue
    fname = os.path.join(queue_dir, testcases[i])
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
            bbs.add(addr)

os.unlink(cov_file)

print("\nTotal number of basic blocks: %d\n" % len(bbs))
