import sys
import os
import subprocess

def usage():
    print ("usage: python3 bb_cov.py <AFL queue dir>\n")
    exit(1)

if len(sys.argv) < 2:
    usage()

queue_dir = sys.argv[1]

if not os.path.isdir(queue_dir):
    usage()


