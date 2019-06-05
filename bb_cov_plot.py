#!/usr/bin/env python3

import sys
import os
import subprocess

def usage():
    print ("usage: python3 bb_cov_plot.py <bb_cov_monitor_data> <output_image.png>\n")
    exit(1)

if len(sys.argv) < 3:
    usage()

in_file = sys.argv[1]
out_file = sys.argv[2]

if not os.path.exists(in_file):
    usage()

plot_script = """
set terminal png truecolor enhanced size 1000,300 butt

set output 'OUT_FILE'

set xdata time
set timefmt '%s'
set format x "%b %d\\n%H:%M"
set tics font 'small'
unset mxtics
unset mytics

set grid xtics linetype 0 linecolor rgb '#e0e0e0'
set grid ytics linetype 0 linecolor rgb '#e0e0e0'
set border linecolor rgb '#50c0f0'
set tics textcolor rgb '#000000'
set key outside

set autoscale xfixmin
set autoscale xfixmax

plot 'IN_FILE' using 1:2 with filledcurve x1 title 'total basic blocks' linecolor rgb '#000000' fillstyle transparent solid 0.2 noborder

""".replace("OUT_FILE", out_file).replace("IN_FILE", in_file)

p = subprocess.Popen(["gnuplot"], stdin=subprocess.PIPE)
p.stdin.write(plot_script.encode("utf-8"))
p.stdin.close()
p.wait()

print(" output image written in: " + out_file)
