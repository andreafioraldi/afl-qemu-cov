# afl-qemu-cov

This is an utility to measure the basic blocks coverage of all testcases in the
AFL/AFL++ queue using a patched QEMU.

Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

## Usage

To count the number of basic blocks covered by all the testcases in the queue
run bb_cov.py:

`./afl-qemu-cov -i /path/to/AFL/queue -o output1.csv -- ./binary <args>`

This output.csv file contains tuples in the format
(testcase id, basic block address). Of course the testcase id not no unique as
a testcase may discover more than one basic block.

`./afl-qemu-total-cov -l output1.csv`

This script outputs the Basic Blocks coverage from the output of the previous
script.

`./afl-qemu-ts-cov -i /path/to/AFL/queue -l output1.csv -o output2.csv`

This script will create output2.csv that contains the tuples
(unix timestamp, testcase id, number of new basic blocks discovered).

This script uses the time fields in the name of the testcase and so cannot be
used with AFL but only with AFL++.
