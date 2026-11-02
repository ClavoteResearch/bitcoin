#!/usr/bin/env python3
"""Qcoin: count copies of an ML-DSA secret key in a running process's memory (Linux, needs ptrace rights on the pid, e.g. root).

usage: memscan_mldsa.py PID SKFILE
Counts, in every readable private mapping of PID (heap, stack, anonymous maps; file-backed maps are skipped):
  full  - occurrences of the whole secret key
  K     - occurrences of the 32-byte signing seed K (sk[32:64]), which a signer copies out of the key on its own
  tr    - occurrences of the 64-byte public-key hash tr (sk[64:128]) as a control: it is not secret, but it is stored right
          behind K in the key, so full-key remnants and unpacked remnants are told apart
Prints one line: full=<n> K=<n> tr=<n>
"""
import re
import sys


def main():
    pid, skfile = sys.argv[1], sys.argv[2]
    sk = open(skfile, "rb").read()
    needles = {"full": sk, "K": sk[32:64], "tr": sk[64:128]}
    counts = dict.fromkeys(needles, 0)
    with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for line in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
            start, end, perms, path = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
            if not perms.startswith("r") or "p" not in perms:
                continue
            if path.startswith("/") and not path.startswith("/dev/shm"):
                continue  # file-backed: binaries, libraries
            if path in ("[vvar]", "[vdso]", "[vsyscall]"):
                continue
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except (OSError, ValueError, OverflowError):
                continue
            for name, needle in needles.items():
                counts[name] += data.count(needle)
    print("full=%d K=%d tr=%d" % (counts["full"], counts["K"], counts["tr"]))


main()
