#!/usr/bin/env python3

import re
import sys
from pathlib import Path

if len(sys.argv) < 2:
    print("Usage:", sys.argv[0], "<dump file>")
    sys.exit(1)

kre = re.compile(r"^[A-Z_]+$")
fout = None

with open(sys.argv[1], encoding="utf-8") as fin:
    for line in fin:
        fields = line.split(":")
        if len(fields) < 2:
            continue

        key = fields[0].strip()
        val = fields[1].strip()

        if key == "Device":
            if fout:
                fout.close()
            fname = val.strip("[]") + ".cfg"
            fout = open(fname, "w", encoding="utf-8")
            fout.write("; " + val + " : " + fields[2].strip() + "\r\n")
        elif kre.match(key) and val != "n/a" and fout is not None:
            fout.write(key + " = " + val + "\r\n")

if fout:
    fout.close()
