#!/usr/bin/env python3
"""tools/fdt_dump.py -- minimal flattened device tree walker (host has no dtc).

Emits "<path> <property> = <value>" lines; string properties are decoded, everything else
is hex so that a byte-array property (register lists live in DT on these drivers) stays readable.
"""
import struct
import sys

BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
FDT_VERSION1 = 0x00000010


def cstr(b, off):
    end = b.index(b"\0", off)
    return b[off:end].decode("utf-8", "replace")


def main(path):
    blob = open(path, "rb").read()
    magic, totalsize, off_dt, off_str, off_rsv, version, last_comp, boot_cpu, \
        size_str, size_struct = struct.unpack_from(">10I", blob, 0)
    if magic != 0xd00dfeed:
        sys.exit(f"not an FDT: magic={magic:#x}")
    if version < FDT_VERSION1:
        print(f"# fdt version={version} (< {FDT_VERSION1})", file=sys.stderr)
    strings = blob[off_str:off_str + size_str]
    start = off_dt
    end = off_dt + size_struct
    stack = []
    i = start
    name = None
    while i < end:
        token, = struct.unpack_from(">I", blob, i)
        i += 4
        if token == NOP:
            continue
        if token == BEGIN_NODE:
            name = cstr(blob, i)
            i += (len(name) + 1 + 3) & ~3
            stack.append(name)
            continue
        if token == END_NODE:
            stack.pop()
            continue
        if token == PROP:
            length, nameoff = struct.unpack_from(">II", blob, i)
            i += 8
            pname = cstr(strings, nameoff)
            data = blob[i:i + length]
            i += (length + 3) & ~3
            txt = decode(pname, data)
            print(f"{node_path(stack)} {pname} = {txt}")
            continue
        if token == END:
            break
        print(f"# unknown token {token} at {i-4:#x}", file=sys.stderr)
        break


def node_path(stack):
    out = []
    for s in stack:
        out.append(s if s else "/")
    p = "/".join(out)
    return p if p.startswith("/") else "/" + p


def decode(pname, data):
    try:
        s = data.rstrip(b"\0").decode("ascii")
        if s and all(32 <= ord(c) < 127 for c in s):
            return repr(s) if len(s) <= 160 else repr(s[:160]) + "..."
    except Exception:
        pass
    cells = []
    for j in range(0, len(data) - 3, 4):
        cells.append(struct.unpack_from(">I", data, j)[0])
    if cells and len(data) % 4 == 0:
        return "u32[" + ",".join(f"{c:#x}" if c < 0x10000 else f"{c:#x}" for c in cells) + "]"
    return "hex[" + data.hex(" ") + "]"


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fw/dtb.dtb")
