#!/usr/bin/env python3
"""
scan_magic.py — 扫描 PE 里的固定常量（magic）并反汇编其周围代码

逆向私有协议时最有效的一招：
  1. 从某个客户端里已知一个 magic（帧头/帧尾/命令字）
  2. 在整个二进制里搜这个 4 字节序列
  3. 批量反汇编每一处的上下文，就能一次性枚举出所有命令构造点

用法：
    python scan_magic.py target.exe 0x67023A45
    python scan_magic.py target.exe 0x67023A45 0x98FDC5BA --window 48

依赖：pip install pefile capstone
"""
import argparse
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("magics", nargs="+", help="十六进制常量，如 0x67023A45")
    ap.add_argument("--window", type=int, default=40, help="上下文反汇编字节数")
    ap.add_argument("--limit", type=int, default=10, help="每个 magic 最多显示几处")
    args = ap.parse_args()

    pe = pefile.PE(args.target)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    is64 = pe.FILE_HEADER.Machine == 0x8664
    data = open(args.target, "rb").read()

    sections = [
        (s.Name.rstrip(b"\0").decode("ascii", "replace"),
         int(s.VirtualAddress), int(s.Misc_VirtualSize),
         int(s.SizeOfRawData), int(s.PointerToRawData))
        for s in pe.sections
    ]

    def va2off(va):
        rva = va - image_base
        for _, sva, vsize, rsize, rptr in sections:
            if sva <= rva < sva + max(vsize, rsize):
                return rptr + (rva - sva)
        return None

    def off2va(off):
        for _, sva, vsize, rsize, rptr in sections:
            if rptr <= off < rptr + rsize:
                return image_base + sva + (off - rptr)
        return None

    text = next((s for s in sections if s[0] == ".text"), None)
    if not text:
        print("[!] 无 .text 段")
        return 1
    _, tva, _, trsize, troff = text
    tstart, tend = troff, troff + trsize

    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)

    for magic_str in args.magics:
        value = int(magic_str, 16)
        pattern = struct.pack("<I", value)

        print("=" * 70)
        print(f"=== magic {magic_str} ===")

        positions = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos < 0:
                break
            positions.append(pos)
            start = pos + 1

        in_text = [p for p in positions if tstart <= p < tend]
        print(f"  全文件出现 {len(positions)} 次，其中 .text 内 {len(in_text)} 次")
        print()

        for pos in in_text[: args.limit]:
            va = off2va(pos)
            begin = max(tstart, pos - args.window // 2)
            begin_va = off2va(begin)
            chunk = data[begin:pos + args.window]
            print(f"  ── 0x{va:08X} ──")
            for insn in md.disasm(chunk, begin_va):
                mark = ""
                if f"0x{value:x}" in insn.op_str or f"0x{value:08x}" in insn.op_str:
                    mark = "   <<<< MAGIC"
                print(f"    {insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{mark}")
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())