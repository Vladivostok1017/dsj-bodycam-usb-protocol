#!/usr/bin/env python3
"""
pe_thunks.py — 定位 PE 程序里对某个 DLL 的真实调用点

问题：很多程序按「序号」导入 DLL（无函数名），且编译器生成跳转桩：
         FF 25 <IAT>        ; jmp dword ptr [IAT]
      真实调用是 E8 <rel32> 指向桩地址。
      直接搜 "FF 15 <IAT>"（call [IAT]）会一无所获。

本脚本：
  1. 解析导入表，把 ordinal -> name 映射回来（需要提供原 DLL 路径）
  2. 在全文件搜 FF 25 <IAT_addr> 定位跳转桩
  3. 反汇编 .text，找 E8 调用指向桩的指令
  4. 输出每个函数的真实调用点

用法：
    python pe_thunks.py target.exe --dll libusb0.dll --list-dll libusb0.dll

依赖：pip install pefile capstone
"""
import argparse
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM


def load_ordinal_map(dll_path):
    """从原 DLL 的导出表读 ordinal -> name"""
    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    out = {}
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name:
                out[sym.ordinal] = sym.name.decode("ascii", "replace")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="待分析的 PE 文件")
    ap.add_argument("--dll", help="按序号导入的目标 DLL 路径（用于解析序号）")
    ap.add_argument("--list-dll", default="libusb0.dll",
                    help="只分析哪个 DLL 的导入（默认 libusb0.dll）")
    args = ap.parse_args()

    ordinal_map = {}
    if args.dll:
        ordinal_map = load_ordinal_map(args.dll)
        print(f"[+] 从 {args.dll} 读取到 {len(ordinal_map)} 个导出名")

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

    # 1) 收集目标 DLL 的 IAT 表
    iat = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode("ascii", "replace").lower() != args.list_dll.lower():
            continue
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode("ascii", "replace")
            else:
                name = ordinal_map.get(imp.ordinal, f"ord#{imp.ordinal}")
            iat[int(imp.address)] = name

    if not iat:
        print(f"[!] 未找到 {args.list_dll} 的导入")
        return 1

    print(f"[+] {args.list_dll}: {len(iat)} 个导入")

    # 2) 找跳转桩 FF 25 <IAT>
    thunks = {}
    for iat_va, name in iat.items():
        pattern = b"\xff\x25" + struct.pack("<I", iat_va)
        pos = data.find(pattern)
        if pos >= 0:
            thunks[off2va(pos)] = name

    print(f"[+] 找到 {len(thunks)} 个跳转桩")

    # 3) 反汇编 .text，找 call <thunk>
    text = next((s for s in sections if s[0] == ".text"), None)
    if not text:
        print("[!] 无 .text 段")
        return 1

    _, tva, _, trsize, troff = text
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    md.detail = True

    calls = {}
    for insn in md.disasm(data[troff:troff + trsize], image_base + tva):
        if insn.mnemonic == "call" and insn.operands:
            op = insn.operands[0]
            if op.type == X86_OP_IMM and op.imm in thunks:
                calls.setdefault(thunks[op.imm], []).append(insn.address)

    print()
    print("=== 真实调用点 ===")
    for name in sorted(calls, key=lambda n: -len(calls[n])):
        addrs = calls[name]
        shown = " ".join(f"0x{a:08X}" for a in addrs[:12])
        print(f"  {name:<28} {len(addrs):3d} 处   {shown}")

    return 0


if __name__ == "__main__":
    sys.exit(main())