#!/usr/bin/env python3
"""
dump_strings.py — 提取 PE 里的 ASCII / UTF-16 字符串，并解析 RT_STRING 资源表

MFC / Win32 程序的中文界面字符串通常在资源字符串表里，代码用
LoadStringW(id, ...) 加载 —— 所以你搜不到对字符串地址的引用。
必须先建 ID <-> 文本 的映射，再搜 push <id>。

用法：
    python dump_strings.py target.exe                  # 全部字符串
    python dump_strings.py target.exe --strings-only    # 只看字符串表
    python dump_strings.py target.exe --grep 密码       # 过滤

依赖：pip install pefile
"""
import argparse
import re
import struct
import sys

try:
    import pefile
except ImportError:
    print("需要 pefile: pip install pefile")
    sys.exit(1)


def extract_strings(data, min_ascii=4, min_utf16=3):
    """双路提取：ASCII + UTF-16LE（.NET / Unicode 程序常用后者）"""
    ascii_strs = [m.group().decode("latin-1")
                  for m in re.finditer(rb"[\x20-\x7E]{%d,}" % min_ascii, data)]

    utf16_strs = []
    i, n, cur = 0, len(data), []
    while i < n - 1:
        ch = data[i] | (data[i + 1] << 8)
        if (0x20 <= ch <= 0x7E) or (0x4E00 <= ch <= 0x9FFF) or (0x3000 <= ch <= 0x303F):
            cur.append(chr(ch))
            i += 2
        else:
            if len(cur) >= min_utf16:
                utf16_strs.append("".join(cur))
            cur = []
            i += 2
    if len(cur) >= min_utf16:
        utf16_strs.append("".join(cur))

    return ascii_strs, utf16_strs


def parse_string_table(pe, data):
    """解析 RT_STRING (type 6) 资源，返回 {string_id: text}"""
    sections = [
        (int(s.VirtualAddress), int(s.Misc_VirtualSize),
         int(s.SizeOfRawData), int(s.PointerToRawData))
        for s in pe.sections
    ]

    def va2off(va):
        for sva, vsize, rsize, rptr in sections:
            if sva <= va < sva + max(vsize, rsize):
                return rptr + (va - sva)
        return None

    out = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return out

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != 6:      # RT_STRING
            continue
        for block in entry.directory.entries:
            block_id = block.id
            for res in block.directory.entries:
                d = res.data.struct
                off = va2off(int(d.OffsetToData))
                if off is None:
                    continue
                end = off + d.Size
                p = off
                for i in range(16):
                    if p + 2 > end:
                        break
                    ln = struct.unpack_from("<H", data, p)[0]
                    p += 2
                    sid = (block_id - 1) * 16 + i
                    if ln:
                        try:
                            out[sid] = data[p:p + ln * 2].decode("utf-16-le")
                        except UnicodeDecodeError:
                            pass
                        p += ln * 2
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--strings-only", action="store_true", help="只输出资源字符串表")
    ap.add_argument("--grep", help="只显示包含该子串的行")
    ap.add_argument("--max", type=int, default=0, help="每个类别最多显示多少条")
    args = ap.parse_args()

    data = open(args.target, "rb").read()

    if args.strings_only:
        pe = pefile.PE(args.target)
        table = parse_string_table(pe, data)
        print(f"=== RT_STRING 资源表：{len(table)} 条 ===")
        for sid in sorted(table):
            text = table[sid]
            if args.grep and args.grep not in text:
                continue
            print(f"  ID={sid:<6d} {text}")
        return 0

    ascii_strs, utf16_strs = extract_strings(data)
    print(f"=== ASCII 字符串 {len(ascii_strs)} 条 ===")
    shown = 0
    for s in ascii_strs:
        if args.grep and args.grep not in s:
            continue
        print(f"  {s}")
        shown += 1
        if args.max and shown >= args.max:
            break

    print()
    print(f"=== UTF-16 字符串 {len(utf16_strs)} 条 ===")
    seen = set()
    shown = 0
    for s in utf16_strs:
        if s in seen:
            continue
        if args.grep and args.grep not in s:
            continue
        seen.add(s)
        print(f"  {s}")
        shown += 1
        if args.max and shown >= args.max:
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())