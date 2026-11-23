#!/usr/bin/env python3
"""
extract_inno.py — Inno Setup 安装包静态分析辅助

国产软件的安装包大量使用 Inno Setup。它把真实载荷压缩后追加在 PE 末尾，
直接搜字符串搜不到任何东西，必须先解包。

本脚本：
  1. 判断是否为 Inno Setup 包（PE 末尾有 "Inno Setup Setup Data (x.y.z)"）
  2. 计算附加数据(overlay)偏移与大小
  3. 提示使用 innoextract 解包

用法：
    python extract_inno.py setup.exe

依赖：pip install pefile
    解包需要 innoextract: https://github.com/dscharrer/innoextract/releases
"""
import argparse
import re
import struct
import subprocess
import sys

try:
    import pefile
except ImportError:
    print("需要 pefile: pip install pefile")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--extract", action="store_true", help="调用 innoextract 解包")
    ap.add_argument("--outdir", help="解包输出目录")
    ap.add_argument("--codepage", default="936", help="ANSI 代码页，中文用 936")
    args = ap.parse_args()

    data = open(args.target, "rb").read()
    pe = pefile.PE(args.target)

    # 1) 节表结束位置 -> overlay
    overlay = max(int(s.PointerToRawData) + int(s.SizeOfRawData) for s in pe.sections)
    overlay_size = len(data) - overlay

    print(f"文件大小      : {len(data):,}")
    print(f"节表结束偏移  : 0x{overlay:X}")
    print(f"附加数据      : {overlay_size:,} 字节 ({overlay_size / 1048576:.2f} MB)")

    # 2) 识别 Inno Setup 版本
    m = re.search(rb"Inno Setup Setup Data\s*\(([^)]{0,20})\)", data)
    if not m:
        print()
        print("[!] 未检测到 Inno Setup 签名 —— 可能是 NSIS / InstallShield / 自研安装器")
        return 2

    print(f"Inno Setup    : v{m.group(1).decode('ascii', 'replace')}")

    # 3) 压缩块标记
    tail = data[overlay:overlay + 16]
    if tail[:3] == b"zlb":
        print("压缩方式      : LZMA (zlb 块)")

    print()
    if not args.extract:
        print("解包命令:")
        print(f'  innoextract -l --codepage={args.codepage} "{args.target}"')
        print(f'  innoextract -e -d "{args.outdir or "out"}" --codepage={args.codepage} "{args.target}"')
        return 0

    outdir = args.outdir or "inno_out"
    cmd = ["innoextract", "-e", "-d", outdir, f"--codepage={args.codepage}", args.target]
    print("执行:", " ".join(cmd))
    subprocess.run(cmd, check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())