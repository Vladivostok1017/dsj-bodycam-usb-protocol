# JYManager 厂商闸门绕过补丁

## 补丁内容

| 项 | 值 |
|---|---|
| 目标文件 | `JYManager.exe`（警翼现场执法记录仪管理软件 V3.4.0.1） |
| 原始 SHA-256 | `08921e8ac0edac2faff8a3c412f589f016cb4b3f44bd4fb32bd8df42297d77f1` |
| 文件偏移 | `0x17585` |
| 虚拟地址 | `0x418185`（ImageBase `0x400000`，`.text` 段） |
| 原始字节 | `75 0C`（`jne 0x418193`） |
| 补丁字节 | `90 90`（`nop nop`） |

补丁后 SHA-256：`e0d085dc1940c69bec14fbf130d7fc59d3989e5a750d32c66428eb91fab55361`

## 作用

跳过对设备 `iManufacturer` 字符串的 `"JYA"` 判定，使流程固定进入 `端点 = 0x81` 分支，
允许非警翼品牌的 Ambarella 设备通过初始化。

## 应用

```python
#!/usr/bin/env python3
import hashlib, sys

OFF = 0x17585
ORIG = b"\x75\x0c"
PATCH = b"\x90\x90"
EXPECTED = "08921e8ac0edac2faff8a3c412f589f016cb4b3f44bd4fb32bd8df42297d77f1"

path = sys.argv[1]
raw = open(path, "rb").read()

got = hashlib.sha256(raw).hexdigest()
if got != EXPECTED:
    print(f"[!] SHA-256 不匹配: {got}")
    print("    版本不符，请先确认是 V3.4.0.1")
    sys.exit(1)

if raw[OFF:OFF+2] == PATCH:
    print("[=] 已是补丁状态")
    sys.exit(0)

if raw[OFF:OFF+2] != ORIG:
    print(f"[!] 补丁点字节不符: {raw[OFF:OFF+2].hex()}")
    sys.exit(1)

data = bytearray(raw)
data[OFF:OFF+2] = PATCH
open(path, "wb").write(data)
print("[+] 补丁已应用")

# 验证：反汇编应为 nop nop 后接 mov [0x5CDB24], 0x81
```

## 反汇编对照

**补丁前**

```asm
0041817B  call strcmp(buf, "JYA")
00418183  test eax, eax
00418185  jne  0x418193          ; ← 不是 JYA，去比 JYB
00418187  mov  dword ptr [0x5CDB24], 0x81
00418191  jmp  0x4181B5
00418193  push 0x575F10          ; "JYB"
```

**补丁后**

```asm
0041817B  call strcmp(buf, "JYA")
00418183  test eax, eax
00418185  nop
00418186  nop                    ; ← 永远不跳
00418187  mov  dword ptr [0x5CDB24], 0x81
00418191  jmp  0x4181B5
```

## 效果

| 状态 | 界面提示 |
|---|---|
| 补丁前 | 「请重新连接!!! (No error)」 |
| 补丁后 | 「密码输入错误!!!」 |

报错改变即证明补丁生效。但**目标设备仍无法通信** —— 那是设备固件层面的问题，
见 [`../docs/negative-results.md`](../docs/negative-results.md)。

## 回退

把 `90 90` 改回 `75 0C` 即可。建议操作前先备份原始文件。