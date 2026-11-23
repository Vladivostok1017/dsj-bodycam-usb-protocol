# 厂商字符串门禁（JYA / JYB）

## 现象

警翼 JYManager 在设备厂商字符串不匹配时，**静默失败**，界面提示「请重新连接!!! (No error)」，
且**不产生任何 libusb 错误**（`GetLastError() == 0`），极难定位。

## 逆向结果

连接函数 `0x417FF0` 中的判定逻辑：

```asm
0041803C  call usb_get_busses
00418045  mov  edx, 0x4255                    ; 只比对 VID，不比对 PID
00418060  cmp  word ptr [ecx+0x214], dx       ; device->idVendor == 0x4255 ?
00418067  je   0x418091
...
00418091  push ecx
00418092  call usb_open                       ; 全程序唯一一处 usb_open
004180E8  call usb_set_configuration(h, 1)
00418114  call usb_claim_interface(h, 0)
00418146  call usb_get_string_simple(h, 1, buf, 0x40)   ; 取 iManufacturer

0041817B  call strcmp(buf, "JYA")             ; ← 常量位于 0x575F0C
00418185  jne  0x418193                       ; 不是 JYA → 去比 JYB
00418187  mov  [0x5CDB24], 0x81               ; 端点 = 0x81
00418191  jmp  0x4181B5

00418193  push 0x575F10                       ; "JYB"
0041819B  call strcmp(buf, "JYB")
004181A5  jne  0x418278                       ; 都不是 → 静默失败退出
004181AB  mov  [0x5CDB24], 0x82               ; 端点 = 0x82
```

**软件要求 `iManufacturer` 必须正好是 `"JYA"` 或 `"JYB"`**（警翼的内部产品代号）。

本设备的实际值是 `"AMBA"` → 两者都不匹配 → 跳 `0x418278` 静默退出。

## 绕过

只需改 **2 个字节**：

| 项 | 值 |
|---|---|
| 文件偏移 | `0x17585` |
| 虚拟地址 | `0x418185` |
| 原字节 | `75 0C` （`jne 0x418193`，短跳转） |
| 补丁后 | `90 90` （`nop nop`） |
| 效果 | 跳过 JYA 判定，固定走 `端点 = 0x81` 分支 |

```python
data = bytearray(open("JYManager.exe", "rb").read())
OFF = 0x17585
assert data[OFF:OFF+2] == b"\x75\x0c", "补丁点字节不符"
data[OFF:OFF+2] = b"\x90\x90"
open("JYManager.exe", "wb").write(data)
```

详见 [`../patches/jymanager-vendor-gate.md`](../patches/jymanager-vendor-gate.md)。

## 补丁后的结果

界面行为改变：

| 补丁前 | 补丁后 |
|---|---|
| 「请重新连接!!! (No error)」 | 「密码输入错误!!!」 |

**这说明补丁生效了** —— 软件越过了字符串闸门，进入了协议交互阶段。
（后续仍失败，但那是另一个问题，见 [`negative-results.md`](negative-results.md)。）

## 为什么这个发现重要

`JYA` / `JYB` 是**同一套通用协议按型号区分的端点选择开关**，不是安全校验：

- `JYA` → 用 Bulk IN `0x81`
- `JYB` → 用 Interrupt IN `0x82`

即：厂商靠产品线代号决定走哪条上行通道。对第三方设备，选择 `0x81`（Bulk）通常是正确的。