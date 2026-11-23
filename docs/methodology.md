# 方法论：从零逆出协议

> 记录实际使用的技术路径，供逆向其他嵌入式 USB 设备时复用。

## 0. 环境

| 组件 | 用途 |
|---|---|
| Ghidra 12.1.4 | 静态反汇编（本项目主要用自研脚本，Ghidra 作为交叉验证） |
| Python 3.13 + `pefile` + `capstone` + `Pillow` | PE 解析、指令反汇编、PDF 图像处理 |
| PowerShell 7 + 32 位 PowerShell 5.1 | 32 位 libusb0 DLL 的宿主进程 |
| Zadig（libwdi） | 给未知 USB 设备绑定 libusb-win32 驱动 |

## 1. 从"看得见的症状"倒推

错误字符串是最好的入口。拿到客户端后第一步永远是**提取全部字符串**：

```python
# UTF-16LE（.NET / Unicode 程序）+ ASCII 双路提取
```

本项目里 `"请重新连接!!! (No error)"` 这个字符串直接指向了失败函数。

## 2. 字符串 → 资源表 → ID

MFC / Win32 程序的中文字符串通常在 **RT_STRING 资源表**里，代码通过 `LoadStringW(id, ...)` 加载，
所以你**搜不到对字符串地址的引用**。

正确做法：解析资源目录，把 `ID ↔ 文本` 建表，然后在 `.text` 里搜 `push <id>`：

```python
# 资源块 ID 与字符串 ID 的关系: string_id = (block_id - 1) * 16 + index
```

拿到 ID 后搜 `push imm` 就能定位使用点。本项目：

```
ID=113  请重新连接!!!
ID=102  连接错误，请检查后再试！
ID=139  已经设置移动磁盘模式!
```

## 3. libusb 调用点：thunk 间接调用

`libusb0.dll` 是**按序号导入**的，且编译器生成了跳转桩（`FF 25 <IAT>`）。
直接搜 `FF 15 <IAT>`（`call [IAT]`）**搜不到**，必须：

1. 解析导出表把 `ordinal → name` 映射回来
2. 在文件里搜 `FF 25 <IAT_addr>` 找桩地址
3. 再搜 `E8 <rel32>` 指向桩地址，得到真实调用点

```python
# 见 tools/pe-analysis/pe_thunks.py
```

本项目结果：

```
usb_open      → 1 处（全程序唯一）
usb_bulk_write→ 1 处
usb_bulk_read → 1 处
```

**调用点唯一 = 通信逻辑高度集中 = 容易完整读完。**

## 4. 帧格式：找"魔法常量"

在发送函数的调用点往前看，通常能直接看到帧的构造函数：

```asm
mov dword ptr [esp+0x2c], 0x67023a45   ; magic
mov dword ptr [esp+0x30], 0x123        ; cmd
mov dword ptr [esp+0x34], edx          ; param（来自全局变量）
mov dword ptr [esp+0x38], ebp          ; trailer
```

**技巧**：把 magic 的 4 字节小端序列在整个 `.text` 里搜，一次性找到所有命令构造点，
然后批量反汇编对比 —— 能快速枚举出全部命令字。

## 5. 参数来自全局变量 → 去 `.data` 读初值

`param` 从 `[0x49D350]` 这类全局变量取值 → 直接读 `.data` 段的初始值即可：

```
0x0049D350  20 00 00 00  →  0x20
```

## 6. 交叉验证多个客户端

**这是本项目最有效的一招。** 拿到同芯片方案的多个厂商客户端后：

- 提取各自的帧构造点
- 逐字节对比

本项目的结论：

| 客户端 | magic | cmd | param | trailer | 端点 |
|---|---|---|---|---|---|
| 警翼 JYManager | `0x67023A45` | `0x123` | `0x20` | `0x98FDC5BA` | 0x01/0x81 |
| TCL DSJ-A6 | 同上 | 同上 | 同上 | 同上 | 同上 |
| TCL DSJ-T3 | 同上 | 同上 | 同上 | 同上 | 同上 |

**完全一致 → 判定为芯片厂商的参考协议，而非某家私有的。**

## 7. 32 位 DLL 必须用 32 位宿主

`.NET`/PowerShell 默认 64 位，加载 32 位 `libusb0.dll` 会失败。
必须用：

```
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
```

并且注意 **`LoadLibraryW` 的 `DllImport` 必须显式指定 `CharSet = CharSet.Unicode`**，
否则路径按 ANSI 传递，报 `err=126`（模块找不到）—— 这个坑我踩过一次。

## 8. 结构体布局验证

不要假设偏移正确。验证方法：读出来的 `idVendor` 必须是合理的值（`0x4255`）。
如果读到垃圾 → 偏移错了。本项目用 `bus+0x208`（devices）、`device+0x214`（idVendor）验证通过。

## 9. PDF 手册：扫描版处理

厂商手册常是扫描版（无文字层）。检测方法：

```python
# 无 ToUnicode / 无 FontFile / 只有 /Image 流  → 扫描版
```

处理：

1. `zlib.decompress` 解 FlateDecode 流
2. 按 `/Width` `/Height` `/BitsPerComponent` `/ColorSpace` 用 PIL 重建
3. `ImageOps.invert()` 反色（线条图常是白线黑底）
4. 放大 4 倍 + 增强对比度再读

## 10. 结论可信度分级

| 级别 | 判据 |
|---|---|
| **观测** | 实际测到的返回值 / 日志 / 字节 |
| **推导** | 从多个观测一致推出的结论 |
| **推断** | 无法直接验证，但符合证据的解释 |

本项目的"设备不提供主机侧数据通道"属于**观测+推导**：
写入返回 16（观测）→ 设备必须回 ACK（USB 协议规范）→ 控制器正常工作（推导）。
而"为什么"（充电模式 / 设计如此 / 固件缺陷）属于**推断**，未能区分。