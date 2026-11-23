# pe-analysis

逆向 Windows 客户端时用的 Python 小工具集。每个脚本可独立运行。

## 安装依赖

```bash
pip install pefile capstone Pillow
```

## 脚本

### `pe_thunks.py` — 定位真实调用点

```bash
python pe_thunks.py JYManager.exe --dll libusb0.dll
```

**解决的问题**：很多程序按**序号**导入 DLL（`ord#21` 而非函数名），且编译器生成跳转桩：

```asm
FF 25 <IAT>     ; jmp dword ptr [IAT]   ← 桩
E8 <rel32>      ; call <桩>              ← 真实调用
```

直接搜 `FF 15 <IAT>`（`call [IAT]`）**会一无所获**。本脚本先解析导出表把序号映射回函数名，
再通过桩地址反查真实调用点。

**本项目输出**：

```
usb_open          1 处   0x418092
usb_bulk_write    1 处   0x417C6D
usb_bulk_read     1 处   0x417B71
```

调用点唯一 = 通信逻辑集中 = 容易完整读完。

### `dump_strings.py` — 字符串双路提取 + 资源字符串表

```bash
python dump_strings.py target.exe                    # ASCII + UTF-16 全提
python dump_strings.py target.exe --strings-only      # 只输出 RT_STRING 表
python dump_strings.py target.exe --grep 密码
```

**关键**：MFC 程序的中文界面字符串在 `RT_STRING` 资源表里，代码用 `LoadStringW(id, ...)`，
所以你**搜不到字符串地址引用**。必须先建 `ID ↔ 文本` 映射：

```
ID=113  请重新连接!!!
ID=102  连接错误，请检查后再试！
ID=139  已经设置移动磁盘模式!
```

然后搜 `push <id>` 就能定位使用点。

### `scan_magic.py` — 扫描魔法常量

```bash
python scan_magic.py target.exe 0x67023A45 0x98FDC5BA
```

**本项目最有效的一招**：拿到一个已知 magic 后全文件搜索 + 批量反汇编上下文，
一次性枚举出所有命令构造点。

```asm
00401A07  mov dword ptr [esp + 0x2c], 0x67023a45   <<<< MAGIC
00401A0F  mov dword ptr [esp + 0x30], 0x123
00401A17  mov dword ptr [esp + 0x34], edx
00401A1B  mov dword ptr [esp + 0x38], ebp
```

### `extract_inno.py` — Inno Setup 安装包分析

```bash
python extract_inno.py setup.exe
python extract_inno.py setup.exe --extract --outdir out
```

**问题**：Inno Setup 把载荷 LZMA 压缩后追加在 PE 末尾，**直接搜字符串什么都搜不到**。

```bash
# 下载便携版（无需安装）
# https://github.com/dscharrer/innoextract/releases
```

## 典型工作流

```
1. extract_inno.py    解包安装器
2. dump_strings.py    提出全部界面字符串，找错误提示定位突破口
3. pe_thunks.py       定位网络/USB/文件 API 的真实调用点
4. scan_magic.py      用已知 magic 枚举全部协议帧构造点
5. 交叉验证多个厂商客户端 → 判定哪些是芯片厂商的通用协议
```