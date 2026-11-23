# 执法记录仪 USB 私有协议逆向

TCL DSJ-TCLT3A1 单警执法视音频记录仪的 USB 通信协议逆向记录。

设备主控为 Ambarella 芯片，USB 标识 `VID:PID 4255:0001`，设备类名 `Amba Simple Class`。

## 现状

- 通信协议已逆向完成，规格见 [`docs/protocol.md`](docs/protocol.md)
- 目标设备可以枚举、可以接收主机数据，但不向主机返回任何数据
- 录像未能从该设备导出
- 已排查的方向和结果记录在 [`findings/test-matrix.md`](findings/test-matrix.md)

## 协议摘要

```
帧格式（16 字节定长，小端）
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ 45 3A 02 67  │ 23 01 00 00  │ 20 00 00 00  │ BA C5 FD 98  │
│ magic        │ cmd          │ param        │ trailer      │
│ 0x67023A45   │ 0x123 / 0xABC│ 0x20         │ 0x98FDC5BA   │
└──────────────┴──────────────┴──────────────┴──────────────┘

传输
  写  EP 0x01  Bulk OUT  512B
  读  EP 0x81  Bulk IN   512B
  超时 3000 ms

初始化
  1. usb_set_configuration(h, 1)
  2. usb_claim_interface(h, 0)
  3. usb_clear_halt(h, 0x01)
  4. usb_clear_halt(h, 0x81)
  5. usb_bulk_write(h, 0x01, frame, 16, 3000)
  6. usb_bulk_read (h, 0x81, buf, N, 3000)
```

该帧格式在警翼 JYManager 3.4.0.1、TCL DSJ-A6、TCL DSJ-T3 三个客户端中逐字节一致。

## 设备信息

```
VID:PID         4255:0001
iManufacturer   AMBA
iProduct        Amba Simple Class
接口            1 个，Class FF/FF/00
端点            0x01 Bulk OUT 512 / 0x81 Bulk IN 512
                0x02 Int  OUT  64 / 0x82 Int  IN  64
```

`0x4255` 为 Ambarella 的 USB Vendor ID。警翼与 TCL 的驱动 INF 均绑定 `USB\VID_4255&PID_0001`。

## 仓库内容

| 路径 | 内容 |
|---|---|
| `docs/protocol.md` | 帧格式、命令字、传输层参数、初始化序列、pyusb 参考实现 |
| `docs/device-fingerprint.md` | VID/PID、描述符、端点表、libusb-win32 结构体偏移 |
| `docs/vendor-gate.md` | JYManager 的厂商字符串校验逻辑与绕过方法 |
| `docs/negative-results.md` | 已验证失败的方案及实测数据 |
| `docs/methodology.md` | 逆向过程使用的方法与工具链 |
| `findings/test-matrix.md` | 18 项测试及结果 |
| `patches/jymanager-vendor-gate.md` | 2 字节补丁说明与应用脚本 |
| `tools/usb-probe/` | libusb-win32 设备探测工具（C#） |
| `tools/pe-analysis/` | PE 分析与安装包解包脚本（Python） |

## 使用

### tools/usb-probe

通过 libusb-win32 对设备做枚举、读描述符、端点状态检查、读写测试、厂商控制请求扫描。

```powershell
# 需先以 Zadig 为设备绑定 libusb-win32 驱动
powershell -ExecutionPolicy Bypass -File .\run.ps1 0x4255 0x0001
```

`run.ps1` 会自动以 32 位 PowerShell 启动（`libusb0.dll` 为 32 位）。

### tools/pe-analysis

```bash
pip install pefile capstone Pillow

# 定位按序号导入的 DLL 的真实调用点
python pe_thunks.py target.exe --dll libusb0.dll

# 提取字符串与 RT_STRING 资源表
python dump_strings.py target.exe --strings-only

# 扫描固定常量并反汇编上下文
python scan_magic.py target.exe 0x67023A45 0x98FDC5BA

# Inno Setup 安装包分析（解包需 innoextract）
python extract_inno.py setup.exe --extract --outdir out
```

## 未确认项

1. 设备不启动数据协议的原因。已排除驱动、软件、密码三方面，未区分以下可能：
   - 该 USB 口仅用于充电与识别，数据经底部 21 触点底座传输
   - 设备处于"充电优先"状态
   - 固件缺陷
2. 底部 21 触点的引脚定义
3. 存储介质为可插拔 TF 卡还是板载 eMMC（电商标注 TF 卡，官方手册无卡槽图示）
4. 完整命令集。目前确认 `0x123`（连接）与 `0xABC`，文件读写相关命令未知

## 外部参考

- [evilwombat/gopro-usb-tools](https://github.com/evilwombat/gopro-usb-tools) — Ambarella 启动模式（USB command mode）协议实现，本项目的控制传输验证基于此
- [innoextract](https://github.com/dscharrer/innoextract) — Inno Setup 安装包解包工具
- [Zadig](https://zadig.akeo.ie/) — Windows USB 驱动绑定工具

## License

MIT