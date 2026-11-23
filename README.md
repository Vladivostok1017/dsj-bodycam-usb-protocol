# 执法记录仪 USB 私有协议逆向（DSJ 系列 / Ambarella 方案）

> 目标设备：**TCL DSJ-TCLT3A1** 单警执法视音频记录仪（Ambarella 方案，`VID:PID 4255:0001`）
> 状态：**协议已完整逆向；目标设备的 USB 数据通道不响应，未能导出录像**
>
> 本项目记录完整协议规格、绕过厂商闸门的方法，以及 18 项测试的全部负面结果，
> 供后续研究者直接复用，避免重复踩坑。

**关键词**：执法记录仪 · 单警执法视音频记录仪 · DSJ · body camera · body-worn camera ·
Ambarella · Amba Simple Class · USB 私有协议逆向

---

## TL;DR

| 项目 | 结果 |
|---|---|
| 厂商私有协议帧格式 | ✅ 完整逆向（16 字节定长，magic `0x67023A45` / trailer `0x98FDC5BA`） |
| 品牌通用性 | ✅ **警翼 JYManager、TCL DSJ-A6、TCL DSJ-T3 三个客户端逐字节一致** |
| 厂商字符串门禁 | ✅ 定位并绕过（`iManufacturer == "JYA"/"JYB"`，2 字节补丁） |
| 设备识别 | ✅ 枚举、描述符、端点、字符串全部拿到 |
| **导出录像** | ❌ **设备枚举正常但从不向主机回发任何数据** |
| 此前公开资料 | ❌ 全网零命中（两个 magic 常量搜索无结果） |

**失败原因不是软件、不是驱动、不是密码，而是设备固件不提供主机侧数据通道。**

---

## 协议速查

```
帧格式（16 字节定长，小端）
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ 45 3A 02 67  │ 23 01 00 00  │ 20 00 00 00  │ BA C5 FD 98  │
│ magic        │ cmd          │ param        │ trailer      │
│ 0x67023A45   │ 0x123 / 0xABC│ 0x20         │ 0x98FDC5BA   │
└──────────────┴──────────────┴──────────────┴──────────────┘

传输层
  写  EP 0x01  Bulk OUT  512B
  读  EP 0x81  Bulk IN   512B
  超时 3000 ms

初始化顺序（缺一不可）
  1. usb_set_configuration(h, 1)
  2. usb_claim_interface(h, 0)
  3. usb_clear_halt(h, 0x01)
  4. usb_clear_halt(h, 0x81)
  5. usb_bulk_write(h, 0x01, frame, 16, 3000)
  6. usb_bulk_read (h, 0x81, buf, N, 3000)
```

详见 [`docs/protocol.md`](docs/protocol.md)。

---

## 设备指纹

```
VID:PID         4255:0001          ← Ambarella 出厂默认，非"启动模式"专属
产品名          "Amba Simple Class"
iManufacturer   "AMBA"
iProduct        "Amba Simple Class"
iSerialNumber   "TCL-00123-56"
接口            1 个，Class FF/FF/00（厂商自定义）
端点            0x01 Bulk OUT 512 / 0x81 Bulk IN 512
                0x02 Int  OUT  64 / 0x82 Int  IN  64
```

厂商 INF 也印证了这一点 —— 警翼和 TCL 两家绑定的是**同一个硬件 ID**：

```ini
; 警翼 libusb0.inf
"警翼执法记录仪"=LIBUSB_DEV, USB\VID_4255&PID_0001

; TCL bulkusb.inf
DeviceName = "Ambarella Evaluation Board 1.2.3.0"
DeviceID   = "VID_4255&PID_0001"
```

详见 [`docs/device-fingerprint.md`](docs/device-fingerprint.md)。

---

## 18 项测试的最终结论

完整矩阵见 [`findings/test-matrix.md`](findings/test-matrix.md)。

**关键的三条：**

1. **设备能收不能发** —— bulk OUT 写入返回 16（设备必须回 ACK），但所有 IN 端点连续 10 秒零字节
2. **端点没有故障** —— `GET_STATUS` 返回 `0x0000`（未 HALT），硬件正常
3. **厂商自己的型号匹配客户端也连不上** —— 排除软件 / 驱动 / 协议实现问题

**推论：设备 USB 控制器活着，但应用层协议服务没有运行。**

## 常见问题：是不是密码不对？

**不是。** 依据：

- 密码 `123456`（说明书初始密码）、`000000`（初始管理员密码）、`15935728` 均试过，结果都是「重新连接」
- 「重新连接」是**通信层**错误；真正的密码错误会报「密码输入错误」
- 密码验证需要设备回话（比对设备内存储的密码），而**设备一个字节都不回**

→ 根本走不到密码判定那一步。

---

## 仓库结构

```
├── docs/
│   ├── protocol.md            协议规格（帧格式、命令、传输层、初始化）
│   ├── device-fingerprint.md  VID/PID、描述符结构、端点表、结构体偏移
│   ├── vendor-gate.md         厂商字符串门禁与绕过方法
│   ├── negative-results.md    试过但失败的方案（含 boot mode 验证）
│   └── methodology.md         从零逆出协议的方法与工具链
├── findings/
│   └── test-matrix.md         18 项测试的完整结果表
├── patches/
│   └── jymanager-vendor-gate.md   JYManager 的 2 字节补丁说明
└── tools/
    ├── usb-probe/             C# 32 位 libusb0 探测工具
    └── pe-analysis/           Python：thunk 解析、资源字符串、magic 扫描、Inno 解包
```

---

## 未解决的问题（欢迎 PR）

1. **设备为何不启动数据协议服务？** 三种可能未能区分：
   - 该 USB 口设计上只是充电 + 基础识别，数据走**底部 21 触点底座**
   - 设备处于某种「充电优先」状态
   - 固件缺陷
2. **底部 21 触点底座接口**的引脚定义未知（可能含 USB D+/D- 或 UART）
3. **存储介质形态**：电商标注 TF 卡，但官方手册 42 页图里**无任何卡槽图示**，疑似焊死 eMMC
4. **完整的命令集**：目前只确认 `0x123`（连接）和 `0xABC`，文件列表 / 读取 / 分片传输命令未知

---

## 免责声明

本项目为**学习与研究用途**，用于理解嵌入式 USB 私有协议的实现方式。
不包含也不分发任何厂商的二进制程序、固件或文档。所有分析均在自有设备上进行。

---

## License

MIT