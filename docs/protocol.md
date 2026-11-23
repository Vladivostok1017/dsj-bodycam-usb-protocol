# 协议规格

> 逆向自三个厂商客户端，三者**逐字节一致**，因此判定为 Ambarella 方案的通用私有协议。

## 1. 传输层

| 方向 | 端点 | 类型 | 包长 | 说明 |
|---|---|---|---|---|
| 命令下发 | `0x01` | Bulk OUT | 512 B | 定长 16 字节帧 |
| 响应返回 | `0x81` | Bulk IN | 512 B | 长度由设备决定 |
| 备用/中断通道 | `0x02` | Interrupt OUT | 64 B | 已测，同样无响应 |
| 备用/中断通道 | `0x82` | Interrupt IN | 64 B | 已测，同样无响应 |

超时：**3000 ms**（三个客户端一致）

## 2. 初始化序列

必须严格按此顺序，顺序错则设备无响应：

```c
usb_set_configuration(handle, 1);
usb_claim_interface(handle, 0);
usb_clear_halt(handle, 0x01);
usb_clear_halt(handle, 0x81);
/* 可选：clear_halt(0x02), clear_halt(0x82) —— 实测无差别 */
```

## 3. 帧格式

固定 **16 字节**，小端序：

```
偏移  0        4        8        12       16
      ┌────────┬────────┬────────┬────────┐
      │ magic  │  cmd   │ param  │trailer │
      └────────┴────────┴────────┴────────┘
字节   45 3A 02 67  23 01 00 00  20 00 00 00  BA C5 FD 98
```

| 字段 | 常量 | 说明 |
|---|---|---|
| `magic` | `0x67023A45` | 帧头标识，三个客户端完全一致 |
| `cmd` | `0x00000123` / `0x00000ABC` | 命令字，见下 |
| `param` | `0x00000020` | 参数，取自客户端全局变量初值 |
| `trailer` | `0x98FDC5BA` | 固定帧尾。**注意：不是校验和** —— 两条不同 cmd 的帧尾完全相同，说明它是常量而非计算值 |

### 已识别的命令

| cmd | 用途 | param 来源 |
|---|---|---|
| `0x123` | 连接 / 建立会话 | 客户端全局，初值 `0x20` |
| `0xABC` | 后续交互（用途未完全确认） | 客户端全局，初值 `0x20` |

> 客户端在发送 `0x123` 后，会检查响应中的某个 dword 是否等于 `0xABC` 作为成功判据。

## 4. 参考实现（Python / pyusb）

```python
import usb.core, struct

MAGIC   = 0x67023A45
TRAILER = 0x98FDC5BA

def frame(cmd, param=0x20):
    return struct.pack("<IIII", MAGIC, cmd, param, TRAILER)

dev = usb.core.find(idVendor=0x4255, idProduct=0x0001)
dev.set_configuration()
usb.util.claim_interface(dev, 0)
dev.clear_halt(0x01)
dev.clear_halt(0x81)

dev.write(0x01, frame(0x123), timeout=3000)
try:
    resp = dev.read(0x81, 512, timeout=3000)
    print("响应:", resp.hex())
except usb.core.USBTimeoutError:
    print("设备无响应")     # ← 本项目的目标设备停在这里
```

## 5. 原始出处（逆向位置）

| 客户端 | 版本 | 位置 |
|---|---|---|
| 警翼 JYManager | 3.4.0.1 | `.data` 命令模板 `0x5C708C`(cmd 0x123) / `0x5C707C`(cmd 0xABC)，发送函数 `0x417C00`，接收 `0x417B00` |
| TCL DSJ-A6 | V1.0.0.1 | 命令构造 `0x401E37`，发送 `0x401D00`，接收 `0x401D50` |
| TCL DSJ-T3 | V1.0.0.1 | 命令构造 `0x401A07`(cmd 0x123) / `0x401B35`(cmd 0xABC)，发送 `0x4018D0` |

三者帧内容、端点、超时完全一致。

## 6. 未解部分

- `param` 的实际语义（固定 `0x20` 还是运行时会变）
- `0xABC` 之后完整的命令集
- 文件列表 / 文件读取 / 分片传输的命令序列