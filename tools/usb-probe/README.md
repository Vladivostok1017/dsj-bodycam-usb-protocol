# usb-probe

通过 **libusb-win32**（`libusb0.dll`）对嵌入式 USB 设备做只读探测。

## 为什么需要专门的工具

- `libusb0.dll` 是 **32 位**的，必须跑在 32 位宿主进程里
- 厂商程序普遍**按序号导入** libusb0（无函数名），调试时需要自己解析导出表
- 很多设备的协议走 **vendor control transfer** 而不是 bulk，通用工具看不到

## 前置条件

1. 设备已用 [Zadig](https://zadig.akeo.ie/) 绑定 **libusb-win32** 驱动
2. 32 位 PowerShell（`%WINDIR%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`）

## 用法

```powershell
# 自动以 32 位重新启动
powershell -ExecutionPolicy Bypass -File .\run.ps1 0x4255 0x0001
```

或手动：

```powershell
Add-Type -Path .\UsbProbe.cs
[UsbProbe]::Enumerate("C:\Windows\SysWOW64\libusb0.dll")
[UsbProbe]::Probe(0x4255, 0x0001, "C:\Windows\SysWOW64\libusb0.dll")
```

## 输出内容

1. **枚举** — 所有 libusb 设备的 VID/PID
2. **字符串描述符** — `iManufacturer` / `iProduct` / `iSerialNumber`
3. **配置描述符** — 接口类、端点类型与包长
4. **初始化结果** — `set_configuration` / `claim_interface` / `clear_halt` 返回值
5. **端点状态** — `GET_STATUS`，判断是否 HALT
6. **读写测试** — 16 字节 bulk 写 + 读，判断设备是否回数据
7. **厂商控制请求扫描** — `bRequest 0..10`，判断有无厂商控制面

## 关键实现细节

### 结构体偏移（libusb-win32, 32 位）

```c
bus->devices            // +0x208
device->descriptor.idVendor   // +0x214
device->descriptor.idProduct  // +0x216
```

### 必须指定 Unicode

```csharp
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern IntPtr LoadLibraryW(string path);
```

**不加 `CharSet.Unicode` 会按 ANSI 传递路径，报 `err=126`（模块找不到）。** 这个坑非常隐蔽。

### 返回值语义

| 返回值 | 含义 |
|---|---|
| `> 0` | 实际传输字节数 |
| `-116` | 超时（`ETIMEDOUT`）—— 设备未响应 |
| `-32` | STALL —— 设备不支持该请求 |
| `0` | 零长度传输 |

## 注意

本工具**只做读取和最小写入**（16 字节零填充探测）。不要用它向未知设备写入非零数据 ——
厂商端点的某些命令可能改变设备状态。