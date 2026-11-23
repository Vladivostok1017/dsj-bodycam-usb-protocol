# 设备指纹

## 目标设备

```
型号(推测)      TCL DSJ-TCLT3A1
VID:PID        4255:0001
序列号          TCL-00123-56
```

> `0x4255` 是 **Ambarella** 的 USB Vendor ID。`4255:0001` 是 Ambarella 芯片的**出厂默认值**，
> 多个品牌（GoPro、警翼、TCL）都用它，因此它**不**代表任何特殊模式。

## 字符串描述符

| 索引 | 内容 |
|---|---|
| 1 (iManufacturer) | `AMBA` |
| 2 (iProduct) | `Amba Simple Class` |
| 3 (iSerialNumber) | `TCL-00123-56` |

**注意**：`Amba Simple Class` 是 Ambarella 的**通用默认名**，不是厂商定制字符串。这本身是一个线索 —— 说明固件没有覆盖这个描述符。

## 配置描述符

```
bNumConfigurations = 1
Configuration 0:
  bNumInterfaces    = 1
  bmAttributes      = 0x80 (bus powered)
  bMaxPower         = 0xFA (500mA)

  Interface 0, alt 0:
    bInterfaceClass    = 0xFF  (Vendor Specific)
    bInterfaceSubClass = 0xFF
    bInterfaceProtocol = 0x00
    bNumEndpoints      = 4
      EP 0x01  Bulk        wMaxPacketSize 512
      EP 0x81  Bulk        wMaxPacketSize 512
      EP 0x02  Interrupt   wMaxPacketSize  64
      EP 0x82  Interrupt   wMaxPacketSize  64
```

## 兼容 ID

```
USB\COMPAT_VID_4255&Class_FF&SubClass_FF&Prot_00
USB\COMPAT_VID_4255&Class_FF&SubClass_FF
USB\COMPAT_VID_4255&Class_FF
USB\Class_FF&SubClass_FF&Prot_00
USB\Class_FF&SubClass_FF
USB\Class_FF
```

## libusb-win32 结构体偏移（逆向时用到的）

客户端按 libusb-win32 0.1.x 的头文件编译，直接读结构体字段：

```c
struct usb_bus {
    struct usb_bus *next;        // +0x000
    struct usb_bus *prev;        // +0x004
    char dirname[512];           // +0x008
    struct usb_device *devices;  // +0x208   ← 客户端用这个偏移
    unsigned long location;      // +0x20C
};

struct usb_device {
    struct usb_device *next;     // +0x000
    struct usb_device *prev;     // +0x004
    char filename[512];          // +0x008
    struct usb_bus *bus;         // +0x208
    struct usb_device_descriptor descriptor;  // +0x20C
    /* idVendor  = descriptor+8  = +0x214   ← 客户端用这个偏移 */
    /* idProduct = descriptor+10 = +0x216 */
};
```

**验证**：libusb-win32 `1.2.3.0` 与 `1.4.0.0` 的这两个 DLL 在相同偏移下都能正确读出 VID/PID，**结构体布局兼容**。

## 驱动

```
服务名      libusb0
驱动文件    libusb0.sys
接口 GUID   {2eae8778-2b7c-42f1-bb83-9aeb31d5fe25}
设备类 GUID {eb781aaf-9c70-4523-a5df-642a87eca567}  ("libusb-win32 devices")
```

装 libusb-win32 驱动后设备状态：

```
Status   = OK
Problem  = 0
Service  = libusb0
Class    = libusb-win32 devices
```

**设备驱动层完全健康** —— 这一点很重要，它把问题范围缩小到了固件。

## 厂商 INF 里的硬件 ID

警翼官方驱动包的 `libusb0.inf`：

```ini
[Devices]
"警翼执法记录仪"=LIBUSB_DEV, USB\VID_4255&PID_0001
```

TCL DSJ-A6 的 `bulkusb.inf`：

```ini
DeviceName = "Ambarella Evaluation Board 1.2.3.0"
DeviceID   = "VID_4255&PID_0001"
DeviceID2  = "VID_4255&PID_0003"
DeviceID3  = "VID_4255&PID_0005"
DeviceID4  = "VID_4255&PID_0007"
DeviceID5  = "VID_4255&PID_0008"
```

两家厂商绑定同一个硬件 ID，进一步印证协议通用。