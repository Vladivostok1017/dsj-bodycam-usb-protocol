// UsbProbe.cs — libusb-win32 (libusb0.dll) 32-bit 探测工具
//
// 用途：逆向 / 调试使用 libusb-win32 的嵌入式 USB 设备。
// 必须运行在 32 位 PowerShell 中（C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe），
// 因为 libusb0.dll 是 32 位的。
//
// 用法（PowerShell）：
//   Add-Type -Path UsbProbe.cs
//   [UsbProbe]::Enumerate("C:\Windows\SysWOW64\libusb0.dll")
//   [UsbProbe]::Probe(0x4255, 0x0001, "C:\Windows\SysWOW64\libusb0.dll")

using System;
using System.Runtime.InteropServices;
using System.Text;

public class UsbProbe
{
    // ── P/Invoke ────────────────────────────────────────────────────────────
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr LoadLibraryW(string path);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")]
    static extern bool FreeLibrary(IntPtr h);

    delegate void t_void();
    delegate int  t_int();
    delegate IntPtr t_ptr();
    delegate IntPtr t_open(IntPtr dev);
    delegate int t_claim(IntPtr h, int iface);
    delegate int t_cfg(IntPtr h, int cfg);
    delegate int t_halt(IntPtr h, int ep);
    delegate int t_bulk(IntPtr h, int ep, byte[] buf, int len, int timeout);
    delegate int t_str(IntPtr h, int idx, byte[] buf, int len);
    delegate int t_ctl(IntPtr h, byte attr, byte req, int val, int idx, byte[] buf, int len);
    delegate int t_close(IntPtr h);

    static Delegate Bind(IntPtr mod, string name, Type t)
    {
        IntPtr p = GetProcAddress(mod, name);
        if (p == IntPtr.Zero) return null;
        return Marshal.GetDelegateForFunctionPointer(p, t);
    }

    // libusb-win32 结构体偏移（32 位）
    const int OFF_BUS_DEVICES = 0x208;  // bus->devices
    const int OFF_DEV_VID     = 0x214;  // device->descriptor.idVendor
    const int OFF_DEV_PID     = 0x216;  // device->descriptor.idProduct

    static IntPtr FindDevice(IntPtr busList, int vid, int pid)
    {
        IntPtr bus = busList;
        while (bus != IntPtr.Zero)
        {
            IntPtr dev = Marshal.ReadIntPtr(bus, OFF_BUS_DEVICES);
            while (dev != IntPtr.Zero)
            {
                int v = Marshal.ReadInt16(dev, OFF_DEV_VID) & 0xFFFF;
                int p = Marshal.ReadInt16(dev, OFF_DEV_PID) & 0xFFFF;
                if (v == vid && (pid < 0 || p == pid)) return dev;
                dev = Marshal.ReadIntPtr(dev, 0);
            }
            bus = Marshal.ReadIntPtr(bus, 0);
        }
        return IntPtr.Zero;
    }

    // ── 枚举 ────────────────────────────────────────────────────────────────
    public static string Enumerate(string dllPath)
    {
        StringBuilder sb = new StringBuilder();
        IntPtr mod = LoadLibraryW(dllPath);
        if (mod == IntPtr.Zero) return "LoadLibrary 失败 err=" + Marshal.GetLastWin32Error();

        try
        {
            var init = (t_void)Bind(mod, "usb_init", typeof(t_void));
            var fb   = (t_int) Bind(mod, "usb_find_busses", typeof(t_int));
            var fd   = (t_int) Bind(mod, "usb_find_devices", typeof(t_int));
            var gb   = (t_ptr) Bind(mod, "usb_get_busses", typeof(t_ptr));
            if (init == null || fb == null || fd == null || gb == null) return "缺少导出";

            init();
            sb.AppendLine("find_busses  = " + fb());
            sb.AppendLine("find_devices = " + fd());

            IntPtr bus = gb();
            while (bus != IntPtr.Zero)
            {
                IntPtr dev = Marshal.ReadIntPtr(bus, OFF_BUS_DEVICES);
                while (dev != IntPtr.Zero)
                {
                    int v = Marshal.ReadInt16(dev, OFF_DEV_VID) & 0xFFFF;
                    int p = Marshal.ReadInt16(dev, OFF_DEV_PID) & 0xFFFF;
                    sb.AppendLine(string.Format("  VID=0x{0:X4} PID=0x{1:X4}", v, p));
                    dev = Marshal.ReadIntPtr(dev, 0);
                }
                bus = Marshal.ReadIntPtr(bus, 0);
            }
        }
        catch (Exception e) { sb.AppendLine("EXC " + e.Message); }
        finally { FreeLibrary(mod); }

        return sb.ToString();
    }

    // ── 完整探测 ────────────────────────────────────────────────────────────
    public static string Probe(int vid, int pid, string dllPath)
    {
        StringBuilder sb = new StringBuilder();
        IntPtr mod = LoadLibraryW(dllPath);
        if (mod == IntPtr.Zero) return "LoadLibrary 失败 err=" + Marshal.GetLastWin32Error();

        try
        {
            var init  = (t_void) Bind(mod, "usb_init", typeof(t_void));
            var fb    = (t_int)  Bind(mod, "usb_find_busses", typeof(t_int));
            var fd    = (t_int)  Bind(mod, "usb_find_devices", typeof(t_int));
            var gb    = (t_ptr)  Bind(mod, "usb_get_busses", typeof(t_ptr));
            var open  = (t_open) Bind(mod, "usb_open", typeof(t_open));
            var claim = (t_claim)Bind(mod, "usb_claim_interface", typeof(t_claim));
            var cfg   = (t_cfg)  Bind(mod, "usb_set_configuration", typeof(t_cfg));
            var halt  = (t_halt) Bind(mod, "usb_clear_halt", typeof(t_halt));
            var wr    = (t_bulk) Bind(mod, "usb_bulk_write", typeof(t_bulk));
            var rd    = (t_bulk) Bind(mod, "usb_bulk_read", typeof(t_bulk));
            var str   = (t_str)  Bind(mod, "usb_get_string_simple", typeof(t_str));
            var ctl   = (t_ctl)  Bind(mod, "usb_control_msg", typeof(t_ctl));
            var close = (t_close)Bind(mod, "usb_close", typeof(t_close));

            init(); fb(); fd();
            IntPtr dev = FindDevice(gb(), vid, pid);
            if (dev == IntPtr.Zero) return "未找到设备";

            IntPtr h = open(dev);
            if (h == IntPtr.Zero) return "usb_open 返回 NULL";

            sb.AppendLine("── 字符串描述符 ──");
            for (int i = 1; i <= 4; i++)
            {
                byte[] b = new byte[256];
                int n = str(h, i, b, 255);
                if (n > 0)
                    sb.AppendLine(string.Format("  string[{0}] = \"{1}\"", i,
                        Encoding.ASCII.GetString(b, 0, n).TrimEnd('\0')));
            }

            sb.AppendLine();
            sb.AppendLine("── 配置描述符 ──");
            byte[] cfgBuf = new byte[512];
            int cn = ctl(h, 0x80, 0x06, 0x0200, 0, cfgBuf, 255);
            sb.AppendLine("  get_descriptor(config) = " + cn + " bytes");
            if (cn > 0)
            {
                int p2 = 0;
                while (p2 + 2 <= cn)
                {
                    int bl = cfgBuf[p2], bt = cfgBuf[p2 + 1];
                    if (bl < 2) break;
                    if (bt == 0x04)
                        sb.AppendLine(string.Format("    IF#{0} alt={1} nEP={2} class=0x{3:X2}/0x{4:X2}/0x{5:X2}",
                            cfgBuf[p2+2], cfgBuf[p2+3], cfgBuf[p2+4], cfgBuf[p2+5], cfgBuf[p2+6], cfgBuf[p2+7]));
                    else if (bt == 0x05)
                        sb.AppendLine(string.Format("      EP 0x{0:X2} attr=0x{1:X2} maxpkt={2}",
                            cfgBuf[p2+2], cfgBuf[p2+3], BitConverter.ToUInt16(cfgBuf, p2+4)));
                    p2 += bl;
                }
            }

            sb.AppendLine();
            sb.AppendLine("── 初始化 ──");
            sb.AppendLine("  set_configuration(1) = " + cfg(h, 1));
            sb.AppendLine("  claim_interface(0)   = " + claim(h, 0));
            foreach (int ep in new int[] { 0x01, 0x81, 0x02, 0x82 })
                sb.AppendLine(string.Format("  clear_halt(0x{0:X2})    = {1}", ep, halt(h, ep)));

            sb.AppendLine();
            sb.AppendLine("── 端点状态 (GET_STATUS) ──");
            foreach (int ep in new int[] { 0x81, 0x82 })
            {
                byte[] st = new byte[2];
                int n = ctl(h, 0x82, 0x00, 0, ep, st, 2);
                sb.Append(string.Format("  EP 0x{0:X2} ret={1}", ep, n));
                if (n == 2)
                    sb.Append(string.Format("  status=0x{0:X2}{1:X2}{2}",
                        st[0], st[1], st[0] == 1 ? "  [HALT]" : "  [OK]"));
                sb.AppendLine();
            }

            sb.AppendLine();
            sb.AppendLine("── 读写测试 (16 字节) ──");
            byte[] probe = new byte[16];
            sb.AppendLine("  bulk_write(0x01) = " + wr(h, 0x01, probe, 16, 2000));
            foreach (int ep in new int[] { 0x81, 0x82 })
            {
                byte[] b = new byte[512];
                int n = rd(h, ep, b, 512, 2000);
                sb.Append(string.Format("  bulk_read (0x{0:X2}) = {1}", ep, n));
                if (n > 0) sb.Append("   " + BitConverter.ToString(b, 0, Math.Min(n, 32)));
                sb.AppendLine();
            }

            sb.AppendLine();
            sb.AppendLine("── 厂商控制请求扫描 (bRequest 0..10) ──");
            for (int rq = 0; rq <= 10; rq++)
            {
                byte[] b = new byte[64];
                int n = ctl(h, 0xC0, (byte)rq, 0, 0, b, 64);
                sb.Append(string.Format("  bRequest=0x{0:X2} -> ret={1}", rq, n));
                if (n > 0) sb.Append("  " + BitConverter.ToString(b, 0, Math.Min(n, 16)));
                sb.AppendLine();
            }

            close(h);
        }
        catch (Exception e) { sb.AppendLine("EXC " + e.GetType().Name + ": " + e.Message); }
        finally { FreeLibrary(mod); }

        return sb.ToString();
    }
}