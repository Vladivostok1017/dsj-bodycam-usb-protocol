# run.ps1 — 用 32 位 PowerShell 加载 UsbProbe.cs
# 用法: powershell -File run.ps1            (自动重新以 32 位启动)
#       powershell -File run.ps1 0x4255 0x0001

param(
    [string]$Vid = "0x4255",
    [string]$Pid = "0x0001"
)

$ErrorActionPreference = "Stop"

# 确保是 32 位进程（libusb0.dll 是 32 位的）
if ([Environment]::Is64BitProcess) {
    Write-Host "[*] 重新以 32 位 PowerShell 启动..."
    $ps32 = "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    & $ps32 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath $Vid $Pid
    exit $LASTEXITCODE
}

Add-Type -Path (Join-Path $PSScriptRoot "UsbProbe.cs")

$dll = "$env:WINDIR\SysWOW64\libusb0.dll"
if (-not (Test-Path $dll)) {
    $dll = "libusb0.dll"   # 回退到 PATH
}

Write-Host "===== 枚举 ====="
Write-Host ([UsbProbe]::Enumerate($dll))

Write-Host "===== 完整探测 ====="
Write-Host ([UsbProbe]::Probe([Convert]::ToInt32($Vid,16), [Convert]::ToInt32($Pid,16), $dll))