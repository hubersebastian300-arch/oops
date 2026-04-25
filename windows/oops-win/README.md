# oops! for Windows

This is the Windows read-only version of `oops!`.

It checks:

- local proxy port reachability
- proxy process presence
- current user proxy registry values
- public exit IP

It does not change:

- network adapters
- Windows Firewall rules
- routes
- DNS settings
- system proxy settings
- VPN or TUN state

## Build

```powershell
dotnet publish -c Release -r win-x64 --self-contained false
```

## Configure

```powershell
$env:OOPS_TARGET_IP = "203.0.113.10"
$env:OOPS_PROXY_HOST = "127.0.0.1"
$env:OOPS_PROXY_PORT = "7897"
$env:OOPS_PROXY_PROCESS = "clash-verge"
```
