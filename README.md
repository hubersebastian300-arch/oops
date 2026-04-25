# oops!

`oops!` is a tiny read-only network status light. It shows one word near the bottom-right of the desktop:

- `safe`: the current checks match the expected network profile.
- `check`: a soft issue or incomplete baseline needs attention.
- `warning`: a hard failure was detected.

It was built as a lightweight personal status light for a proxy/TUN setup. The app can monitor a local proxy port, a TUN interface, OS proxy settings, and the public exit IP. A heavier PixelScan browser check is split into a short-lived helper so WebKit is not loaded by the always-on macOS process.

## Versions

- `VIRCSExitGuardApp/`: macOS source.
- `windows/oops-win/`: Windows source.

Both versions are read-only by design. They do not change network adapters, system proxy settings, firewall rules, DNS settings, routes, or VPN/TUN state.

## Build

### macOS

```bash
swiftc -Osize -framework Cocoa -framework Network \
  VIRCSExitGuardApp/Sources/main.swift \
  -o /tmp/oops

swiftc -Osize -framework Cocoa -framework WebKit \
  VIRCSExitGuardApp/Sources/pixelscan_helper.swift \
  -o /tmp/oops-pixelscan-helper
```

### Windows

The Windows source is included for Windows builds only. This repository does not include Windows binaries.

```powershell
cd windows/oops-win
dotnet publish -c Release -r win-x64 --self-contained false
```

## Configuration

The source uses environment variables so personal network details do not need to be committed:

```bash
export OOPS_TARGET_IP="203.0.113.10"
export OOPS_PROXY_ENDPOINT="127.0.0.1:7897"
export OOPS_PROXY_URL="http://127.0.0.1:7897"
export OOPS_TUN_DEVICE="utun1024"
export OOPS_TUN_IPV4="28.0.0.1"
export OOPS_RISK_CIDR="203.0.113.0/24"
export OOPS_ASN="0"
export OOPS_TIME_ZONE="America/Los_Angeles"
```

See `launchagents/com.example.oops.plist` for a launchd example.

## Permission Model

`oops!` is intended to run as a normal user process.

It may read:

- local proxy port reachability
- local proxy/TUN process presence
- OS proxy configuration
- public IP from HTTPS check endpoints

It must not write:

- network adapter state
- firewall rules
- routing table
- DNS settings
- system proxy settings
- VPN/TUN configuration

## Notes

This is a local utility, not a general-purpose VPN client or kill switch. Review the source and set your own target IP before using it.

## License

MIT
