# oops!

`oops!` is a tiny read-only exit-IP status light. It shows one word near the bottom-right of the desktop:

- `safe`: the current public exit IP matches the configured target.
- `check`: the exit IP is different or could not be checked.

It was built as a lightweight personal status light. The macOS version checks only one thing: the public IPv4 returned by a simple HTTPS endpoint.

## Versions

- `VIRCSExitGuardApp/`: macOS source.
- `windows/oops-win/`: Windows source.

Both versions are read-only by design. They do not change network adapters, system proxy settings, firewall rules, DNS settings, routes, login items, launch agents, or VPN/TUN state.

## Build

### macOS

```bash
swiftc -Osize -framework Cocoa -framework Network \
  VIRCSExitGuardApp/Sources/main.swift \
  -o /tmp/oops
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
export OOPS_CHECK_URL="https://api.ipify.org"
export OOPS_CHECK_INTERVAL_SECONDS="1800"
```

See `launchagents/com.example.oops.plist` for a launchd example.

## Permission Model

`oops!` is intended to run as a normal user process.

The macOS version reads:

- public IP from HTTPS check endpoints

It must not write:

- network adapter state
- login items or launch agents
- firewall rules
- routing table
- DNS settings
- system proxy settings
- VPN/TUN configuration

## Notes

This is a local utility, not a VPN client, proxy client, or kill switch. Review the source and set your own target IP before using it.

## License

MIT
