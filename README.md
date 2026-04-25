# oops!

`oops!` is a tiny macOS floating network guard. It shows one word near the bottom-right of the desktop:

- `safe`: the current checks match the expected network profile.
- `check`: a soft issue or incomplete baseline needs attention.
- `warning`: a hard failure was detected.

It was built as a lightweight personal status light for a proxy/TUN setup. The app can monitor a local proxy port, a TUN interface, macOS proxy settings, and the public exit IP. A heavier PixelScan browser check is split into a short-lived helper so WebKit is not loaded by the always-on process.

## Build

```bash
swiftc -Osize -framework Cocoa -framework Network \
  VIRCSExitGuardApp/Sources/main.swift \
  -o /tmp/oops

swiftc -Osize -framework Cocoa -framework WebKit \
  VIRCSExitGuardApp/Sources/pixelscan_helper.swift \
  -o /tmp/oops-pixelscan-helper
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

## Notes

This is a local utility, not a general-purpose VPN client. Review the source and set your own target IP before using the network cut behavior.

## License

MIT
