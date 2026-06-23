# ByTE X Bit Posture Scanner

A downloadable, local-only security posture scanner. **Everything runs on your
machine and results are shown to you only — nothing is ever transmitted** to
ByTE X Bit or anyone else. No account, no cloud, no phone-home.

This is **N0**: the host-only check. It inspects the computer it runs on. Local
network scanning is a separate, opt-in step added in a later version.

## What it checks (this version)

- System identity (OS, version, kernel)
- Host firewall (Windows Firewall / ufw / firewalld)
- Disk encryption (BitLocker / LUKS)
- Endpoint protection (Microsoft Defender)
- Updates: automatic-update status and pending updates
- Administrative account count
- Legacy/risky settings (e.g. SMBv1 on Windows, SSH root login on Linux)
- Installed software inventory (count)
- **Passive local-network discovery** (opt-in `--network`): lists devices via the
  ARP cache and SSDP/UPnP service discovery. No port scanning, local subnet only.

Every WARN/FAIL comes with a plain-language **why it matters** and a concrete **fix**.

## Build

Requires Go 1.22+. No third-party dependencies.

```bash
./build.sh        # produces dist/bxb-scan (Linux) and dist/bxb-scan.exe (Windows)
```

Or build a single target directly:

```bash
go build -o bxb-scan .                                  # current platform
GOOS=windows GOARCH=amd64 go build -o bxb-scan.exe .    # Windows from any OS
```

## Run

Just run it. With no arguments it shows a short menu:

```
  What would you like to scan?
    1) This computer only            (host posture)
    2) This computer + local network (adds passive device discovery)
    q) Quit
```

Pick 1 or 2, then choose whether to save an HTML report you can keep.

Flags skip the menu (useful for scripts):

```bash
./bxb-scan --host-only           # host posture only
./bxb-scan --network             # host + passive local-network discovery
./bxb-scan --html report.html    # host scan, write an HTML report
./bxb-scan --no-color            # plain text (no ANSI colors)
./bxb-scan --no-pause            # don't wait for Enter (implies --host-only)
```

On Windows, **double-click the `.exe`** — it shows the menu and stays open until
you press Enter. On Linux/macOS, run it from a terminal.

Some Windows checks (BitLocker) report more detail when run as Administrator,
but the scanner runs fine as a normal user.

## Privacy & safety

- Read-only. It inspects settings; it never changes anything.
- Local-only. No network calls. The optional HTML report is written to a path
  you choose, on your machine.
- By default it does not touch the network. With `--network` it reads the ARP
  cache (passive) and sends standard SSDP service-discovery multicast — it never
  scans ports, and it stays on the local subnet.

## License

Apache License 2.0. © 2026 ByTE X Bit Technologies LLC. The ByTE X Bit name and
logos are trademarks and are not covered by the Apache license.
