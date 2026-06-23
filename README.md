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

```bash
./bxb-scan                       # on-screen report
./bxb-scan --html report.html    # also write a local HTML report
./bxb-scan --no-color            # plain text (no ANSI colors)
```

On Windows, **double-click `bxb-scan.exe`** — it runs the scan and waits for a
keypress so the window stays open. Or from PowerShell:
```powershell
.xb-scan.exe --html report.html
.xb-scan.exe --no-pause          # for scripts (don't wait for Enter)
```powershell
.\bxb-scan.exe --html report.html
```

Some Windows checks (BitLocker) report more detail when run as Administrator,
but the scanner runs fine as a normal user.

## Privacy & safety

- Read-only. It inspects settings; it never changes anything.
- Local-only. No network calls. The optional HTML report is written to a path
  you choose, on your machine.
- This version does not touch the network at all.

## License

Apache License 2.0. © 2026 ByTE X Bit Technologies LLC. The ByTE X Bit name and
logos are trademarks and are not covered by the Apache license.
