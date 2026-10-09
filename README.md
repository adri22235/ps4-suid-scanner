# PS4 Security Research — Firmware 13.04

Public research notes, firmware-specific data, and a BD-J SUID/SGID scanner. Treat firmware offsets and vulnerability claims as **research leads**, not verified facts, unless a primary source and reproducible test are linked.

## Contents

- 1304.c / 1304.h — Project-provided offset table for FW 13.04
- 1352_offsets.txt — Partial project-provided offset table for FW 13.52
- src/org/bdj/SuidScanner.java — SUID/SGID scanner via the BD-J API
- scanner_1304.iso — Pre-built image; verify its provenance and hash before use
- cve_analysis.md — Evidence status and limitations for vulnerability research

## Evidence status

A vulnerability in upstream FreeBSD does **not** by itself establish that the same code or bug exists in Sony's modified Orbis kernel. Firmware-specific conclusions require comparison against the relevant Sony kernel build or reproducible tests on an authorized test device.

- **CVE-2026-7270 (execve)**: FreeBSD published an advisory for affected supported FreeBSD releases. That advisory does not establish impact on Orbis/FreeBSD 9; see [FreeBSD-SA-26:13.exec](https://www.mail-archive.com/announce%40freebsd.org/msg00235.html).
- **CVE-2026-49415 (execve TOCTOU)**: FreeBSD published an advisory for specific supported release branches. Do not describe it as affecting every FreeBSD version or PS4 without evidence; see [FreeBSD-SA-26:39.execve](https://lists.freebsd.org/archives/freebsd-security/2026-June/000522.html).
- **UFS/FFS size arithmetic**: an upstream FreeBSD fix is available at [freebsd-src commit 442f060](https://github.com/freebsd/freebsd-src/commit/442f0608ec7e4b8ccb13f3101f294acbf0fce446). Whether the vulnerable code exists in a particular Orbis firmware must be checked independently.
- **MP4 parser report**: crashes reported in this project are not proof of a remotely exploitable memory corruption bug or of impact on other firmware versions. Keep affected versions marked unknown until supported by reproducible evidence.

## SUID Scanner

The scanner attempts to enumerate filesystem entries and report files whose mode includes SUID or SGID bits. It uses native functions exposed by the BD-J API and can write a text report to a mounted USB device.

### Usage

1. Verify the image's origin and integrity before using it.
2. Use only on a console and media you own or are authorized to test.
3. Insert a writable USB device and the test BD-R.
4. Review the on-screen output and, if available, /mnt/usb0/suid_scan.txt.

**Limitations:** directory visibility depends on the BD-J environment and permissions. The scanner's stat field offsets are ABI-specific and must be verified against the exact target firmware; results are not a complete inventory unless coverage is demonstrated. A failed scan or empty result does not prove that no SUID/SGID files exist.

## Firmware offset tables

The offset files in this repository are research data, not an authoritative compatibility guarantee. Verify every value against a public source or the exact firmware image before using it. Do not infer that an offset remains valid across firmware versions simply because some addresses appear unchanged.

## References

- [BD-JB-1250](https://github.com/ps3120/BD-JB-1250)
- [Scene-Collective/ps4-hen](https://github.com/Scene-Collective/ps4-hen)
- [PPPwn](https://github.com/TheOfficialFloW/PPPwn)
- [FreeBSD-SA-26:13.exec](https://www.mail-archive.com/announce%40freebsd.org/msg00235.html)
- [FreeBSD-SA-26:39.execve](https://lists.freebsd.org/archives/freebsd-security/2026-June/000522.html)
- [FreeBSD UFS/FFS fix, commit 442f060](https://github.com/freebsd/freebsd-src/commit/442f0608ec7e4b8ccb13f3101f294acbf0fce446)

## License

See the repository's license file, if present. This project is intended for educational and authorized security research.
