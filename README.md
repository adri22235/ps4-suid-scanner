# PS4 SUID Scanner for Firmware 13.04

Scans the PS4 filesystem for SUID/SGID binaries via BD-JB userland exploit.
Useful for kernel exploit research (CVE-2026-49415 TOCTOU investigation).

## Based on
- [BD-JB-1250](https://github.com/ps3120/BD-JB-1250) by ps3120/Gezine
- bdj1304.iso entry point for PS4 FW 13.04

## How it works
Uses native FreeBSD syscalls (open, getdents, stat) via BD-JB's Java API
to enumerate files with SUID/SGID bits set. Results displayed on screen
and saved to USB at `/mnt/usb0/suid_scan.txt`.

## Usage
1. Burn `scanner_1304.iso` to BD-R at 4x speed
2. Insert USB drive (FAT32/exFAT) in PS4
3. Insert BD-R disc
4. Results appear on screen and saved to USB

## Build
Requires modified BD-JB-1250 with SuidScanner.java integrated into InitXlet.

## CVE Research
This tool supports investigation of CVE-2026-49415 (execve TOCTOU race)
which affects all FreeBSD versions including the PS4's Orbis OS (FreeBSD 9).

## Credits
- ps3120 — BD-JB-1250 and bdj1304.iso
- Gezine — BD-JB vulnerability discovery
- Scene-Collective — ps4-hen open source offsets
- Pharaoh2k — 13.04 kernel offsets verification
