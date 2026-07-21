# PS4 Security Research — Firmware 13.04

Research tools and kernel offsets for PS4 firmware 13.04 security research.

## Contents

- `1304.c` / `1304.h` — Complete kernel offsets for FW 13.04
- `1352_offsets.txt` — Partial kernel offsets for FW 13.52
- `src/org/bdj/SuidScanner.java` — SUID/SGID binary scanner via BD-JB
- `scanner_1304.iso` — Pre-built ISO for testing
- `cve_analysis.md` — CVE analysis for PS4 kernel

## Status (July 21, 2026)

### Entry Points Confirmed on 13.04
- ✅ **BD-JB** — Sandbox escape working (ps3120/Gezine)
- ✅ **WebKit DOM postMessage** — Vulnerability present (confirmed on hardware)
- ✅ **WebKit DOM getters** — Vulnerability present (confirmed on hardware)
- ✅ **WebKit LLInt OOB** — Vulnerability present (confirmed on hardware)
- ✅ **PlayStation Vue** — Installed, potential Celsius entry point

### Kernel Exploits
- 🔥 **Celsius (ffs_mount)** — Integer overflow in ffs_mountfs(), works up to 13.04, patched in 13.50. Discovered by bollars.
- 🔥 **CVE-2026-49415** — execve TOCTOU race condition, affects all FreeBSD versions. Under investigation.

### Latest News
- **2026-07-21**: MasterMaind confirms BD-J sandbox escape up to 13.50/13.52
- **2026-07-21**: etaHEN updated for PS5 up to 12.70
- **2026-07-18**: Celsius (ffs_mount KEX) announced by bollars
- **2026-07-18**: 13.04 kernel offsets published

## SUID Scanner

Scans the PS4 filesystem for SUID/SGID binaries via BD-JB userland exploit.
Uses native FreeBSD syscalls (open, getdents, stat) via BD-JB's Java API.
Results displayed on screen and saved to USB at `/mnt/usb0/suid_scan.txt`.

### Usage
1. Burn `scanner_1304.iso` to BD-R at 4x speed
2. Insert USB drive (FAT32/exFAT) in PS4
3. Insert BD-R disc
4. Results appear on screen and saved to USB

## Kernel Offsets

### 13.04 (Complete)
Full offsets in `1304.c` — based on 13.02 (identical kernel) verified by Pharaoh2k's offset table.

### 13.52 (Partial)
```
PRISON0    = 0x111FA18
ROOTVNODE  = 0x2136E90
SYSENT     = 0x110A760
unknown1   = 0x4D6D0
unknown2   = 0xE6C60
```

## CVE Analysis

See `cve_analysis.md` for detailed analysis of:
- **CVE-2026-7270** — execve buffer overflow (DISCARDED: function not present in FreeBSD 9)
- **CVE-2026-49415** — execve TOCTOU race (CANDIDATE: SUID code confirmed in FreeBSD 9)
- **Celsius / ffs_mount** — Integer overflow in ffs_mountfs() (CONFIRMED for 13.04)

## Celsius (ffs_mount) Technical Analysis

The vulnerability is in `ffs_mountfs()` in `sys/ufs/ffs/ffs_vfsops.c`:

```c
size = fs->fs_cssize;                          // attacker controlled
if (fs->fs_contigsumsize > 0)
    size += fs->fs_ncg * sizeof(int32_t);      // INTEGER OVERFLOW
size += fs->fs_ncg * sizeof(u_int8_t);         // INTEGER OVERFLOW
space = malloc((u_long)size, M_UFSMNT, M_WAITOK);  // small malloc

// Later:
for (i = 0; i < fs->fs_ncg; i++)               // huge loop
    *lp++ = fs->fs_contigsumsize;               // HEAP OVERFLOW
```

`fs->fs_ncg` comes from the UFS superblock (attacker controlled). A large value causes integer overflow in the size calculation, resulting in a small malloc but massive heap overflow.

**Requirements:** BD-J or Vue entry point + 250GB+ HDD with malformed UFS image.

## MP4 Parser Vulnerability (Under Investigation)

A malformed MP4 file (`mutado_race.mp4`) crashes Media Player and SHAREfactory:
- Crash confirmed on FW 11.00 (likely present on 13.04)
- Bug in `moov.udta.meta` atom parsing
- Child atom declares 190 bytes in 90-byte container → heap overflow
- Injection points at offsets 0x833 and 0x885
- Error 34878-0 on SHAREfactory, freeze on Media Player

Credit: Shunsui (discovery and analysis)

## Based on
- [BD-JB-1250](https://github.com/ps3120/BD-JB-1250) by ps3120/Gezine
- [Scene-Collective/ps4-hen](https://github.com/Scene-Collective/ps4-hen) for offset format
- [PPPwn](https://github.com/TheOfficialFloW/PPPwn) by TheFloW for exploit architecture reference

## Credits
- ps3120 — BD-JB-1250 and bdj1304.iso
- Gezine — BD-JB vulnerability discovery
- Scene-Collective — ps4-hen open source offsets
- Pharaoh2k — 13.04 kernel offsets verification
- bollars — Celsius (ffs_mount) discovery
- MasterMaind (@ASaudidos) — BD-J escape confirmation up to 13.52
- Shunsui — MP4 parser vulnerability discovery and analysis
- Victor — Celsius confirmation and technical guidance

## License
This research is for educational and security research purposes only.
