# PS4 Kernel Vulnerability Notes (Orbis OS)

## Scope and evidence standard

Orbis is a Sony-maintained operating system derived from FreeBSD, but upstream FreeBSD advisories do not prove that a vulnerability affects a specific PS4 firmware. For each claim, record the exact firmware/build, the corresponding public source or binary evidence, the test method, and the reproducible result. Until then, use **unconfirmed for Orbis**.

## CVE-2026-7270 — FreeBSD execve(2) issue

- **Upstream source:** [FreeBSD-SA-26:13.exec](https://www.mail-archive.com/announce%40freebsd.org/msg00235.html)
- **Upstream summary:** an argument-buffer size calculation in execve(2) can lead to an out-of-bounds memory operation in affected supported FreeBSD releases.
- **Orbis status:** **not established**. The upstream advisory does not demonstrate that the affected implementation exists in the FreeBSD-derived code used by PS4 firmware.
- **What would establish impact:** compare the relevant function and patch against a legally obtained, exact Orbis firmware build. Do not infer impact solely from the shared FreeBSD ancestry.

## CVE-2026-49415 — FreeBSD execve(2) TOCTOU issue

- **Upstream source:** [FreeBSD-SA-26:39.execve](https://lists.freebsd.org/archives/freebsd-security/2026-June/000522.html)
- **Upstream summary:** a race during SUID program execution can permit a process to modify the new address space before credentials are elevated.
- **Orbis status:** **unconfirmed**. The advisory lists affected supported FreeBSD release branches; it does not say that FreeBSD 9 or Orbis is affected.
- **Important correction:** do not describe this as affecting “all FreeBSD versions.” Confirm the exact affected-version scope from the advisory.

## UFS/FFS size arithmetic — possible relation to Orbis

- **Public upstream reference:** [freebsd-src commit 442f060](https://github.com/freebsd/freebsd-src/commit/442f0608ec7e4b8ccb13f3101f294acbf0fce446)
- **Upstream finding:** the commit changes size calculations in UFS/FFS mount code to address integer-overflow risk.
- **Orbis status:** **unconfirmed** until the relevant code is compared with the exact Sony kernel build and validated. An upstream fix alone does not establish that PS4 firmware contains the same vulnerable code or that it is reachable.
- **Current limitation:** this repository does not provide sufficient independently reproducible evidence to claim that the issue is confirmed on PS4 13.04 or that a working kernel exploit exists.

## MP4 parser crash report

- **Project report:** a malformed MP4 reportedly causes Media Player or SHAREfactory to crash on firmware 11.00.
- **Orbis status:** **unverified report**. A crash alone does not establish the root cause, a heap overflow, controllable memory corruption, or impact on later firmware.
- **Evidence needed:** a minimal reproducible test file with a documented hash, exact application and firmware versions, repeatable results, and a defensively collected crash report. Until those are available, affected versions and exploitability remain unknown.

## Reporting format

For every new finding, include:

1. Exact console firmware and application version.
2. Public source links and exact source revision or binary hash.
3. Reproduction steps limited to an authorized test environment.
4. Observed result, expected result, and logs.
5. Confidence label: confirmed upstream, observed on Orbis, hypothesis, or not reproduced.

Do not label a vulnerability “confirmed on PS4” based only on an upstream FreeBSD patch or an unverified community claim.
