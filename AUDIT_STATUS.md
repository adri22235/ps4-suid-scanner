# Repository audit status

This file tracks the public, static audit of this repository. It is not a claim that the scanner or any exploit component has been built or tested on a PS4.

## File-by-file status

| Path | Status | Remaining work |
|---|---|---|
| `README.md` | Scope and evidence claims clarified | Add reproducible build/use instructions once the actual build inputs are identified |
| `cve_analysis.md` | Upstream FreeBSD claims separated from Orbis claims | No PS4-specific CVE is confirmed by the evidence currently stored here |
| `src/org/bdj/SuidScanner.java` | Directory record bounds checks; `getdirentries` fallback; UTF-8 byte-safe paths/reports; prefers `lstat`; logs read errors; writes a report even when zero hits are found | Build against the exact BD-J API version; validate `stat` layout and native symbols on each target firmware; test on authorized hardware |
| `1304.c` | Offset table only; not independently validated by this audit | Includes `sections.h` and `offsets/1304.h`, which are not present at those paths in this repository |
| `1304.h` | Header fragment | Includes `../offsets.h`, which is absent from the repository tree |
| `1400.c` | Offset table only; not independently validated by this audit | Includes `sections.h` and `offsets/1400.h`, which are not present at those paths in this repository |
| `1400.h` | Header fragment | Includes `../offsets.h`, which is absent from the repository tree |
| `1352_offsets.txt` | Partial values, source attribution is not independently reproducible here | Verify each value against an authoritative public source or exact firmware; do not infer compatibility across all 13.x releases |
| `1400_offsets.txt` | Re-labelled as unverified research notes | Verify all values and remove conclusions not supported by reproducible evidence |
| `webkit_gadgets_1304.js` | Gadget list and research comments | Record the exact source binary hash, extraction commands and per-gadget validation before calling values confirmed |
| `webkit_gadgets_1350.js` | Reference data for a different firmware; comments already identify partial matches | Do not use as a 13.04 gadget table; validate against the exact 13.50 source binary |
| `jordy_stage2.js` | Incomplete research scaffold, explicitly labelled non-working | Contains TODOs/placeholders and unresolved symbols such as `targetAddress`; not a runnable or verified chain |
| `scanner_1304.iso` | Binary image, 16 MiB in the public tree | Record SHA-256, provenance, contents and a reproducible build process; source-to-image equivalence is unverified |
| `hen.bin` | Binary payload, 500,736 bytes in the public tree | Record SHA-256, origin, intended firmware and license/provenance before treating it as trusted |

## Repository-level blockers

1. No build manifest, build script, test suite, or CI workflow was found in the audited tree.
2. The BD-J source references `org.bdj.api.API` and `org.bdj.Status`, but those source files are not included in this repository. The exact public BD-J API revision must be pinned before compilation can be reproducible.
3. The C offset fragments reference headers that are absent at the referenced paths. They cannot be treated as a standalone buildable C target in this tree.
4. The ISO and binary payload have no in-repository SHA-256/provenance manifest, so their relationship to the text sources cannot currently be established.
5. Firmware-specific offsets and `stat` layout must remain unverified until backed by an exact public source or a reproducible test on an authorized device.

## Validation record

- Static source review only.
- The scanner has not been compiled or run on PS4 hardware by this audit.
- No CI result is available for this branch.
- No kernel-exploit functionality has been added or made operational by these changes.
