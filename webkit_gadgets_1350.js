// WebKit ROP Gadgets — PS4 Firmware 13.50
// Source: libSceNKWebKit.sprx.decrypted (68 MB)
// Found using radare2 6.1.9 byte pattern search
// For use with CSSFontFace exploit (ntfargo) porting
//
// These are for FW 13.50 as REFERENCE.
// FW 13.04 gadgets will have different addresses.
// Use BinDiff between 13.04 and 13.50 WebKit libs to port.

const webkit_gadgets_1350 = {
  wk_RET:          0x3cbc51b,
  wk_LEAVE_RET:    0x182f7,
  wk_POP_RAX_RET:  0x10504,
  wk_POP_RBX_RET:  0x79e8,
  wk_POP_RCX_RET:  0x1bade,
  wk_POP_RDI_RET:  0x5c480,
  wk_POP_RDX_RET:  0x12c5ba,
  wk_POP_RSI_RET:  0x6e45e,
  wk_POP_RBP_RET:  0x3ccc7a2,
  wk_POP_RSP_RET:  0x3cbc51a,
  wk_POP_R8_RET:   0x5c47f,
  wk_POP_R9_RET:   0x9db883,   // 49 59 c3
  wk_POP_R10_RET:  0x2dbf3b5,  // 41 5a 41 (partial match)
  wk_POP_R11_RET:  0x1989ba,   // 41 5b 41 (partial match)
  wk_POP_R12_RET:  0x2426b15,  // 41 5c c3
  wk_POP_R13_RET:  0x5c47b,    // 41 5d 41 5e 41 5f c3 (pop r13; pop r14; pop r15; ret)
  wk_POP_R14_RET:  0xa5e91,
  wk_POP_R15_RET:  0x5c47f,    // shares with POP_R8 (41 5f c3)
};

// Notes:
// - POP_R13 is actually: pop r13; pop r14; pop r15; ret
//   Requires 3 dummy values on stack (r13 value + r14 dummy + r15 dummy)
// - POP_R10 and POP_R11 are partial matches (not followed by direct ret)
//   May need verification in disassembly for clean gadgets
// - POP_R15 and POP_R8 share the same address (0x5c47f)
//   This is because: 41 58 = pop r8, 41 5f = pop r15
//   At 0x5c47f: 41 5f c3 (pop r15; ret) but entered at -1 byte:
//   0x5c47e: 41 58 41 5f c3 (pop r8; pop r15; ret)

// Kernel offsets for 13.50 (from midohar36 kernel dump):
// Use these with the gadgets above for a complete exploit on 13.50
// PRISON0    = 0x111FA18  (same as 13.00-13.04)
// ROOTVNODE  = 0x2136E90  (same as 13.00-13.04)
// Note: Full kernel offsets for 13.50 need to be extracted via BinDiff

// To port to 13.04:
// 1. Obtain libSceNKWebKit.sprx from FW 13.04
// 2. Repeat radare2 byte pattern search for each gadget
// 3. Or BinDiff the two WebKit libs to map addresses
// 4. Combine with kernel offsets from 1304.c
// 5. Create KPATCH 1304.bin
