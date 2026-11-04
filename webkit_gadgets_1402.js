// WebKit ROP Gadgets & Mitigation Assessment — PS4 Firmware 14.02
// Target: libSceNKWebKit.sprx (PS4 System Software 14.02 - Released Nov 4, 2026)
// García Casado Security Research | Lead: Adrián García Casado
// Standard: ISO/IEC 29147 CVD / Comparative Binary Analysis
//
// CONTEXT & SONY MITIGATION ANALYSIS:
// Firmware 14.02 is a reactive security update specifically deployed by Sony
// to mitigate userland WebKit UAF primitives and APM kernel timing races exposed in 14.00.
// This mapping tracks the candidate gadget offsets and differential delta from 14.00.

const webkit_gadgets_1402 = {
  // Single-instruction primitives (candidate baseline)
  wk_RET                        : 0x4032,    // ret
  wk_LEAVE_RET                  : 0x1c2f7,    // leave; ret
  wk_POP_RAX_RET                : 0x14504,    // pop rax; ret
  wk_POP_RBX_RET                : 0xb9e8,    // pop rbx; ret
  wk_POP_RCX_RET                : 0x1fade,    // pop rcx; ret
  wk_POP_RDX_RET                : 0x1305ba,    // pop rdx; ret
  wk_POP_RSI_RET                : 0x7245e,    // pop rsi; ret
  wk_POP_RDI_RET                : 0x60480,    // pop rdi; ret
  wk_POP_RBP_RET                : 0x40b6,    // pop rbp; ret
  wk_POP_RSP_RET                : 0x73017,    // pop rsp; ret
  wk_POP_R8_RET                 : 0x230cbe1,    // pop r8; ret
  wk_POP_R12_RET                : 0x242ab15,    // pop r12; ret
  wk_POP_R14_RET                : 0xa9e91,    // pop r14; ret
  wk_POP_R15_RET                : 0x6047f,    // pop r15; ret
  wk_MOV_RAX_RDI_RET            : 0x23320,    // mov rax, rdi; ret
  wk_MOV_RDX_RAX_RET            : 0x1ceba9,    // mov rdx, rax; ret
  wk_XCHG_RAX_RSP_RET           : 0x3f755a8,    // xchg rax, rsp; ret (Stack Pivot)
  wk_MOV_QWORD_RDI_RAX_RET      : 0x948b,    // mov [rdi], rax; ret (Write primitive)
  wk_MOV_RAX_QWORD_RAX_RET      : 0x14021,    // mov rax, [rax]; ret (Read primitive)
  wk_MOV_RAX_QWORD_RDI_RET      : 0xe2ea0,    // mov rax, [rdi]; ret (Read primitive)
  wk_ADD_RAX_RCX_RET            : 0x84f67,    // add rax, rcx; ret
  wk_SUB_RAX_RCX_RET            : 0x98736c,    // sub rax, rcx; ret
  wk_XOR_RAX_RAX_RET            : 0x23d14f6,    // xor rax, rax; ret
  wk_INC_RAX_RET                : 0xc5e51c,    // inc rax; ret
  wk_JMP_RAX                    : 0x4082,    // jmp rax
  wk_CALL_RAX                   : 0x4041,    // call rax
  wk_JMP_RCX                    : 0x12a2a,    // jmp rcx

  // Compound gadgets
  wk_POP_R13_POP_R14_POP_R15_RET: 0x6047b,    // pop r13; pop r14; pop r15; ret
  wk_POP_RBX_POP_RBP_RET        : 0xad0f,    // pop rbx; pop rbp; ret
};

// Firmware 14.02 Status:
// - Userland WebKit entry points patched by Sony.
// - Existing 14.00 exploits DO NOT trigger reliably on 14.02.
// - DO NOT UPDATE PS4 consoles above 14.00 (stay on 13.04 / 14.00).

module.exports = { webkit_gadgets_1402 };
