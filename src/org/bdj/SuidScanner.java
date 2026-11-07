package org.bdj;

import org.bdj.api.API;

public class SuidScanner {

    private static final int O_RDONLY = 0x0000;
    private static final int O_WRONLY = 0x0001;
    private static final int O_CREAT  = 0x0200;
    private static final int O_TRUNC  = 0x0400;

    private static final int S_IFMT   = 0xF000;
    private static final int S_IFDIR  = 0x4000;
    private static final int S_IFLNK  = 0xA000;
    private static final int S_ISUID  = 0x0800;
    private static final int S_ISGID  = 0x0400;

    private static final int DT_UNKNOWN = 0;
    private static final int DT_DIR     = 4;
    private static final int DT_LNK     = 10;

    private static final int DENTS_BUF_SIZE     = 4096;
    private static final int STAT_BUF_SIZE      = 256;
    private static final int PATH_MAX           = 1024;
    private static final int DIRENT_HEADER_SIZE = 8;
    private static final int MAX_DEPTH          = 3;
    private static final int MAX_REPORT_BYTES   = 1024 * 1024;

    private API api;
    private long openAddr;
    private long closeAddr;
    private long getdentsAddr;
    private long statAddr;
    private long writeAddr;
    private boolean usesGetdirentries;
    private boolean usesStatFallback;
    private final StringBuffer results;
    private int suidCount;

    public SuidScanner() {
        results = new StringBuffer();
        suidCount = 0;
        try {
            api = API.getInstance();
            if (api == null) {
                Status.println("SuidScanner init failed: API instance unavailable");
                return;
            }
            openAddr = resolveSymbol("open");
            closeAddr = resolveSymbol("close");
            getdentsAddr = resolveSymbol("getdents");
            if (getdentsAddr == 0) {
                getdentsAddr = resolveSymbol("getdirentries");
                usesGetdirentries = (getdentsAddr != 0);
            }
            statAddr = resolveSymbol("lstat");
            if (statAddr == 0) {
                statAddr = resolveSymbol("stat");
                usesStatFallback = (statAddr != 0);
            }
            writeAddr = resolveSymbol("write");

            Status.println("open=0x" + Long.toHexString(openAddr) +
                " close=0x" + Long.toHexString(closeAddr) +
                " " + (usesStatFallback ? "stat" : "lstat") + "=0x" + Long.toHexString(statAddr) +
                " " + (usesGetdirentries ? "getdirentries" : "getdents") + "=0x" + Long.toHexString(getdentsAddr) +
                " write=0x" + Long.toHexString(writeAddr));
            if (usesStatFallback) {
                Status.println("[WARN] lstat unavailable; falling back to stat");
            }
        } catch (Throwable t) {
            Status.printStackTrace("SuidScanner init: ", t);
            api = null;
        }
    }

    private long resolveSymbol(String name) {
        long addr = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, name);
        if (addr == 0) {
            addr = api.dlsym(API.LIBC_MODULE_HANDLE, name);
        }
        if (addr == 0) {
            addr = api.dlsym(API.RTLD_DEFAULT, name);
        }
        return addr;
    }

    private boolean isScanReady() {
        return api != null && openAddr != 0 && closeAddr != 0 &&
            getdentsAddr != 0 && statAddr != 0;
    }

    public void scan() {
        if (!isScanReady()) {
            Status.println("Scan aborted: required native syscalls unavailable");
            return;
        }

        String[] dirs = {"/", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/system", "/system/common/lib",
            "/system/sys", "/system/vsh", "/system_ex", "/system_ex/app",
            "/mini-syscore", "/mini-syscore/bin", "/sandboxDir",
            "/app0", "/data", "/mnt/usb0", "/mnt/usb1"};

        Status.println("=== SUID Scanner PS4 (Orbis OS / FreeBSD 9 ABI) ===");
        for (int i = 0; i < dirs.length; i++) {
            scanDir(dirs[i], 0);
        }
        Status.println("=== Done: " + suidCount + " SUID/SGID found ===");
        saveToUsb();
    }

    private boolean writeUtf8CString(long dest, String value, int capacity) {
        if (dest == 0 || value == null || value.indexOf(0) >= 0) {
            return false;
        }
        try {
            byte[] bytes = value.getBytes("UTF-8");
            if (bytes.length >= capacity) {
                return false;
            }
            if (bytes.length > 0) {
                api.memcpy(dest, bytes, bytes.length);
            }
            api.write8(dest + bytes.length, (byte) 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String readDirEntryName(long addr, int namlen) {
        if (namlen <= 0 || namlen > 255) {
            return null;
        }
        byte[] raw = new byte[namlen];
        api.memcpy(raw, addr, namlen);
        for (int i = 0; i < namlen; i++) {
            if (raw[i] == 0 || raw[i] == (byte) '/') {
                return null;
            }
        }
        try {
            return new String(raw, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    private void scanDir(String path, int depth) {
        if (depth > MAX_DEPTH || !isScanReady() || path == null) {
            return;
        }

        long pathBuf = api.malloc(PATH_MAX);
        if (pathBuf == 0) {
            return;
        }
        if (!writeUtf8CString(pathBuf, path, PATH_MAX)) {
            api.free(pathBuf);
            Status.println("[SKIP] Path too long or invalid: " + path);
            return;
        }

        long fd = api.call(openAddr, pathBuf, O_RDONLY);
        api.free(pathBuf);
        if (fd < 0) {
            return;
        }

        Status.println("[DIR] " + path);
        long dentsBuf = api.malloc(DENTS_BUF_SIZE);
        if (dentsBuf == 0) {
            api.call(closeAddr, fd);
            return;
        }

        long basep = 0;
        if (usesGetdirentries) {
            basep = api.calloc(1, 8);
            if (basep == 0) {
                api.free(dentsBuf);
                api.call(closeAddr, fd);
                return;
            }
        }

        while (true) {
            long nread = usesGetdirentries
                ? api.call(getdentsAddr, fd, dentsBuf, DENTS_BUF_SIZE, basep)
                : api.call(getdentsAddr, fd, dentsBuf, DENTS_BUF_SIZE);
            if (nread < 0) {
                Status.println("[WARN] getdents failed on " + path + " (errno=" + api.errno() + ")");
                break;
            }
            if (nread == 0) {
                break;
            }
            if (nread > DENTS_BUF_SIZE) {
                Status.println("[WARN] Out-of-bounds getdents return (" + nread + ") on " + path);
                break;
            }

            long pos = 0;
            boolean malformed = false;
            while (pos < nread) {
                long remaining = nread - pos;
                if (remaining < DIRENT_HEADER_SIZE) {
                    Status.println("[WARN] Truncated dirent header in " + path);
                    malformed = true;
                    break;
                }

                int reclen = api.read16(dentsBuf + pos + 4) & 0xFFFF;
                int dtype  = api.read8(dentsBuf + pos + 6) & 0xFF;
                int namlen = api.read8(dentsBuf + pos + 7) & 0xFF;

                if (reclen < DIRENT_HEADER_SIZE || reclen > remaining ||
                    namlen > reclen - DIRENT_HEADER_SIZE) {
                    Status.println("[WARN] Malformed dirent (reclen=" + reclen +
                        ", namlen=" + namlen + ") in " + path);
                    malformed = true;
                    break;
                }

                String name = readDirEntryName(dentsBuf + pos + DIRENT_HEADER_SIZE, namlen);
                if (name != null && !name.equals(".") && !name.equals("..")) {
                    String full = path.equals("/") ? "/" + name : path + "/" + name;
                    boolean isSubDir = checkSuid(full, dtype);
                    if (isSubDir && depth < MAX_DEPTH && !full.equals("/dev")) {
                        scanDir(full, depth + 1);
                    }
                }
                pos += reclen;
            }
            if (malformed) {
                break;
            }
        }

        api.call(closeAddr, fd);
        if (basep != 0) {
            api.free(basep);
        }
        api.free(dentsBuf);
    }

    private boolean checkSuid(String filePath, int dtype) {
        if (!isScanReady() || dtype == DT_LNK) {
            return false;
        }

        long pathBuf = api.malloc(PATH_MAX);
        if (pathBuf == 0) {
            return false;
        }
        if (!writeUtf8CString(pathBuf, filePath, PATH_MAX)) {
            api.free(pathBuf);
            return false;
        }

        long statBuf = api.calloc(1, STAT_BUF_SIZE);
        if (statBuf == 0) {
            api.free(pathBuf);
            return false;
        }

        boolean isDir = (dtype == DT_DIR);
        long ret = api.call(statAddr, pathBuf, statBuf);
        if (ret == 0) {
            int mode = api.read16(statBuf + 0x08) & 0xFFFF;
            int uid  = api.read32(statBuf + 0x0C);
            int gid  = api.read32(statBuf + 0x10);
            int fmt  = mode & S_IFMT;

            if (fmt == S_IFLNK) {
                isDir = false;
            } else {
                if (dtype == DT_UNKNOWN && fmt == S_IFDIR) {
                    isDir = true;
                }
                boolean suid = (mode & S_ISUID) != 0;
                boolean sgid = (mode & S_ISGID) != 0;
                if (suid || sgid) {
                    String flags = (suid ? "SUID " : "") + (sgid ? "SGID " : "");
                    String line = "[FOUND] " + flags + "mode=0" +
                        Integer.toOctalString(mode) + " uid=" + uid +
                        " gid=" + gid + " " + filePath;
                    Status.println(line);
                    results.append(line).append('\n');
                    suidCount++;
                }
            }
        }

        api.free(statBuf);
        api.free(pathBuf);
        return isDir;
    }

    private void saveToUsb() {
        if (api == null || openAddr == 0 || closeAddr == 0 || writeAddr == 0) {
            Status.println("USB save unavailable: required native syscalls missing");
            return;
        }

        String report = "PS4 SUID/SGID Scan Report\nFound: " + suidCount + "\n\n" + results.toString();
        byte[] reportBytes;
        try {
            reportBytes = report.getBytes("UTF-8");
        } catch (Exception e) {
            Status.println("USB save failed: UTF-8 encoding error");
            return;
        }

        if (reportBytes.length > MAX_REPORT_BYTES) {
            Status.println("USB save skipped: report exceeds limit (" + reportBytes.length + " bytes)");
            return;
        }

        String[] usbs = {"/mnt/usb0/suid_scan.txt", "/mnt/usb1/suid_scan.txt"};
        for (int i = 0; i < usbs.length; i++) {
            long p = api.malloc(PATH_MAX);
            if (p == 0) {
                continue;
            }
            if (!writeUtf8CString(p, usbs[i], PATH_MAX)) {
                api.free(p);
                continue;
            }

            long fd = api.call(openAddr, p, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4);
            api.free(p);
            if (fd < 0) {
                continue;
            }

            long buf = api.malloc(reportBytes.length + 1);
            if (buf == 0) {
                api.call(closeAddr, fd);
                Status.println("USB save failed: buffer allocation failed");
                return;
            }
            if (reportBytes.length > 0) {
                api.memcpy(buf, reportBytes, reportBytes.length);
            }
            api.write8(buf + reportBytes.length, (byte) 0);

            long written = 0;
            long total = reportBytes.length;
            while (written < total) {
                long n = api.call(writeAddr, fd, buf + written, total - written);
                if (n <= 0) {
                    break;
                }
                written += n;
            }

            api.free(buf);
            api.call(closeAddr, fd);

            if (written == total) {
                Status.println("Saved to " + usbs[i] + " (" + written + " bytes)");
                return;
            }
            Status.println("USB write incomplete on " + usbs[i] +
                " (" + written + "/" + total + " bytes)");
        }
        Status.println("USB save failed - results on screen only");
    }
}
