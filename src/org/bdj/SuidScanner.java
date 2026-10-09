package org.bdj;

import org.bdj.api.API;

public class SuidScanner {

    private static final int O_RDONLY = 0x0000;
    private static final int O_WRONLY = 0x0001;
    private static final int O_CREAT  = 0x0200;
    private static final int O_TRUNC  = 0x0400;
    private static final int S_ISUID  = 0x0800;
    private static final int S_ISGID  = 0x0400;
    private static final int DT_DIR = 4;
    private static final int DENTS_BUF_SIZE = 4096;
    private static final int STAT_BUF_SIZE = 256;
    private static final int PATH_MAX = 1024;
    private static final int DIRENT_HEADER_SIZE = 8;

    private API api;
    private long openAddr, closeAddr, getdentsAddr, statAddr, writeAddr;
    private boolean usesGetdirentries;
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
            openAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "open");
            closeAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "close");
            getdentsAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "getdents");
            if (getdentsAddr == 0) {
                // FreeBSD commonly exposes getdirentries(2), not the Linux getdents(2) API.
                getdentsAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "getdirentries");
                usesGetdirentries = getdentsAddr != 0;
            }
            statAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "stat");
            writeAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "write");
            Status.println("open=" + Long.toHexString(openAddr) +
                " stat=" + Long.toHexString(statAddr) +
                " directory-reader=" + (usesGetdirentries ? "getdirentries" : "getdents") +
                "@" + Long.toHexString(getdentsAddr));
        } catch (Exception e) {
            Status.printStackTrace("SuidScanner init: ", e);
            api = null;
        }
    }

    public void scan() {
        if (!isScanReady()) {
            Status.println("Scan aborted: required native API functions are unavailable");
            return;
        }

        String[] dirs = {"/", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/system", "/system/common/lib",
            "/system/sys", "/system/vsh", "/system_ex", "/system_ex/app",
            "/mini-syscore", "/mini-syscore/bin", "/sandboxDir",
            "/app0", "/data", "/mnt/usb0", "/mnt/usb1"};

        Status.println("=== SUID Scanner PS4 13.04 ===");
        for (int i = 0; i < dirs.length; i++) {
            scanDir(dirs[i], 0);
        }
        Status.println("=== Done: " + suidCount + " SUID/SGID found ===");
        saveToUsb();
    }

    private boolean isScanReady() {
        return api != null && openAddr != 0 && closeAddr != 0 &&
            getdentsAddr != 0 && statAddr != 0;
    }

    private int utf8Length(String value) {
        if (value == null) return -1;
        try {
            return value.getBytes("UTF-8").length;
        } catch (Exception e) {
            return -1;
        }
    }

    private boolean isPathValid(String path) {
        int length = utf8Length(path);
        return length >= 0 && length < PATH_MAX;
    }

    private boolean copyUtf8String(long dest, String value, int capacity) {
        if (dest == 0 || value == null) return false;
        try {
            byte[] bytes = value.getBytes("UTF-8");
            if (bytes.length >= capacity) return false;
            for (int i = 0; i < bytes.length; i++) {
                api.write8(dest + i, bytes[i]);
            }
            api.write8(dest + bytes.length, (byte) 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String readDirName(long address, int byteLength) {
        if (byteLength < 0 || byteLength > 255) return null;
        byte[] bytes = new byte[byteLength];
        for (int i = 0; i < byteLength; i++) {
            bytes[i] = api.read8(address + i);
        }
        try {
            String name = new String(bytes, "UTF-8");
            byte[] encoded = name.getBytes("UTF-8");
            if (encoded.length != bytes.length) return null;
            for (int i = 0; i < bytes.length; i++) {
                if (encoded[i] != bytes[i]) return null;
            }
            return name;
        } catch (Exception e) {
            return null;
        }
    }

    private void scanDir(String path, int depth) {
        if (depth > 3 || !isScanReady() || !isPathValid(path)) {
            if (!isPathValid(path)) {
                Status.println("[SKIP] Path exceeds supported length");
            }
            return;
        }

        long pathBuf = api.malloc(PATH_MAX);
        if (pathBuf == 0) {
            Status.println("[WARN] Unable to allocate path buffer");
            return;
        }
        if (!copyUtf8String(pathBuf, path, PATH_MAX)) {
            api.free(pathBuf);
            Status.println("[WARN] Unable to encode directory path");
            return;
        }
        long fd = api.call(openAddr, pathBuf, O_RDONLY);
        api.free(pathBuf);
        if (fd < 0) return;

        Status.println("[DIR] " + path);
        long dentsBuf = api.malloc(DENTS_BUF_SIZE);
        if (dentsBuf == 0) {
            api.call(closeAddr, fd);
            Status.println("[WARN] Unable to allocate directory buffer");
            return;
        }

        long basep = 0;
        if (usesGetdirentries) {
            // getdirentries expects a writable 64-bit off_t * basep on amd64.
            basep = api.calloc(1, 8);
            if (basep == 0) {
                api.free(dentsBuf);
                api.call(closeAddr, fd);
                Status.println("[WARN] Unable to allocate directory offset buffer");
                return;
            }
        }

        while (true) {
            long nread = usesGetdirentries
                ? api.call(getdentsAddr, fd, dentsBuf, DENTS_BUF_SIZE, basep)
                : api.call(getdentsAddr, fd, dentsBuf, DENTS_BUF_SIZE);
            if (nread <= 0) break;
            if (nread > DENTS_BUF_SIZE) {
                Status.println("[WARN] Invalid getdents length; stopping directory: " + path);
                break;
            }

            long pos = 0;
            boolean malformed = false;
            while (pos < nread) {
                long remaining = nread - pos;
                if (remaining < DIRENT_HEADER_SIZE) {
                    Status.println("[WARN] Truncated directory entry; stopping directory: " + path);
                    malformed = true;
                    break;
                }

                int reclen = api.read16(dentsBuf + pos + 4) & 0xFFFF;
                int dtype = api.read8(dentsBuf + pos + 6) & 0xFF;
                int namlen = api.read8(dentsBuf + pos + 7) & 0xFF;

                if (reclen < DIRENT_HEADER_SIZE || reclen > remaining ||
                    namlen > reclen - DIRENT_HEADER_SIZE) {
                    Status.println("[WARN] Malformed directory entry; stopping directory: " + path);
                    malformed = true;
                    break;
                }

                String name = readDirName(dentsBuf + pos + DIRENT_HEADER_SIZE, namlen);
                if (name != null && name.length() > 0 &&
                    !name.equals(".") && !name.equals("..") &&
                    name.indexOf('/') < 0 && name.indexOf(0) < 0) {
                    String full = path.equals("/") ? "/" + name : path + "/" + name;
                    if (isPathValid(full)) {
                        checkSuid(full);
                        if (dtype == DT_DIR && depth < 3) {
                            scanDir(full, depth + 1);
                        }
                    } else {
                        Status.println("[SKIP] Path exceeds supported length");
                    }
                }
                pos += reclen;
            }
            if (malformed) break;
        }

        api.call(closeAddr, fd);
        if (basep != 0) api.free(basep);
        api.free(dentsBuf);
    }

    private void checkSuid(String filePath) {
        if (!isScanReady() || !isPathValid(filePath)) return;

        long pathBuf = api.malloc(PATH_MAX);
        if (pathBuf == 0) return;
        if (!copyUtf8String(pathBuf, filePath, PATH_MAX)) {
            api.free(pathBuf);
            Status.println("[WARN] Unable to encode file path");
            return;
        }
        long statBuf = api.calloc(1, STAT_BUF_SIZE);
        if (statBuf == 0) {
            api.free(pathBuf);
            return;
        }

        long ret = api.call(statAddr, pathBuf, statBuf);
        if (ret == 0) {
            // These offsets are ABI-specific; validate them against the target firmware
            // before interpreting the fields on a different PS4 firmware.
            int mode = api.read16(statBuf + 0x08) & 0xFFFF;
            int uid = api.read32(statBuf + 0x0C);
            int gid = api.read32(statBuf + 0x10);
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
        api.free(statBuf);
        api.free(pathBuf);
    }

    private void saveToUsb() {
        if (results.length() == 0 || api == null || openAddr == 0 ||
            closeAddr == 0 || writeAddr == 0) {
            if (results.length() > 0) {
                Status.println("USB save unavailable: required native API functions are missing");
            }
            return;
        }

        String[] usbs = {"/mnt/usb0/suid_scan.txt", "/mnt/usb1/suid_scan.txt"};
        String data = "PS4 13.04 SUID Scan\nFound: " + suidCount + "\n\n" + results.toString();
        byte[] reportBytes;
        try {
            reportBytes = data.getBytes("UTF-8");
        } catch (Exception e) {
            Status.println("USB save failed: unable to encode report");
            return;
        }
        if (reportBytes.length >= PATH_MAX * 1024) {
            Status.println("USB save skipped: report is too large");
            return;
        }

        for (int i = 0; i < usbs.length; i++) {
            if (!isPathValid(usbs[i])) continue;
            long p = api.malloc(PATH_MAX);
            if (p == 0) continue;
            if (!copyUtf8String(p, usbs[i], PATH_MAX)) {
                api.free(p);
                continue;
            }
            long fd = api.call(openAddr, p, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4);
            api.free(p);
            if (fd < 0) continue;

            long buf = api.malloc(reportBytes.length + 1);
            if (buf == 0) {
                api.call(closeAddr, fd);
                Status.println("USB save failed: unable to allocate report buffer");
                return;
            }
            for (int j = 0; j < reportBytes.length; j++) {
                api.write8(buf + j, reportBytes[j]);
            }
            api.write8(buf + reportBytes.length, (byte) 0);

            long written = 0;
            long total = reportBytes.length;
            while (written < total) {
                long count = api.call(writeAddr, fd, buf + written, total - written);
                if (count <= 0) break;
                written += count;
            }
            api.free(buf);
            api.call(closeAddr, fd);

            if (written == total) {
                Status.println("Saved to " + usbs[i]);
                return;
            }
            Status.println("USB write incomplete at " + usbs[i] +
                " (" + written + "/" + total + " bytes)");
        }
        Status.println("USB save failed - results on screen only");
    }
}
