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
    private static final int DT_REG = 8;
    private static final int DENTS_BUF_SIZE = 4096;
    private static final int STAT_BUF_SIZE = 256;
    private static final int PATH_MAX = 1024;

    private API api;
    private long openAddr, closeAddr, getdentsAddr, statAddr, writeAddr;
    private StringBuffer results;
    private int suidCount;

    public SuidScanner() {
        results = new StringBuffer();
        suidCount = 0;
        try {
            api = API.getInstance();
            openAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "open");
            closeAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "close");
            getdentsAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "getdents");
            statAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "stat");
            writeAddr = api.dlsym(API.LIBC_MODULE_HANDLE, "write");
            Status.println("open=" + Long.toHexString(openAddr) +
                " stat=" + Long.toHexString(statAddr) +
                " getdents=" + Long.toHexString(getdentsAddr));
        } catch (Exception e) {
            Status.printStackTrace("SuidScanner init: ", e);
        }
    }

    public void scan() {
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

    private void scanDir(String path, int depth) {
        if (depth > 3 || openAddr == 0) return;
        long pathBuf = api.malloc(PATH_MAX);
        if (pathBuf == 0) return;
        api.strcpy(pathBuf, path);
        long fd = api.call(openAddr, pathBuf, O_RDONLY);
        if (fd < 0) { api.free(pathBuf); return; }
        Status.println("[DIR] " + path);
        long dentsBuf = api.malloc(DENTS_BUF_SIZE);
        if (dentsBuf == 0) { api.call(closeAddr, fd); api.free(pathBuf); return; }
        long nread;
        while (true) {
            nread = api.call(getdentsAddr, fd, dentsBuf, DENTS_BUF_SIZE);
            if (nread <= 0) break;
            long pos = 0;
            while (pos < nread) {
                int reclen = api.read16(dentsBuf + pos + 4) & 0xFFFF;
                if (reclen == 0) break;
                int dtype = api.read8(dentsBuf + pos + 6) & 0xFF;
                int namlen = api.read8(dentsBuf + pos + 7) & 0xFF;
                String name = api.readString(dentsBuf + pos + 8, namlen);
                if (!name.equals(".") && !name.equals("..")) {
                    String full = path.equals("/") ? "/" + name : path + "/" + name;
                    checkSuid(full);
                    if (dtype == DT_DIR && depth < 3) scanDir(full, depth + 1);
                }
                pos += reclen;
            }
        }
        api.call(closeAddr, fd);
        api.free(dentsBuf);
        api.free(pathBuf);
    }

    private void checkSuid(String filePath) {
        long pathBuf = api.malloc(PATH_MAX);
        if (pathBuf == 0) return;
        api.strcpy(pathBuf, filePath);
        long statBuf = api.calloc(1, STAT_BUF_SIZE);
        if (statBuf == 0) { api.free(pathBuf); return; }
        long ret = api.call(statAddr, pathBuf, statBuf);
        if (ret == 0) {
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
                results.append(line + "\n");
                suidCount++;
            }
        }
        api.free(statBuf);
        api.free(pathBuf);
    }

    private void saveToUsb() {
        if (results.length() == 0 || writeAddr == 0) return;
        String[] usbs = {"/mnt/usb0/suid_scan.txt", "/mnt/usb1/suid_scan.txt"};
        for (int i = 0; i < usbs.length; i++) {
            long p = api.malloc(PATH_MAX);
            if (p == 0) continue;
            api.strcpy(p, usbs[i]);
            long fd = api.call(openAddr, p, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4);
            if (fd >= 0) {
                String data = "PS4 13.04 SUID Scan\nFound: " + suidCount + "\n\n" + results.toString();
                long buf = api.malloc(data.length() + 1);
                if (buf != 0) {
                    api.strcpy(buf, data);
                    api.call(writeAddr, fd, buf, (long) data.length());
                    api.free(buf);
                }
                api.call(closeAddr, fd);
                Status.println("Saved to " + usbs[i]);
                api.free(p);
                return;
            }
            api.free(p);
        }
        Status.println("USB save failed - results on screen only");
    }
}
