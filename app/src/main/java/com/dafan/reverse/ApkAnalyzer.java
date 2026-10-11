package com.dafan.reverse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Local-only APK/ZIP inspection helpers. Does not execute code from the APK. */
public final class ApkAnalyzer {
    private ApkAnalyzer() {}

    public static String sha256(InputStream in) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192]; int n;
            while ((n = in.read(buf)) != -1) digest.update(buf, 0, n);
            byte[] bytes = digest.digest(); StringBuilder out = new StringBuilder();
            for (byte b : bytes) out.append(String.format(Locale.US, "%02x", b & 0xff));
            return out.toString();
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }

    public static List<String> listEntries(ZipFile zip) {
        List<String> entries = new ArrayList<>();
        Enumeration<? extends ZipEntry> en = zip.entries();
        while (en.hasMoreElements()) {
            ZipEntry e = en.nextElement();
            String line = e.getName() + (e.isDirectory() ? "/" : "") + (e.isDirectory() ? "" : "  (" + e.getSize() + " bytes)");
            entries.add(line);
        }
        Collections.sort(entries, String.CASE_INSENSITIVE_ORDER);
        return entries;
    }

    public static List<String> findDexStrings(ZipFile zip, int maxStrings) throws IOException {
        List<String> found = new ArrayList<>();
        Enumeration<? extends ZipEntry> en = zip.entries();
        while (en.hasMoreElements() && found.size() < maxStrings) {
            ZipEntry entry = en.nextElement();
            if (entry.isDirectory() || !entry.getName().matches("(?i)classes[0-9]*\\.dex")) continue;
            try (InputStream in = zip.getInputStream(entry)) {
                byte[] data = readLimited(in, 32 * 1024 * 1024);
                collectAsciiStrings(data, found, maxStrings);
            }
        }
        return found;
    }

    static void collectAsciiStrings(byte[] data, List<String> out, int limit) {
        StringBuilder current = new StringBuilder();
        for (byte value : data) {
            int c = value & 0xff;
            if (c >= 32 && c <= 126) {
                current.append((char)c);
            } else {
                addCandidate(current, out, limit);
                if (out.size() >= limit) return;
            }
        }
        addCandidate(current, out, limit);
    }

    private static void addCandidate(StringBuilder s, List<String> out, int limit) {
        if (s.length() >= 5 && out.size() < limit) {
            String v = s.toString();
            if (!out.contains(v)) out.add(v);
        }
        s.setLength(0);
    }

    private static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n; int total = 0;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > max) throw new IOException("DEX entry exceeds safety limit (32 MiB)");
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
