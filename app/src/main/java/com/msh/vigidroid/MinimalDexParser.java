package com.msh.vigidroid;

import java.io.*;
import java.nio.*;
import java.util.*;

public final class MinimalDexParser {

    public interface Listener {
        void onApi(String feature);
    }

    public static void parse(InputStream is, Listener listener) throws IOException {
        byte[] dex = readAll(is);
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);

        // ---- Read header ----
        int stringIdsSize = buf.getInt(56);
        int stringIdsOff  = buf.getInt(60);

        int typeIdsSize   = buf.getInt(64);
        int typeIdsOff    = buf.getInt(68);

        int methodIdsSize = buf.getInt(88);
        int methodIdsOff  = buf.getInt(92);

        // ---- Load string pool ----
        String[] strings = new String[stringIdsSize];
        for (int i = 0; i < stringIdsSize; i++) {
            int off = buf.getInt(stringIdsOff + i * 4);
            strings[i] = readMutf8(buf, off);
        }

        // ---- Load types ----
        String[] types = new String[typeIdsSize];
        for (int i = 0; i < typeIdsSize; i++) {
            int idx = buf.getInt(typeIdsOff + i * 4);
            types[i] = strings[idx];
        }

        // ---- Parse method_ids ----
        for (int i = 0; i < methodIdsSize; i++) {
            int base = methodIdsOff + i * 8;

            int classIdx = buf.getShort(base) & 0xFFFF;
            int nameIdx  = buf.getInt(base + 4);

            String classDesc = types[classIdx];
            if (!classDesc.startsWith("Landroid/")) continue;

            String method = strings[nameIdx];
            emitFeature(classDesc, method, listener);
        }
    }

    // ---------------- helpers ----------------

    private static void emitFeature(String classDesc, String method, Listener l) {
        // Landroid/telephony/TelephonyManager;
        String cls = classDesc.substring(1, classDesc.length() - 1)
                .toLowerCase(Locale.US);

        String feature = "apicalls::l" + cls + "." + method.toLowerCase(Locale.US);
        l.onApi(feature);
    }

    private static String readMutf8(ByteBuffer buf, int offset) {
        int pos = offset;
        int[] out = new int[1];
        pos += readUleb128(buf, pos, out); // skip utf16 length

        StringBuilder sb = new StringBuilder();
        while (true) {
            byte b = buf.get(pos++);
            if (b == 0) break;
            if ((b & 0x80) == 0) {
                sb.append((char) b);
            } else if ((b & 0xE0) == 0xC0) {
                int b2 = buf.get(pos++) & 0x3F;
                sb.append((char) (((b & 0x1F) << 6) | b2));
            } else {
                int b2 = buf.get(pos++) & 0x3F;
                int b3 = buf.get(pos++) & 0x3F;
                sb.append((char) (((b & 0x0F) << 12) | (b2 << 6) | b3));
            }
        }
        return sb.toString();
    }

    private static int readUleb128(ByteBuffer buf, int pos, int[] out) {
        int result = 0;
        int count = 0;
        int cur;
        do {
            cur = buf.get(pos + count) & 0xFF;
            result |= (cur & 0x7F) << (count * 7);
            count++;
        } while ((cur & 0x80) != 0);
        out[0] = result;
        return count;
    }

    private static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        while ((r = is.read(buf)) != -1) {
            baos.write(buf, 0, r);
        }
        return baos.toByteArray();
    }
}
