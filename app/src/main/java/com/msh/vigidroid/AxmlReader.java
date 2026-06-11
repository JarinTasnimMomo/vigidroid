package com.msh.vigidroid;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public final class AxmlReader {
    private final InputStream is;

    public AxmlReader(InputStream is) {
        this.is = is;
    }

    private int readInt(byte[] data, int offset) {
        return (data[offset] & 0xff) | ((data[offset+1] & 0xff) << 8) |
                ((data[offset+2] & 0xff) << 16) | ((data[offset+3] & 0xff) << 24);
    }

    private String getString(byte[] data, int offset) {
        int len = (data[offset] & 0xff) | ((data[offset+1] & 0xff) << 8);
        return new String(data, offset + 2, len * 2, StandardCharsets.UTF_16LE);
    }

    public Set<String> parse() throws Exception {
        Set<String> features = new HashSet<>();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) != -1) {
            baos.write(buffer, 0, read);
        }
        byte[] buf = baos.toByteArray();
        int stringPoolOffset = 36; // Typical start after file and pool headers
        int numStrings = readInt(buf, 16); // Number of strings is at offset 16
        int stringsStart = readInt(buf, 28) + 8; // Offset where actual string data begins
        for (int i = 0; i < numStrings; i++) {
            int offset = readInt(buf, stringPoolOffset + (i * 4));
            String s = getString(buf, stringsStart + offset);

            if (s.startsWith("android.permission.") || s.startsWith("android.intent.action.")) {
                features.add(s);
            }
        }
        return features;
    }
}
