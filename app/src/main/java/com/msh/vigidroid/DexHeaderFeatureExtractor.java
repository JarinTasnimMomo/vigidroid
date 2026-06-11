package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * BM1 (mlp_header) feature extraction: all classes*.dex headers, sum-pooled, min-max normalized.
 * Matches Python only_base1_model src/features/dex_header.py + multidex.py (mode=sum).
 */
public final class DexHeaderFeatureExtractor {

    public static final int FEATURE_DIM = 104;
    public static final int DEX_MAGIC_LEN = 8;
    public static final int DEX_HEADER_SIZE = 0x70;
    public static final String NORMALIZATION_ASSET =
            "models/mlp_header/features/normalization_header.json";
    public static final String EARLY_FUSION_DEX_MANIFEST_NORMALIZATION_ASSET =
            "models/early_fusion_dex_manifest/features/normalization_header.json";
    public static final String DUAL_BRANCH_DEX_MANIFEST_NORMALIZATION_ASSET =
            "models/dual_branch_dex_manifest/features/normalization_header.json";

    private static final Pattern DEX_BASENAME = Pattern.compile("^classes(\\d*)\\.dex$");

    private final float[] mins;
    private final float[] maxs;

    public static final class ExtractionResult {
        public final float[] features;
        public final int dexFilesFound;
        public final long extractNanos;
        public final long normalizeNanos;

        ExtractionResult(float[] features, int dexFilesFound, long extractNanos, long normalizeNanos) {
            this.features = features;
            this.dexFilesFound = dexFilesFound;
            this.extractNanos = extractNanos;
            this.normalizeNanos = normalizeNanos;
        }
    }

    public DexHeaderFeatureExtractor(float[] mins, float[] maxs) {
        if (mins.length != FEATURE_DIM || maxs.length != FEATURE_DIM) {
            throw new IllegalArgumentException("Expected min/max length " + FEATURE_DIM);
        }
        this.mins = mins;
        this.maxs = maxs;
    }

    public static DexHeaderFeatureExtractor fromAssets(Context context) throws Exception {
        return fromAssets(context, NORMALIZATION_ASSET);
    }

    public static DexHeaderFeatureExtractor fromAssets(Context context, String normalizationAsset)
            throws Exception {
        String json = ModelAssetHelper.readAssetText(context, normalizationAsset);
        JSONObject root = new JSONObject(json);
        float[] mins = jsonArrayToFloats(root.getJSONArray("mins"));
        float[] maxs = jsonArrayToFloats(root.getJSONArray("maxs"));
        return new DexHeaderFeatureExtractor(mins, maxs);
    }

    public ExtractionResult extract(File apkFile) throws Exception {
        try (ZipFile zip = new ZipFile(apkFile)) {
            List<String> dexEntries = listDexEntries(zip);
            if (dexEntries.isEmpty()) {
                throw new IllegalStateException("No classes*.dex in APK");
            }
            List<byte[]> dexBytes = new ArrayList<>(dexEntries.size());
            for (String entryName : dexEntries) {
                ZipEntry entry = zip.getEntry(entryName);
                if (entry != null) {
                    dexBytes.add(readEntryBytes(zip, entry));
                }
            }
            return extractFromDexByteArrays(dexBytes);
        }
    }

    /** Sum-pool + min-max from pre-read DEX buffers (shared {@link FeatureContext}). */
    public ExtractionResult extractFromDexByteArrays(List<byte[]> dexByteArrays) throws Exception {
        if (dexByteArrays.isEmpty()) {
            throw new IllegalStateException("No classes*.dex in APK");
        }
        long t0 = System.nanoTime();
        float[] summed = new float[FEATURE_DIM];
        for (byte[] dexBytes : dexByteArrays) {
            float[] perDex = extractRawHeaderFeatures(dexBytes);
            for (int i = 0; i < FEATURE_DIM; i++) {
                summed[i] += perDex[i];
            }
        }
        long t1 = System.nanoTime();
        float[] normalized = transformMinMax(summed);
        long t2 = System.nanoTime();
        return new ExtractionResult(normalized, dexByteArrays.size(), t1 - t0, t2 - t1);
    }

    static List<String> listDexEntries(ZipFile zip) {
        List<String> names = new ArrayList<>();
        java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (entry.isDirectory()) {
                continue;
            }
            String base = basename(entry.getName());
            if (DEX_BASENAME.matcher(base).matches()) {
                names.add(entry.getName());
            }
        }
        Collections.sort(names, Comparator.comparingInt(DexHeaderFeatureExtractor::dexSortKey)
                .thenComparing(name -> basename(name)));
        return names;
    }

    static int dexSortKey(String entryName) {
        Matcher m = DEX_BASENAME.matcher(basename(entryName));
        if (!m.matches()) {
            return 999_999;
        }
        String suffix = m.group(1);
        return suffix == null || suffix.isEmpty() ? 0 : Integer.parseInt(suffix);
    }

    static String basename(String path) {
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }

    static byte[] readEntryBytes(ZipFile zip, ZipEntry entry) throws Exception {
        try (InputStream is = zip.getInputStream(entry)) {
            long size = entry.getSize();
            if (size < 0 || size > 64 * 1024 * 1024) {
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int read;
                while ((read = is.read(buf)) != -1) {
                    bos.write(buf, 0, read);
                }
                return bos.toByteArray();
            }
            byte[] data = new byte[(int) size];
            int offset = 0;
            while (offset < data.length) {
                int read = is.read(data, offset, data.length - offset);
                if (read < 0) {
                    throw new IllegalStateException("Unexpected EOF reading " + entry.getName());
                }
                offset += read;
            }
            return data;
        }
    }

    static boolean validateMagic(byte[] dexBytes) {
        if (dexBytes.length < DEX_MAGIC_LEN) {
            return false;
        }
        if (dexBytes[0] != 'd' || dexBytes[1] != 'e' || dexBytes[2] != 'x' || dexBytes[3] != '\n') {
            return false;
        }
        for (int i = 4; i <= 6; i++) {
            if (dexBytes[i] < '0' || dexBytes[i] > '9') {
                return false;
            }
        }
        return dexBytes[7] == 0;
    }

    static float[] extractRawHeaderFeatures(byte[] dexBytes) {
        if (!validateMagic(dexBytes)) {
            throw new IllegalArgumentException("Invalid DEX magic");
        }
        if (dexBytes.length < DEX_HEADER_SIZE) {
            throw new IllegalArgumentException("DEX buffer too small for header");
        }
        float[] out = new float[FEATURE_DIM];
        for (int i = 0; i < FEATURE_DIM; i++) {
            int b = dexBytes[DEX_MAGIC_LEN + i] & 0xFF;
            out[i] = b / 255.0f;
        }
        return out;
    }

    float[] transformMinMax(float[] raw) {
        float[] out = new float[FEATURE_DIM];
        for (int i = 0; i < FEATURE_DIM; i++) {
            float denom = maxs[i] - mins[i];
            if (denom == 0f) {
                denom = 1f;
            }
            out[i] = (raw[i] - mins[i]) / denom;
        }
        return out;
    }

    private static float[] jsonArrayToFloats(JSONArray arr) throws Exception {
        float[] values = new float[arr.length()];
        for (int i = 0; i < arr.length(); i++) {
            values[i] = (float) arr.getDouble(i);
        }
        return values;
    }
}
