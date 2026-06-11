package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * A1 — MLDP permissions + Dex header cascade feature extractor.
 *
 * <p>Aligned with mldp_dexheader_cascade Python P2: x_S from frozen MLDP vocab, H from
 * classes*.dex headers (sum-pool + corpus min-max), Mode A fusion x = [x_S || H].
 */
public final class MldpDexHeaderExtractor {

  public static final String MODEL_FAMILY_ID = "mldp_dexheader_cascade";
  public static final String DOMAIN = "manifest_mldp_perm_dex_header";

  public static final int S_DIM = 22;
  public static final int H_DIM = 104;
  public static final int D_DIM = 126;

  public static final String FEATURES_ASSET_PREFIX =
      "models/mldp_dexheader_cascade/features/";
  public static final String MLDP_VOCAB_ASSET =
      FEATURES_ASSET_PREFIX + "mldp_permission_vocab.json";
  public static final String NORMALIZATION_ASSET =
      FEATURES_ASSET_PREFIX + "normalization_header.json";
  public static final String FEATURE_LAYOUT_ASSET =
      FEATURES_ASSET_PREFIX + "feature_layout.json";

  private final Map<String, Integer> mldpTokenToIndex;
  private final int sDim;
  private final int hDim;
  private final int dDim;
  private final DexHeaderFeatureExtractor dexExtractor;

  public static final class PermissionBlockResult {
    public final float[] xS;
    public final int permissionCount;
    public final long parseNanos;

    PermissionBlockResult(float[] xS, int permissionCount, long parseNanos) {
      this.xS = xS;
      this.permissionCount = permissionCount;
      this.parseNanos = parseNanos;
    }

    public long parseMs() {
      return parseNanos / 1_000_000L;
    }
  }

  public static final class DexBlockResult {
    public final float[] h;
    public final int dexFilesFound;
    public final long dexNanos;

    DexBlockResult(float[] h, int dexFilesFound, long dexNanos) {
      this.h = h;
      this.dexFilesFound = dexFilesFound;
      this.dexNanos = dexNanos;
    }

    public long dexMs() {
      return dexNanos / 1_000_000L;
    }
  }

  public static final class ExtractionResult {
    public final float[] xS;
    public final float[] h;
    public final float[] x;
    public final int permissionCount;
    public final int dexFilesFound;
    public final long parseNanos;
    public final long dexNanos;
    public final long vectorizeNanos;

    ExtractionResult(
        float[] xS,
        float[] h,
        float[] x,
        int permissionCount,
        int dexFilesFound,
        long parseNanos,
        long dexNanos,
        long vectorizeNanos) {
      this.xS = xS;
      this.h = h;
      this.x = x;
      this.permissionCount = permissionCount;
      this.dexFilesFound = dexFilesFound;
      this.parseNanos = parseNanos;
      this.dexNanos = dexNanos;
      this.vectorizeNanos = vectorizeNanos;
    }

    public long parseMs() {
      return parseNanos / 1_000_000L;
    }

    public long dexMs() {
      return dexNanos / 1_000_000L;
    }

    public long vectorizeMs() {
      return vectorizeNanos / 1_000_000L;
    }
  }

  public MldpDexHeaderExtractor(
      Map<String, Integer> mldpTokenToIndex,
      DexHeaderFeatureExtractor dexExtractor,
      int sDim,
      int hDim,
      int dDim) {
    this.mldpTokenToIndex = mldpTokenToIndex;
    this.dexExtractor = dexExtractor;
    this.sDim = sDim;
    this.hDim = hDim;
    this.dDim = dDim;
    if (sDim + hDim != dDim) {
      throw new IllegalArgumentException("Expected S+H=" + dDim + ", got " + sDim + "+" + hDim);
    }
  }

  public static MldpDexHeaderExtractor fromAssets(Context context) throws Exception {
    JSONObject layout = new JSONObject(ModelAssetHelper.readAssetText(context, FEATURE_LAYOUT_ASSET));
    int sDim = layout.getInt("S");
    int hDim = layout.getInt("H");
    int dDim = layout.getInt("d");
    if (sDim + hDim != dDim) {
      throw new IllegalStateException("feature_layout.json d mismatch");
    }

    JSONObject mldpVocab = new JSONObject(ModelAssetHelper.readAssetText(context, MLDP_VOCAB_ASSET));
    Map<String, Integer> mldpIndex =
        PermissionNormalizer.buildTokenToIndex(mldpVocab.getJSONArray("tokens"));
    DexHeaderFeatureExtractor dexExtractor =
        DexHeaderFeatureExtractor.fromAssets(context, NORMALIZATION_ASSET);
    return new MldpDexHeaderExtractor(mldpIndex, dexExtractor, sDim, hDim, dDim);
  }

  public static MldpDexHeaderExtractor fromAssetStrings(
      String mldpVocabJson, String normalizationJson, String featureLayoutJson) throws Exception {
    JSONObject layout = new JSONObject(featureLayoutJson);
    int sDim = layout.getInt("S");
    int hDim = layout.getInt("H");
    int dDim = layout.getInt("d");

    JSONObject mldpVocab = new JSONObject(mldpVocabJson);
    Map<String, Integer> mldpIndex =
        PermissionNormalizer.buildTokenToIndex(mldpVocab.getJSONArray("tokens"));

    JSONObject normRoot = new JSONObject(normalizationJson);
    float[] mins = jsonArrayToFloats(normRoot.getJSONArray("mins"));
    float[] maxs = jsonArrayToFloats(normRoot.getJSONArray("maxs"));
    DexHeaderFeatureExtractor dexExtractor = new DexHeaderFeatureExtractor(mins, maxs);
    return new MldpDexHeaderExtractor(mldpIndex, dexExtractor, sDim, hDim, dDim);
  }

  /** Manifest permissions only — used by Mode B before optional dex read (A3). */
  public PermissionBlockResult extractPermissionBlock(File apkFile) throws Exception {
    long t0 = System.nanoTime();
    List<String> normalizedPermissions = PermissionNormalizer.readNormalizedPermissions(apkFile);
    long t1 = System.nanoTime();
    return buildPermissionBlock(normalizedPermissions, t1 - t0);
  }

  public PermissionBlockResult extractPermissionBlock(FeatureContext ctx) throws Exception {
    return buildPermissionBlock(ctx.normalizedPermissions(), 0L);
  }

  private PermissionBlockResult buildPermissionBlock(
      List<String> normalizedPermissions, long parseNanos) {
    long t1 = System.nanoTime();
    float[] xS = buildXS(normalizedPermissions);
    long t2 = System.nanoTime();
    return new PermissionBlockResult(xS, normalizedPermissions.size(), parseNanos + (t2 - t1));
  }

  /** Dex header H only — skipped on Mode B early exit (A3). */
  public DexBlockResult extractDexBlock(File apkFile) throws Exception {
    DexHeaderFeatureExtractor.ExtractionResult dex = dexExtractor.extract(apkFile);
    return new DexBlockResult(
        dex.features, dex.dexFilesFound, dex.extractNanos + dex.normalizeNanos);
  }

  public DexBlockResult extractDexBlock(FeatureContext ctx) throws Exception {
    DexHeaderFeatureExtractor.ExtractionResult dex =
        dexExtractor.extractFromDexByteArrays(ctx.dexByteArrays());
    return new DexBlockResult(
        dex.features, dex.dexFilesFound, dex.extractNanos + dex.normalizeNanos);
  }

  public ExtractionResult extract(File apkFile) throws Exception {
    long t0 = System.nanoTime();
    List<String> normalizedPermissions = PermissionNormalizer.readNormalizedPermissions(apkFile);
    long t1 = System.nanoTime();
    return fuseBlocks(
        normalizedPermissions,
        t1 - t0,
        dexExtractor.extract(apkFile));
  }

  public ExtractionResult extract(FeatureContext ctx) throws Exception {
    return fuseBlocks(
        ctx.normalizedPermissions(),
        0L,
        dexExtractor.extractFromDexByteArrays(ctx.dexByteArrays()));
  }

  private ExtractionResult fuseBlocks(
      List<String> normalizedPermissions,
      long parseNanos,
      DexHeaderFeatureExtractor.ExtractionResult dex) {
    long t2 = System.nanoTime();
    float[] xS = buildXS(normalizedPermissions);
    long t3 = System.nanoTime();

    float[] x = fuse(xS, dex.features);
    long t4 = System.nanoTime();

    return new ExtractionResult(
        xS,
        dex.features,
        x,
        normalizedPermissions.size(),
        dex.dexFilesFound,
        parseNanos,
        dex.extractNanos + dex.normalizeNanos,
        (t3 - t2) + (t4 - t3));
  }

  /** Manifest-only helper for JVM tests (x_S block). */
  public ExtractionResult extractManifest(InputStream manifestStream) throws Exception {
    long t0 = System.nanoTime();
    List<String> rawPermissions = ManifestAxmlParser.extractManifestPermissions(manifestStream);
    List<String> normalizedPermissions = PermissionNormalizer.normalizePermissions(rawPermissions);
    long t1 = System.nanoTime();

    long t2 = System.nanoTime();
    float[] xS = buildXS(normalizedPermissions);
    float[] h = new float[hDim];
    float[] x = fuse(xS, h);
    long t3 = System.nanoTime();

    return new ExtractionResult(
        xS,
        h,
        x,
        normalizedPermissions.size(),
        0,
        t1 - t0,
        0L,
        t3 - t2);
  }

  public float[] buildXS(List<String> normalizedPermissions) {
    return PermissionNormalizer.buildBinaryVector(normalizedPermissions, mldpTokenToIndex, sDim);
  }

  public float[] fuse(float[] xS, float[] h) {
    if (xS.length != sDim) {
      throw new IllegalArgumentException("Expected x_S length " + sDim);
    }
    if (h.length != hDim) {
      throw new IllegalArgumentException("Expected H length " + hDim);
    }
    float[] fused = new float[dDim];
    System.arraycopy(xS, 0, fused, 0, sDim);
    System.arraycopy(h, 0, fused, sDim, hDim);
    return fused;
  }

  private static float[] jsonArrayToFloats(JSONArray arr) throws Exception {
    float[] values = new float[arr.length()];
    for (int i = 0; i < arr.length(); i++) {
      values[i] = (float) arr.getDouble(i);
    }
    return values;
  }
}
