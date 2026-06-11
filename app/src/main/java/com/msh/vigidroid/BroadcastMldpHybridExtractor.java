package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * A1 — Broadcast + MLDP hybrid manifest feature extractor.
 * Early-fused x = [x_S || x_R] aligned with broadcast_mldp_hybrid Python P2 vectorize.py.
 */
public final class BroadcastMldpHybridExtractor {

  public static final int S_DIM = 22;
  public static final int R_DIM = 70;
  public static final int FEATURE_DIM = 92;

  public static final String FEATURES_ASSET_PREFIX = "models/broadcast_mldp_hybrid/features/";
  public static final String MLDP_VOCAB_ASSET = FEATURES_ASSET_PREFIX + "mldp_permission_vocab.json";
  public static final String RECEIVER_VOCAB_ASSET =
      FEATURES_ASSET_PREFIX + "receiver_action_vocab.json";
  public static final String SYSTEM_ACTIONS_ASSET = FEATURES_ASSET_PREFIX + "system_actions.json";
  public static final String FEATURE_LAYOUT_ASSET = FEATURES_ASSET_PREFIX + "feature_layout.json";

  private final Map<String, Integer> mldpTokenToIndex;
  private final Map<String, Integer> receiverTokenToIndex;
  private final Set<String> systemActions;
  private final int sDim;
  private final int rDim;

  public static final class ExtractionResult {
    public final float[] vector;
    public final int permissionCount;
    public final int receiverActionCount;
    public final long parseNanos;
    public final long vectorizeNanos;

    ExtractionResult(
        float[] vector,
        int permissionCount,
        int receiverActionCount,
        long parseNanos,
        long vectorizeNanos) {
      this.vector = vector;
      this.permissionCount = permissionCount;
      this.receiverActionCount = receiverActionCount;
      this.parseNanos = parseNanos;
      this.vectorizeNanos = vectorizeNanos;
    }

    public long parseMs() {
      return parseNanos / 1_000_000L;
    }

    public long vectorizeMs() {
      return vectorizeNanos / 1_000_000L;
    }
  }

  public BroadcastMldpHybridExtractor(
      Map<String, Integer> mldpTokenToIndex,
      Map<String, Integer> receiverTokenToIndex,
      Set<String> systemActions,
      int sDim,
      int rDim) {
    this.mldpTokenToIndex = mldpTokenToIndex;
    this.receiverTokenToIndex = receiverTokenToIndex;
    this.systemActions = systemActions;
    this.sDim = sDim;
    this.rDim = rDim;
    if (sDim + rDim != FEATURE_DIM) {
      throw new IllegalArgumentException(
          "Expected S+R=" + FEATURE_DIM + ", got " + sDim + "+" + rDim);
    }
  }

  public static BroadcastMldpHybridExtractor fromAssets(Context context) throws Exception {
    JSONObject layout = new JSONObject(ModelAssetHelper.readAssetText(context, FEATURE_LAYOUT_ASSET));
    int sDim = layout.getInt("S");
    int rDim = layout.getInt("R");
    if (layout.getInt("total") != sDim + rDim) {
      throw new IllegalStateException("feature_layout.json total mismatch");
    }

    JSONObject mldpVocab = new JSONObject(ModelAssetHelper.readAssetText(context, MLDP_VOCAB_ASSET));
    JSONArray mldpTokens = mldpVocab.getJSONArray("tokens");
    Map<String, Integer> mldpIndex = PermissionNormalizer.buildTokenToIndex(mldpTokens);

    JSONObject receiverVocab =
        new JSONObject(ModelAssetHelper.readAssetText(context, RECEIVER_VOCAB_ASSET));
    JSONArray receiverTokens = receiverVocab.getJSONArray("tokens");
    Map<String, Integer> receiverIndex = buildReceiverTokenToIndex(receiverTokens);

    Set<String> systemActions = loadSystemActions(context);
    return new BroadcastMldpHybridExtractor(mldpIndex, receiverIndex, systemActions, sDim, rDim);
  }

  public static BroadcastMldpHybridExtractor fromAssetStrings(
      String mldpVocabJson,
      String receiverVocabJson,
      String systemActionsJson,
      String featureLayoutJson)
      throws Exception {
    JSONObject layout = new JSONObject(featureLayoutJson);
    int sDim = layout.getInt("S");
    int rDim = layout.getInt("R");

    JSONObject mldpVocab = new JSONObject(mldpVocabJson);
    Map<String, Integer> mldpIndex =
        PermissionNormalizer.buildTokenToIndex(mldpVocab.getJSONArray("tokens"));

    JSONObject receiverVocab = new JSONObject(receiverVocabJson);
    Map<String, Integer> receiverIndex =
        buildReceiverTokenToIndex(receiverVocab.getJSONArray("tokens"));

    Set<String> systemActions = loadSystemActionsFromJson(systemActionsJson);
    return new BroadcastMldpHybridExtractor(mldpIndex, receiverIndex, systemActions, sDim, rDim);
  }

  public ExtractionResult extract(File apkFile) throws Exception {
    long t0 = System.nanoTime();
    ManifestAxmlParser.HybridManifestFeatures parsed;
    try (ZipFile zip = new ZipFile(apkFile)) {
      ZipEntry entry = zip.getEntry("AndroidManifest.xml");
      if (entry == null) {
        throw new IllegalStateException("AndroidManifest.xml not found in APK");
      }
      try (InputStream is = zip.getInputStream(entry)) {
        parsed = ManifestAxmlParser.parseHybridManifest(is);
      }
    }
    long t1 = System.nanoTime();
    return vectorizeHybridManifest(parsed, t1 - t0);
  }

  public ExtractionResult extract(FeatureContext ctx) throws Exception {
    return vectorizeHybridManifest(ctx.hybridManifest(), 0L);
  }

  private ExtractionResult vectorizeHybridManifest(
      ManifestAxmlParser.HybridManifestFeatures parsed, long parseNanos) {
    List<String> normalizedPermissions = PermissionNormalizer.normalizePermissions(parsed.permissions);
    List<String> filteredActions = filterReceiverSystemActions(parsed.receiverActions);
    long t1 = System.nanoTime();
    float[] vector = buildHybridVector(normalizedPermissions, filteredActions);
    long t2 = System.nanoTime();
    return new ExtractionResult(
        vector,
        normalizedPermissions.size(),
        filteredActions.size(),
        parseNanos,
        t2 - t1);
  }

  /** Parse a standalone binary AndroidManifest.xml (test helper). */
  public ExtractionResult extractManifest(InputStream manifestStream) throws Exception {
    long t0 = System.nanoTime();
    ManifestAxmlParser.HybridManifestFeatures parsed =
        ManifestAxmlParser.parseHybridManifest(manifestStream);
    List<String> normalizedPermissions = PermissionNormalizer.normalizePermissions(parsed.permissions);
    List<String> filteredActions = filterReceiverSystemActions(parsed.receiverActions);
    long t1 = System.nanoTime();
    float[] vector = buildHybridVector(normalizedPermissions, filteredActions);
    long t2 = System.nanoTime();
    return new ExtractionResult(
        vector,
        normalizedPermissions.size(),
        filteredActions.size(),
        t1 - t0,
        t2 - t1);
  }

  public List<String> filterReceiverSystemActions(List<String> receiverActions) {
    List<String> out = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    for (String action : receiverActions) {
      if (action == null) {
        continue;
      }
      String name = action.trim();
      if (name.isEmpty() || !systemActions.contains(name) || !seen.add(name)) {
        continue;
      }
      out.add(name);
    }
    return out;
  }

  public float[] buildHybridVector(List<String> normalizedPermissions, List<String> receiverActions) {
    float[] xS =
        PermissionNormalizer.buildBinaryVector(normalizedPermissions, mldpTokenToIndex, sDim);
    float[] xR = buildReceiverBinaryVector(receiverActions);
    float[] fused = new float[FEATURE_DIM];
    System.arraycopy(xS, 0, fused, 0, sDim);
    System.arraycopy(xR, 0, fused, sDim, rDim);
    return fused;
  }

  private float[] buildReceiverBinaryVector(List<String> receiverActions) {
    float[] vec = new float[rDim];
    for (String action : receiverActions) {
      Integer idx = receiverTokenToIndex.get(action);
      if (idx != null && idx >= 0 && idx < rDim) {
        vec[idx] = 1.0f;
      }
    }
    return vec;
  }

  private static Map<String, Integer> buildReceiverTokenToIndex(JSONArray tokens) throws Exception {
    Map<String, Integer> tokenToIndex = new java.util.HashMap<>();
    for (int i = 0; i < tokens.length(); i++) {
      tokenToIndex.put(tokens.getString(i), i);
    }
    return tokenToIndex;
  }

  private static Set<String> loadSystemActions(Context context) throws Exception {
    return loadSystemActionsFromJson(ModelAssetHelper.readAssetText(context, SYSTEM_ACTIONS_ASSET));
  }

  static Set<String> loadSystemActionsFromJson(String json) throws Exception {
    JSONObject root = new JSONObject(json);
    JSONArray actions = root.getJSONArray("actions");
    Set<String> out = new HashSet<>();
    for (int i = 0; i < actions.length(); i++) {
      String action = actions.getString(i).trim();
      if (!action.isEmpty()) {
        out.add(action);
      }
    }
    if (out.isEmpty()) {
      throw new IllegalStateException("system_actions.json is empty");
    }
    return out;
  }
}
