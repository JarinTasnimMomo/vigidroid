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
 * A1 — Dex header (BM1 norm) + static receiver system-action features for fusion model.
 * Semantics aligned with dexheader_broadcast_fusion Python P2.
 */
public final class DexheaderBroadcastFusionExtractor {

  public static final int H_DIM = DexHeaderFeatureExtractor.FEATURE_DIM;

  public static final String FEATURES_ASSET_PREFIX =
      "models/dexheader_broadcast_fusion/features/";
  public static final String NORMALIZATION_ASSET =
      FEATURES_ASSET_PREFIX + "normalization_header.json";
  public static final String RECEIVER_VOCAB_ASSET =
      FEATURES_ASSET_PREFIX + "receiver_action_vocab.json";
  public static final String SYSTEM_ACTIONS_ASSET = FEATURES_ASSET_PREFIX + "system_actions.json";
  public static final String FEATURE_LAYOUT_ASSET = FEATURES_ASSET_PREFIX + "feature_layout.json";

  private final DexHeaderFeatureExtractor dexExtractor;
  private final Map<String, Integer> receiverTokenToIndex;
  private final Set<String> systemActions;
  private final int rDim;

  public static final class ExtractionResult {
    public final float[] header;
    public final float[] receiver;
    public final int dexFilesFound;
    public final int receiverActionCount;
    public final long parseMs;
    public final long dexMs;
    public final long vectorizeMs;

    ExtractionResult(
        float[] header,
        float[] receiver,
        int dexFilesFound,
        int receiverActionCount,
        long parseNanos,
        long dexNanos,
        long vectorizeNanos) {
      this.header = header;
      this.receiver = receiver;
      this.dexFilesFound = dexFilesFound;
      this.receiverActionCount = receiverActionCount;
      this.parseMs = parseNanos / 1_000_000L;
      this.dexMs = dexNanos / 1_000_000L;
      this.vectorizeMs = vectorizeNanos / 1_000_000L;
    }
  }

  public DexheaderBroadcastFusionExtractor(
      DexHeaderFeatureExtractor dexExtractor,
      Map<String, Integer> receiverTokenToIndex,
      Set<String> systemActions,
      int rDim) {
    this.dexExtractor = dexExtractor;
    this.receiverTokenToIndex = receiverTokenToIndex;
    this.systemActions = systemActions;
    this.rDim = rDim;
  }

  public int getReceiverDim() {
    return rDim;
  }

  public static DexheaderBroadcastFusionExtractor fromAssets(Context context) throws Exception {
    JSONObject layout = new JSONObject(ModelAssetHelper.readAssetText(context, FEATURE_LAYOUT_ASSET));
    int rDim = layout.getInt("receiver");

    DexHeaderFeatureExtractor dexExtractor =
        DexHeaderFeatureExtractor.fromAssets(context, NORMALIZATION_ASSET);

    JSONObject receiverVocab =
        new JSONObject(ModelAssetHelper.readAssetText(context, RECEIVER_VOCAB_ASSET));
    Map<String, Integer> receiverIndex =
        buildReceiverTokenToIndex(receiverVocab.getJSONArray("tokens"));

    Set<String> systemActions =
        BroadcastMldpHybridExtractor.loadSystemActionsFromJson(
            ModelAssetHelper.readAssetText(context, SYSTEM_ACTIONS_ASSET));

    return new DexheaderBroadcastFusionExtractor(
        dexExtractor, receiverIndex, systemActions, rDim);
  }

  public static DexheaderBroadcastFusionExtractor fromAssetStrings(
      String normalizationJson,
      String receiverVocabJson,
      String systemActionsJson,
      String featureLayoutJson)
      throws Exception {
    JSONObject layout = new JSONObject(featureLayoutJson);
    int rDim = layout.getInt("receiver");

    JSONObject normRoot = new JSONObject(normalizationJson);
    float[] mins = jsonArrayToFloats(normRoot.getJSONArray("mins"));
    float[] maxs = jsonArrayToFloats(normRoot.getJSONArray("maxs"));
    DexHeaderFeatureExtractor dexExtractor = new DexHeaderFeatureExtractor(mins, maxs);

    JSONObject receiverVocab = new JSONObject(receiverVocabJson);
    Map<String, Integer> receiverIndex =
        buildReceiverTokenToIndex(receiverVocab.getJSONArray("tokens"));

    Set<String> systemActions =
        BroadcastMldpHybridExtractor.loadSystemActionsFromJson(systemActionsJson);

    return new DexheaderBroadcastFusionExtractor(
        dexExtractor, receiverIndex, systemActions, rDim);
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

    DexHeaderFeatureExtractor.ExtractionResult dex = dexExtractor.extract(apkFile);
    long t2 = System.nanoTime();

    List<String> filtered = filterReceiverSystemActions(parsed.receiverActions);
    float[] receiverVec = buildReceiverBinaryVector(filtered);
    long t3 = System.nanoTime();

    return new ExtractionResult(
        dex.features,
        receiverVec,
        dex.dexFilesFound,
        filtered.size(),
        t1 - t0,
        t2 - t1,
        t3 - t2);
  }

  public ExtractionResult extract(FeatureContext ctx) throws Exception {
    long t0 = System.nanoTime();
    DexHeaderFeatureExtractor.ExtractionResult dex =
        dexExtractor.extractFromDexByteArrays(ctx.dexByteArrays());
    long t1 = System.nanoTime();
    List<String> filtered = filterReceiverSystemActions(ctx.hybridManifest().receiverActions);
    float[] receiverVec = buildReceiverBinaryVector(filtered);
    long t2 = System.nanoTime();
    return new ExtractionResult(
        dex.features,
        receiverVec,
        dex.dexFilesFound,
        filtered.size(),
        0L,
        t1 - t0,
        t2 - t1);
  }

  List<String> filterReceiverSystemActions(List<String> receiverActions) {
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

  float[] buildReceiverBinaryVector(List<String> receiverActions) {
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

  private static float[] jsonArrayToFloats(JSONArray array) throws Exception {
    float[] out = new float[array.length()];
    for (int i = 0; i < array.length(); i++) {
      out[i] = (float) array.getDouble(i);
    }
    return out;
  }
}
