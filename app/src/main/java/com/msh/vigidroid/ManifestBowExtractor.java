package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Early-fusion Dex+manifest BoW: permissions + intent actions/categories → multihot vector.
 * Matches Python full_combined_pipeline_approach src/features/manifest_bow.py.
 */
public final class ManifestBowExtractor {

  public static final int BOW_DIM = 4381;
  public static final String EARLY_FUSION_DEX_MANIFEST_VOCAB_ASSET =
      "models/early_fusion_dex_manifest/features/vocab.json";
  public static final String DUAL_BRANCH_DEX_MANIFEST_VOCAB_ASSET =
      "models/dual_branch_dex_manifest/features/vocab.json";

  private final Map<String, Integer> tokenToIndex;
  private final int unkIndex;
  private final int vectorSize;

  public static final class ExtractionResult {
    public final float[] bow;
    public final int tokenCount;
    public final long extractNanos;
    public final long vectorizeNanos;

    ExtractionResult(float[] bow, int tokenCount, long extractNanos, long vectorizeNanos) {
      this.bow = bow;
      this.tokenCount = tokenCount;
      this.extractNanos = extractNanos;
      this.vectorizeNanos = vectorizeNanos;
    }
  }

  public ManifestBowExtractor(Map<String, Integer> tokenToIndex, int unkIndex, int vectorSize) {
    this.tokenToIndex = tokenToIndex;
    this.unkIndex = unkIndex;
    this.vectorSize = vectorSize;
  }

  public static ManifestBowExtractor fromAssets(Context context) throws Exception {
    return fromAssets(context, EARLY_FUSION_DEX_MANIFEST_VOCAB_ASSET);
  }

  public static ManifestBowExtractor fromAssets(Context context, String vocabAsset) throws Exception {
    String json = ModelAssetHelper.readAssetText(context, vocabAsset);
    JSONObject root = new JSONObject(json);
    JSONObject mapping = root.getJSONObject("token_to_index");
    Map<String, Integer> tokenToIndex = new HashMap<>();
    Iterator<String> keys = mapping.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      tokenToIndex.put(key, mapping.getInt(key));
    }
    int unkIndex = root.getInt("unk_index");
    int vectorSize = root.optInt("vector_size", tokenToIndex.size() + 1);
    if (vectorSize != BOW_DIM) {
      throw new IllegalStateException("Expected vocab vector_size " + BOW_DIM + ", got " + vectorSize);
    }
    return new ManifestBowExtractor(tokenToIndex, unkIndex, vectorSize);
  }

  public ExtractionResult extract(File apkFile) throws Exception {
    long t0 = System.nanoTime();
    List<String> tokens = readManifestTokens(apkFile);
    long t1 = System.nanoTime();
    return vectorizeTokens(tokens, t1 - t0);
  }

  public ExtractionResult extract(FeatureContext ctx) throws Exception {
    return vectorizeTokens(ctx.manifestBowTokens(), 0L);
  }

  private ExtractionResult vectorizeTokens(List<String> tokens, long parseNanos) {
    long t1 = System.nanoTime();
    float[] bow = buildMultihot(tokens);
    long t2 = System.nanoTime();
    return new ExtractionResult(bow, tokens.size(), parseNanos, t2 - t1);
  }

  List<String> readManifestTokens(File apkFile) throws Exception {
    try (ZipFile zip = new ZipFile(apkFile)) {
      ZipEntry entry = zip.getEntry("AndroidManifest.xml");
      if (entry == null) {
        throw new IllegalStateException("AndroidManifest.xml not found in APK");
      }
      try (InputStream is = zip.getInputStream(entry)) {
        return ManifestAxmlParser.extractManifestTokens(is);
      }
    }
  }

  float[] buildMultihot(List<String> tokens) {
    float[] vec = new float[vectorSize];
    for (String token : tokens) {
      Integer idx = tokenToIndex.get(token);
      int index = idx != null ? idx : unkIndex;
      if (index >= 0 && index < vectorSize) {
        vec[index] = 1.0f;
      }
    }
    return vec;
  }
}
