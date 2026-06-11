package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * MLDP-pruned A1: manifest permissions only, normalized to permissions:: tokens,
 * binary float[1, |S|] aligned with features/selected_permissions.json (frozen set S).
 * Matches Python permission_extractor/src/features/permission_vector.py.
 */
public final class MldpPrunedPermissionExtractor {

  public static final int FEATURE_DIM = 40;
  public static final String VOCAB_ASSET =
      "models/mldp_pruned_permission/features/selected_permissions.json";

  private final Map<String, Integer> tokenToIndex;
  private final int vectorSize;

  public static final class ExtractionResult {
    public final float[] vector;
    public final int permissionCount;
    public final long extractNanos;
    public final long vectorizeNanos;

    ExtractionResult(float[] vector, int permissionCount, long extractNanos, long vectorizeNanos) {
      this.vector = vector;
      this.permissionCount = permissionCount;
      this.extractNanos = extractNanos;
      this.vectorizeNanos = vectorizeNanos;
    }
  }

  public MldpPrunedPermissionExtractor(Map<String, Integer> tokenToIndex, int vectorSize) {
    this.tokenToIndex = tokenToIndex;
    this.vectorSize = vectorSize;
  }

  public static MldpPrunedPermissionExtractor fromAssets(Context context) throws Exception {
    String json = ModelAssetHelper.readAssetText(context, VOCAB_ASSET);
    JSONObject root = new JSONObject(json);
    JSONArray permissions = root.getJSONArray("permissions");
    int vectorSize = root.optInt("S", permissions.length());
    if (vectorSize != FEATURE_DIM) {
      throw new IllegalStateException("Expected frozen set S " + FEATURE_DIM + ", got " + vectorSize);
    }
    Map<String, Integer> tokenToIndex = PermissionNormalizer.buildTokenToIndex(permissions);
    return new MldpPrunedPermissionExtractor(tokenToIndex, vectorSize);
  }

  public ExtractionResult extract(File apkFile) throws Exception {
    long t0 = System.nanoTime();
    List<String> tokens = PermissionNormalizer.readNormalizedPermissions(apkFile);
    long t1 = System.nanoTime();
    return vectorizePermissions(tokens, t1 - t0);
  }

  public ExtractionResult extract(FeatureContext ctx) {
    return vectorizePermissions(ctx.normalizedPermissions(), 0L);
  }

  private ExtractionResult vectorizePermissions(List<String> tokens, long parseNanos) {
    long t1 = System.nanoTime();
    float[] vector = buildBinaryVector(tokens);
    long t2 = System.nanoTime();
    return new ExtractionResult(vector, tokens.size(), parseNanos, t2 - t1);
  }

  float[] buildBinaryVector(List<String> normalizedTokens) {
    return PermissionNormalizer.buildBinaryVector(normalizedTokens, tokenToIndex, vectorSize);
  }
}
