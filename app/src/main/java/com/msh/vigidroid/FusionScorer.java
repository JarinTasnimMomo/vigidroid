package com.msh.vigidroid;

import com.msh.vigidroid.ModelRegistry;

/** Weighted score fusion using {@link CascadePolicy} fusion weights (L3 / C5). */
public final class FusionScorer {

  private FusionScorer() {}

  public static float legacyXgbCnnScore(CascadePolicy policy, float xgbScore, float cnnScore) {
    boolean hasXgb = xgbScore >= 0f;
    boolean hasCnn = cnnScore >= 0f;
    if (!hasXgb && !hasCnn) {
      return -1f;
    }
    if (hasXgb && !hasCnn) {
      return xgbScore;
    }
    if (!hasXgb) {
      return cnnScore;
    }
    double wXgb = policy.fusionWeightFor(ModelRegistry.MANIFEST_XGB.modelId);
    double wCnn = policy.fusionWeightFor(ModelRegistry.BYTECNN.modelId);
    double total = wXgb + wCnn;
    if (total <= 0.0) {
      return (xgbScore + cnnScore) / 2f;
    }
    return (float) ((wXgb * xgbScore + wCnn * cnnScore) / total);
  }

  public static String legacyDecision(float score) {
    if (score < 0f) {
      return null;
    }
    return score >= 0.5f ? "malware" : "benign";
  }
}
