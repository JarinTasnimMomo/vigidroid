package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONObject;

/** Malware decision threshold loaded from bundled thresholds.json. */
public final class ModelThresholds {

  public static final float DEFAULT_MALWARE_THRESHOLD = 0.5f;

  private final float malwareThreshold;
  private final String decisionVariant;
  private final String modelType;

  public ModelThresholds(float malwareThreshold, String decisionVariant, String modelType) {
    this.malwareThreshold = malwareThreshold;
    this.decisionVariant = decisionVariant;
    this.modelType = modelType;
  }

  public static ModelThresholds fromAsset(Context context, String assetPath) throws Exception {
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, assetPath));
    float malwareThreshold;
    if (root.has("malware_threshold")) {
      malwareThreshold = (float) root.getDouble("malware_threshold");
    } else if (root.has("tuned_val")) {
      malwareThreshold = (float) root.getDouble("tuned_val");
    } else {
      malwareThreshold = (float) root.optDouble("default", DEFAULT_MALWARE_THRESHOLD);
    }
    return new ModelThresholds(
        malwareThreshold,
        root.optString("decision_variant", "linregdroid1"),
        root.optString("model_type", "linear_svc"));
  }

  public float getMalwareThreshold() {
    return malwareThreshold;
  }

  /** LinRegDroid only; empty for MLDP bundles. */
  public String getDecisionVariant() {
    return decisionVariant;
  }

  /** MLDP only; linear_svc or tiny_mlp. */
  public String getModelType() {
    return modelType;
  }

  /** LinRegDroid1 / MLDP: malware when clamped or sigmoid probability >= threshold. */
  public boolean isMalware(float malwareProbability) {
    return malwareProbability >= malwareThreshold;
  }
}
