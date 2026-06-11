package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONObject;

/** Mode A + Mode B cascade thresholds from bundled thresholds.json. */
public final class MldpDexHeaderCascadeThresholds {

  public static final float DEFAULT_MALWARE_THRESHOLD = 0.5f;

  private final float modeADefault;
  private final float modeATuned;
  private final float stage1TLow;
  private final float stage1THigh;

  public MldpDexHeaderCascadeThresholds(
      float modeADefault,
      float modeATuned,
      float stage1TLow,
      float stage1THigh) {
    this.modeADefault = modeADefault;
    this.modeATuned = modeATuned;
    this.stage1TLow = stage1TLow;
    this.stage1THigh = stage1THigh;
  }

  public static MldpDexHeaderCascadeThresholds fromAsset(Context context, String assetPath)
      throws Exception {
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, assetPath));
    JSONObject modeA = root.optJSONObject("mode_a");
    JSONObject modeB = root.optJSONObject("mode_b");
    float defaultThreshold = DEFAULT_MALWARE_THRESHOLD;
    float tunedThreshold = DEFAULT_MALWARE_THRESHOLD;
    if (modeA != null) {
      defaultThreshold = (float) modeA.optDouble("default", DEFAULT_MALWARE_THRESHOLD);
      tunedThreshold = (float) modeA.optDouble("tuned_val", defaultThreshold);
    } else if (root.has("default")) {
      defaultThreshold = (float) root.optDouble("default", DEFAULT_MALWARE_THRESHOLD);
      tunedThreshold = (float) root.optDouble("tuned_val", defaultThreshold);
    }
    float tLow = 0f;
    float tHigh = 1f;
    if (modeB != null) {
      tLow = (float) modeB.optDouble("stage1_t_low", 0f);
      tHigh = (float) modeB.optDouble("stage1_t_high", 1f);
    }
    return new MldpDexHeaderCascadeThresholds(defaultThreshold, tunedThreshold, tLow, tHigh);
  }

  public float getModeADefault() {
    return modeADefault;
  }

  public float getModeATuned() {
    return modeATuned;
  }

  public float getStage1TLow() {
    return stage1TLow;
  }

  public float getStage1THigh() {
    return stage1THigh;
  }

  public boolean isMalwareModeA(float malwareProbability) {
    return malwareProbability >= modeATuned;
  }

  public boolean isMalwareStage2(float stage2Probability) {
    return stage2Probability >= modeATuned;
  }

  public boolean isEarlyExitBenign(float stage1Score) {
    return stage1Score <= stage1TLow;
  }

  public boolean isEarlyExitMalware(float stage1Score) {
    return stage1Score >= stage1THigh;
  }

  public boolean isUncertainBand(float stage1Score) {
    return stage1Score > stage1TLow && stage1Score < stage1THigh;
  }
}
