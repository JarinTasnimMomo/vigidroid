package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Loads {@code assets/cascade_policy.json} — tiers, thresholds, fusion weights. */
public final class CascadePolicy {

  public static final String ASSET_PATH = "cascade_policy.json";

  public static final class Tier {
    public final int tier;
    public final List<String> models;
    public final double tLow;
    public final double tHigh;
    public final boolean conservativeMalwareOr;
    public final boolean mlpHeaderFallback;
    public final boolean finalTier;

    Tier(
        int tier,
        List<String> models,
        double tLow,
        double tHigh,
        boolean conservativeMalwareOr,
        boolean mlpHeaderFallback,
        boolean finalTier) {
      this.tier = tier;
      this.models = models;
      this.tLow = tLow;
      this.tHigh = tHigh;
      this.conservativeMalwareOr = conservativeMalwareOr;
      this.mlpHeaderFallback = mlpHeaderFallback;
      this.finalTier = finalTier;
    }
  }

  private final String policyName;
  private final String legacyEnsemblePolicy;
  private final boolean enabled;
  private final String tier3PatternModel;
  private final List<Tier> tiers;
  private final Map<String, Double> modelWeights;
  private final Map<String, Double> fusionWeights;

  private CascadePolicy(
      String policyName,
      String legacyEnsemblePolicy,
      boolean enabled,
      String tier3PatternModel,
      List<Tier> tiers,
      Map<String, Double> modelWeights,
      Map<String, Double> fusionWeights) {
    this.policyName = policyName;
    this.legacyEnsemblePolicy = legacyEnsemblePolicy;
    this.enabled = enabled;
    this.tier3PatternModel = tier3PatternModel;
    this.tiers = tiers;
    this.modelWeights = modelWeights;
    this.fusionWeights = fusionWeights;
  }

  public static CascadePolicy load(Context context) throws Exception {
    return fromJson(new JSONObject(ModelAssetHelper.readAssetText(context, ASSET_PATH)));
  }

  public static CascadePolicy disabledDefault() {
    return new CascadePolicy(
        "cascade_v1",
        "legacy_xgb_cnn",
        false,
        ModelRegistry.EARLY_FUSION_DEX_MANIFEST.modelId,
        Collections.emptyList(),
        Collections.emptyMap(),
        Collections.emptyMap());
  }

  static CascadePolicy fromJson(JSONObject root) throws Exception {
    String policyName = root.optString("policy_name", "cascade_v1");
    String legacyEnsemblePolicy = root.optString("legacy_ensemble_policy", "legacy_xgb_cnn");
    boolean enabled = root.optBoolean("enabled", false);
    String tier3Pattern =
        root.optString("tier3_pattern_model", ModelRegistry.EARLY_FUSION_DEX_MANIFEST.modelId);

    List<Tier> tiers = new ArrayList<>();
    JSONArray tierArr = root.getJSONArray("tiers");
    for (int i = 0; i < tierArr.length(); i++) {
      JSONObject tierObj = tierArr.getJSONObject(i);
      List<String> models = new ArrayList<>();
      JSONArray modelArr = tierObj.getJSONArray("models");
      for (int j = 0; j < modelArr.length(); j++) {
        models.add(modelArr.getString(j));
      }
      tiers.add(
          new Tier(
              tierObj.getInt("tier"),
              Collections.unmodifiableList(models),
              tierObj.optDouble("t_low", 0.15),
              tierObj.optDouble("t_high", 0.85),
              tierObj.optBoolean("conservative_malware_or", false),
              tierObj.optBoolean("mlp_header_fallback", false),
              tierObj.optBoolean("final", false)));
    }

    Map<String, Double> modelWeights = parseWeightMap(root.optJSONObject("model_weights"));
    Map<String, Double> fusionWeights = parseWeightMap(root.optJSONObject("fusion_weights"));

    return new CascadePolicy(
        policyName,
        legacyEnsemblePolicy,
        enabled,
        tier3Pattern,
        Collections.unmodifiableList(tiers),
        modelWeights,
        fusionWeights);
  }

  private static Map<String, Double> parseWeightMap(JSONObject obj) throws Exception {
    Map<String, Double> map = new HashMap<>();
    if (obj == null) {
      return map;
    }
    JSONArray names = obj.names();
    if (names == null) {
      return map;
    }
    for (int i = 0; i < names.length(); i++) {
      String key = names.getString(i);
      map.put(key, obj.optDouble(key, 1.0));
    }
    return map;
  }

  public String getPolicyName() {
    return policyName;
  }

  public String getLegacyEnsemblePolicy() {
    return legacyEnsemblePolicy;
  }

  public boolean isEnabled() {
    return enabled;
  }

  /** Runtime override for a scan session (UI / {@code EXTRA_CASCADE_ENABLED}). */
  public CascadePolicy withEnabled(boolean enabledOverride) {
    if (this.enabled == enabledOverride) {
      return this;
    }
    return new CascadePolicy(
        policyName,
        legacyEnsemblePolicy,
        enabledOverride,
        tier3PatternModel,
        tiers,
        modelWeights,
        fusionWeights);
  }

  public String getTier3PatternModel() {
    return tier3PatternModel;
  }

  public List<Tier> getTiers() {
    return tiers;
  }

  public Tier tier(int number) {
    for (Tier tier : tiers) {
      if (tier.tier == number) {
        return tier;
      }
    }
    return null;
  }

  public double weightFor(String modelId) {
    Double weight = modelWeights.get(modelId);
    if (weight != null) {
      return weight;
    }
    weight = fusionWeights.get(modelId);
    return weight != null ? weight : 1.0;
  }

  public double fusionWeightFor(String modelId) {
    Double weight = fusionWeights.get(modelId);
    if (weight != null) {
      return weight;
    }
    return weightFor(modelId);
  }
}
