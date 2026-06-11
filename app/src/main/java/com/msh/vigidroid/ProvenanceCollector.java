package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

/** Collect app + model bundle provenance for session metrics (A9). */
public final class ProvenanceCollector {

  private ProvenanceCollector() {}

  public static JSONObject buildSessionProvenance(Context context, CascadePolicy policy)
      throws Exception {
    JSONObject provenance = new JSONObject();
    provenance.put("app_version", BuildConfig.VERSION_NAME);
    if (policy != null) {
      provenance.put("cascade_policy", policy.getPolicyName());
      provenance.put("cascade_enabled", policy.isEnabled());
    }
    JSONArray models = new JSONArray();
    for (ModelRegistry.Entry entry : ModelRegistry.REGISTERED_MODELS) {
      JSONObject model = readManifestSummary(context, entry);
      if (model != null) {
        models.put(model);
      }
    }
    provenance.put("models", models);
    return provenance;
  }

  private static JSONObject readManifestSummary(Context context, ModelRegistry.Entry entry) {
    String manifestPath = entry.assetsPrefix + "export_manifest.json";
    try {
      JSONObject manifest = new JSONObject(ModelAssetHelper.readAssetText(context, manifestPath));
      JSONObject out = new JSONObject();
      out.put("model_id", entry.modelId);
      if (manifest.has("config_hash")) {
        out.put("config_hash", manifest.getString("config_hash"));
      }
      if (manifest.has("preprocessing_version")) {
        out.put("preprocessing_version", manifest.getString("preprocessing_version"));
      }
      if (manifest.has("val_f1")) {
        out.put("val_f1", manifest.getDouble("val_f1"));
      }
      if (manifest.has("val_accuracy")) {
        out.put("val_accuracy", manifest.getDouble("val_accuracy"));
      }
      return out;
    } catch (Exception ignored) {
      return null;
    }
  }
}
