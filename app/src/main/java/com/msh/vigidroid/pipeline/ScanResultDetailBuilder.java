package com.msh.vigidroid.pipeline;

import com.msh.vigidroid.ModelRegistry;

import org.json.JSONArray;
import org.json.JSONObject;

/** Compact JSON for L5 per-APK detail dialog. */
public final class ScanResultDetailBuilder {

  private ScanResultDetailBuilder() {}

  public static String toJson(ScanApkResult result) throws Exception {
    JSONObject root = new JSONObject();
    root.put("apk_sha256", result.apkSha256);
    root.put("wall_ms", result.wallMs);
    root.put("shared_parse_ms", result.sharedParseMs);
    root.put("total_ms", result.wallMs + result.sharedParseMs);
    root.put("ensemble_score", result.ensembleScore);
    root.put("ensemble_decision", result.ensembleDecision);

    JSONArray stages = new JSONArray();
    for (StageResult stage : result.stages) {
      JSONObject obj = new JSONObject();
      obj.put("domain", stage.domain);
      String modelId = stage.modelId;
      if (modelId == null || modelId.isEmpty()) {
        ModelRegistry.Entry entry = ModelRegistry.entryForDomain(stage.domain);
        if (entry != null) {
          modelId = entry.modelId;
        }
      }
      if (modelId != null) {
        obj.put("model_id", modelId);
      }
      obj.put("status", stage.status);
      if (stage.errorMessage != null) {
        obj.put("error_message", stage.errorMessage);
      }
      obj.put("parse_ms", stage.parseMs);
      obj.put("vectorize_ms", stage.vectorizeMs);
      obj.put("inference_ms", stage.inferenceMs);
      obj.put("cpu_ms", stage.cpuMs);
      if (stage.score >= 0f) {
        obj.put("score", stage.score);
      }
      obj.put("mem_delta_bytes", stage.memDeltaBytes);
      if (stage.cascade) {
        obj.put("mode", stage.cascadeMode);
        obj.put("dex_ms", stage.dexMs);
        if (stage.stage1Score >= 0f) {
          obj.put("stage1_score", stage.stage1Score);
        }
        if (stage.stage2Score >= 0f) {
          obj.put("stage2_score", stage.stage2Score);
        }
        obj.put("early_exit", stage.earlyExit);
      }
      stages.put(obj);
    }
    root.put("stages", stages);

    if (result.cascade != null) {
      JSONObject cascade = new JSONObject();
      cascade.put("policy", result.cascade.policyName);
      cascade.put("exit_tier", result.cascade.exitTier);
      cascade.put("exit_reason", result.cascade.exitReason);
      cascade.put("final_score", result.cascade.finalScore);
      cascade.put("decision", result.cascade.decision);
      cascade.put("models_run", new JSONArray(result.cascade.modelsRun));
      cascade.put("models_skipped", new JSONArray(result.cascade.modelsSkipped));
      root.put("cascade", cascade);
    }
    return root.toString();
  }
}
