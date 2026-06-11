package com.msh.vigidroid.pipeline;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Locale;

/** Human-readable scan detail for the per-APK dialog (Phase 4). */
public final class ScanDetailFormatter {

  private ScanDetailFormatter() {}

  public static String format(String detailJson) {
    if (detailJson == null || detailJson.isEmpty()) {
      return "No stage detail available.";
    }
    try {
      JSONObject root = new JSONObject(detailJson);
      StringBuilder sb = new StringBuilder();
      appendTimingBlock(sb, root);
      appendEnsembleBlock(sb, root);
      appendCascadeBlock(sb, root);
      appendStagesBlock(sb, root);
      return sb.toString();
    } catch (Exception ex) {
      return detailJson;
    }
  }

  private static void appendTimingBlock(StringBuilder sb, JSONObject root) throws JSONException {
    if (!root.has("wall_ms")) {
      return;
    }
    double wall = root.optDouble("wall_ms", 0);
    double shared = root.optDouble("shared_parse_ms", 0);
    double total =
        root.has("total_ms") ? root.optDouble("total_ms", wall + shared) : wall + shared;
    sb.append(
        String.format(
            Locale.US,
            "stage_wall=%.1f ms  shared_parse=%.1f ms  total=%.1f ms%n",
            wall,
            shared,
            total));
  }

  private static void appendEnsembleBlock(StringBuilder sb, JSONObject root) throws JSONException {
    if (!root.has("ensemble_decision")) {
      return;
    }
    String decision = root.optString("ensemble_decision", "unknown");
    double score = root.optDouble("ensemble_score", -1);
    sb.append("Ensemble (list badge): ")
        .append(decision)
        .append("  score=")
        .append(String.format(Locale.US, "%.4f", score))
        .append('\n');
    if (!root.has("cascade")) {
      sb.append("  (legacy mode: weighted manifest_xgb + bytecnn only)\n");
    }
    sb.append('\n');
  }

  private static void appendCascadeBlock(StringBuilder sb, JSONObject root) throws JSONException {
    if (!root.has("cascade")) {
      return;
    }
    JSONObject cascade = root.getJSONObject("cascade");
    sb.append("Cascade policy: ").append(cascade.optString("policy")).append('\n');
    sb.append("  exit tier ")
        .append(cascade.optInt("exit_tier"))
        .append(" — ")
        .append(cascade.optString("exit_reason"))
        .append('\n');
    sb.append("  decision=")
        .append(cascade.optString("decision"))
        .append(" score=")
        .append(String.format(Locale.US, "%.4f", cascade.optDouble("final_score", -1)))
        .append('\n');
    appendIdList(sb, "  models_run", cascade.optJSONArray("models_run"));
    appendIdList(sb, "  models_skipped", cascade.optJSONArray("models_skipped"));
    sb.append('\n');
  }

  private static void appendStagesBlock(StringBuilder sb, JSONObject root) throws JSONException {
    JSONArray stages = root.optJSONArray("stages");
    if (stages == null) {
      return;
    }
    sb.append("Stages:\n");
    for (int i = 0; i < stages.length(); i++) {
      JSONObject stage = stages.getJSONObject(i);
      sb.append("  ")
          .append(stage.optString("model_id", stage.optString("domain")))
          .append(" [")
          .append(stage.optString("status"))
          .append("]\n");
      if (stage.has("score")) {
        sb.append("    score=")
            .append(String.format(Locale.US, "%.4f", stage.optDouble("score", -1)))
            .append('\n');
      }
      if (stage.optBoolean("early_exit", false)) {
        sb.append("    cascade early_exit=true");
        if (stage.has("mode")) {
          sb.append(" mode=").append(stage.optString("mode"));
        }
        sb.append('\n');
      }
      sb.append("    parse=")
          .append(String.format(Locale.US, "%.1f", stage.optDouble("parse_ms", 0)))
          .append("ms vec=")
          .append(String.format(Locale.US, "%.1f", stage.optDouble("vectorize_ms", 0)))
          .append("ms infer=")
          .append(String.format(Locale.US, "%.1f", stage.optDouble("inference_ms", 0)))
          .append("ms cpu=")
          .append(String.format(Locale.US, "%.1f", stage.optDouble("cpu_ms", 0)))
          .append("ms\n");
      if (stage.has("mem_delta_bytes")) {
        sb.append("    mem_delta=").append(stage.optLong("mem_delta_bytes", 0)).append(" bytes\n");
      }
      if (stage.has("error_message")) {
        sb.append("    error=").append(stage.optString("error_message")).append('\n');
      }
    }
  }

  private static void appendIdList(StringBuilder sb, String label, JSONArray arr)
      throws JSONException {
    if (arr == null || arr.length() == 0) {
      return;
    }
    sb.append(label).append(": ");
    for (int i = 0; i < arr.length(); i++) {
      if (i > 0) {
        sb.append(", ");
      }
      sb.append(arr.getString(i));
    }
    sb.append('\n');
  }
}
