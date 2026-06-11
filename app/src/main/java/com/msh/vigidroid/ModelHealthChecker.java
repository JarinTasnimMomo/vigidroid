package com.msh.vigidroid;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Debug-build ONNX parity checks (one vector per critical runner). */
public final class ModelHealthChecker {

  public static final double TOLERANCE = 1e-3;

  public static final class Result {
    public final String modelId;
    public final boolean ok;
    public final String detail;

    Result(String modelId, boolean ok, String detail) {
      this.modelId = modelId;
      this.ok = ok;
      this.detail = detail;
    }
  }

  private ModelHealthChecker() {}

  public static List<Result> runAll(
      Context context,
      MldpDexHeaderModeAOnnxRunner modeARunner,
      BroadcastMldpHybridOnnxRunner broadcastRunner,
      DexheaderBroadcastFusionOnnxRunner fusionRunner) {
    List<Result> results = new ArrayList<>();
    results.add(checkModeA(context, modeARunner));
    results.add(checkBroadcast(context, broadcastRunner));
    results.add(checkFusion(context, fusionRunner));
    return results;
  }

  private static Result checkModeA(Context context, MldpDexHeaderModeAOnnxRunner runner) {
    String modelId = "mldp_dexheader_cascade_mode_a";
    if (runner == null) {
      return new Result(modelId, false, "runner not loaded");
    }
    try {
      JSONObject root =
          new JSONObject(
              ModelAssetHelper.readAssetText(
                  context, "models/mldp_dexheader_cascade/parity_samples/parity_onnx_vectors.json"));
      float[] vector = jsonRowToFloats(root.getJSONArray("vectors").getJSONArray(0));
      double expected = root.getJSONArray("expected_mode_a_malware_prob").getDouble(0);
      float score = runner.predict(vector);
      double delta = Math.abs(score - expected);
      if (delta > TOLERANCE) {
        return new Result(
            modelId,
            false,
            String.format(Locale.US, "delta=%.6f expected=%.6f got=%.6f", delta, expected, score));
      }
      return new Result(modelId, true, String.format(Locale.US, "score=%.6f", score));
    } catch (Exception ex) {
      return new Result(modelId, false, ex.getMessage());
    }
  }

  private static Result checkBroadcast(Context context, BroadcastMldpHybridOnnxRunner runner) {
    String modelId = "broadcast_mldp_hybrid";
    if (runner == null) {
      return new Result(modelId, false, "runner not loaded");
    }
    try {
      JSONObject root =
          new JSONObject(
              ModelAssetHelper.readAssetText(
                  context, "models/broadcast_mldp_hybrid/parity_samples/parity_onnx_vectors.json"));
      float[] vector = jsonRowToFloats(root.getJSONArray("vectors").getJSONArray(0));
      double expected = root.getJSONArray("expected_malware_probability").getDouble(0);
      float score = runner.predict(vector);
      double delta = Math.abs(score - expected);
      if (delta > TOLERANCE) {
        return new Result(
            modelId,
            false,
            String.format(Locale.US, "delta=%.6f expected=%.6f got=%.6f", delta, expected, score));
      }
      return new Result(modelId, true, String.format(Locale.US, "score=%.6f", score));
    } catch (Exception ex) {
      return new Result(modelId, false, ex.getMessage());
    }
  }

  private static Result checkFusion(Context context, DexheaderBroadcastFusionOnnxRunner runner) {
    String modelId = "dexheader_broadcast_fusion";
    if (runner == null) {
      return new Result(modelId, false, "runner not loaded");
    }
    try {
      JSONObject root =
          new JSONObject(
              ModelAssetHelper.readAssetText(
                  context,
                  "models/dexheader_broadcast_fusion/parity_samples/parity_onnx_vectors.json"));
      JSONArray hRow = root.getJSONArray("H").getJSONArray(0);
      JSONArray rRow = root.getJSONArray("R").getJSONArray(0);
      float[] h = jsonRowToFloats(hRow);
      float[] r = jsonRowToFloats(rRow);
      double expected = root.getJSONArray("expected_malware_probability").getDouble(0);
      float score = runner.predict(h, r);
      double delta = Math.abs(score - expected);
      if (delta > TOLERANCE) {
        return new Result(
            modelId,
            false,
            String.format(Locale.US, "delta=%.6f expected=%.6f got=%.6f", delta, expected, score));
      }
      return new Result(modelId, true, String.format(Locale.US, "score=%.6f", score));
    } catch (Exception ex) {
      return new Result(modelId, false, ex.getMessage());
    }
  }

  private static float[] jsonRowToFloats(JSONArray row) throws org.json.JSONException {
    float[] out = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      out[i] = (float) row.getDouble(i);
    }
    return out;
  }
}
