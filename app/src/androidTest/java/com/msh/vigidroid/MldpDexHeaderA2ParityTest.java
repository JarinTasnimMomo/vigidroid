package com.msh.vigidroid;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import ai.onnxruntime.OrtEnvironment;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A2 — Device ONNX parity for Mode A + Mode B cascade vs PC export expected_prob.
 *
 * <p>Run on device/emulator after {@code generate_a2_parity_vectors.py}.
 */
@RunWith(AndroidJUnit4.class)
public class MldpDexHeaderA2ParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final String PARITY_VECTORS_ASSET =
      "models/mldp_dexheader_cascade/parity_samples/parity_onnx_vectors.json";

  @Test
  public void modeA_onnxInference_matchesPcExport() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, PARITY_VECTORS_ASSET));
    JSONArray vectors = root.getJSONArray("vectors");
    JSONArray expected = root.getJSONArray("expected_mode_a_malware_prob");

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpDexHeaderModeAOnnxRunner runner = MldpDexHeaderModeAOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < vectors.length(); i++) {
        float score = runner.predict(jsonToFloats(vectors.getJSONArray(i)));
        double want = expected.getDouble(i);
        maxDiff = Math.max(maxDiff, Math.abs(score - want));
        assertEquals("Mode A ONNX parity failed at index " + i, want, (double) score, TOLERANCE);
      }
      assertTrue(maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  @Test
  public void modeB_stage1AndStage2_onnxInference_matchesPcExport() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, PARITY_VECTORS_ASSET));
    JSONArray xSVectors = root.getJSONArray("x_s_vectors");
    JSONArray hVectors = root.getJSONArray("h_vectors");
    JSONArray expectedS1 = root.getJSONArray("expected_stage1_prob");
    JSONArray expectedS2 = root.getJSONArray("expected_stage2_prob");

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpDexHeaderModeBOnnxRunner runner = MldpDexHeaderModeBOnnxRunner.create(context, env);
    try {
      for (int i = 0; i < xSVectors.length(); i++) {
        float s1 = runner.predictStage1(jsonToFloats(xSVectors.getJSONArray(i)));
        float s2 = runner.predictStage2(jsonToFloats(hVectors.getJSONArray(i)));
        assertEquals(
            "Stage-1 ONNX parity failed at index " + i,
            expectedS1.getDouble(i),
            (double) s1,
            TOLERANCE);
        assertEquals(
            "Stage-2 ONNX parity failed at index " + i,
            expectedS2.getDouble(i),
            (double) s2,
            TOLERANCE);
      }
    } finally {
      runner.close();
    }
  }

  @Test
  public void modeB_cascadeGate_respectsThresholdBands() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, PARITY_VECTORS_ASSET));
    JSONArray xSVectors = root.getJSONArray("x_s_vectors");
    MldpDexHeaderModeBOnnxRunner runner = MldpDexHeaderModeBOnnxRunner.create(context, OrtEnvironment.getEnvironment());
    try {
      MldpDexHeaderCascadeThresholds thresholds = runner.getThresholds();
      for (int i = 0; i < xSVectors.length(); i++) {
        MldpDexHeaderModeBOnnxRunner.CascadeResult gate =
            runner.predictStage1Gate(jsonToFloats(xSVectors.getJSONArray(i)));
        if (gate.stage1Score <= thresholds.getStage1TLow()) {
          assertEquals(MldpDexHeaderModeBOnnxRunner.EarlyExitKind.BENIGN, gate.earlyExitKind);
          assertTrue(gate.skippedDex);
        } else if (gate.stage1Score >= thresholds.getStage1THigh()) {
          assertEquals(MldpDexHeaderModeBOnnxRunner.EarlyExitKind.MALWARE, gate.earlyExitKind);
          assertTrue(gate.skippedDex);
        }
      }
    } finally {
      runner.close();
    }
  }

  private static float[] jsonToFloats(JSONArray row) throws Exception {
    float[] values = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      values[i] = (float) row.getDouble(i);
    }
    return values;
  }
}
