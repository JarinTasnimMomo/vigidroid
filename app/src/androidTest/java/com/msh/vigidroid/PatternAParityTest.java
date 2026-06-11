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
 * A4: Pattern A parity — ONNX on device vs PC export parity_samples (tolerance 1e-4).
 */
@RunWith(AndroidJUnit4.class)
public class PatternAParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final String PARITY_ASSET =
      "models/early_fusion_dex_manifest/parity_samples/parity_vectors.json";

  @Test
  public void paritySamples_matchPcExport() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    String json = ModelAssetHelper.readAssetText(context, PARITY_ASSET);
    JSONObject root = new JSONObject(json);
    JSONArray headers = root.getJSONArray("headers");
    JSONArray bows = root.getJSONArray("bows");
    JSONArray expectedScores = root.getJSONArray("expected_scores");
    JSONArray sampleIds = root.optJSONArray("sample_ids");

    assertEquals("Expected 8 parity samples", 8, headers.length());
    assertEquals(headers.length(), bows.length());
    assertEquals(headers.length(), expectedScores.length());

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    PatternAOnnxRunner runner = PatternAOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < headers.length(); i++) {
        float[] header = jsonRowToFloats(headers.getJSONArray(i));
        float[] bow = jsonRowToFloats(bows.getJSONArray(i));
        float score = runner.predict(header, bow);
        double expected = expectedScores.getDouble(i);
        double diff = Math.abs(score - expected);
        maxDiff = Math.max(maxDiff, diff);
        String label = sampleIds != null ? sampleIds.getString(i) : ("sample_" + i);
        assertEquals("Parity failed for " + label, expected, (double) score, TOLERANCE);
      }
      assertTrue("max diff should be < tolerance", maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  private static float[] jsonRowToFloats(JSONArray row) throws Exception {
    float[] values = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      values[i] = (float) row.getDouble(i);
    }
    return values;
  }
}
