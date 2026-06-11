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
 * A4: MLDP pruned parity — Java ONNX runner on device vs PC export parity_samples (±1e-4).
 * Parity vectors align with {@link MldpPrunedPermissionExtractor} frozen set S=40.
 */
@RunWith(AndroidJUnit4.class)
public class MldpPrunedParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final String PARITY_ASSET =
      "models/mldp_pruned_permission/parity_samples/parity_vectors.json";
  private static final String MANIFEST_ASSET =
      "models/mldp_pruned_permission/export_manifest.json";

  @Test
  public void paritySamples_matchPcExport() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    String json = ModelAssetHelper.readAssetText(context, PARITY_ASSET);
    JSONObject root = new JSONObject(json);
    JSONArray vectors = root.getJSONArray("vectors");
    JSONArray expectedScores = root.getJSONArray("expected_malware_probability");
    JSONArray sampleIds = root.optJSONArray("sample_ids");

    assertEquals("Expected 10 parity samples", 10, vectors.length());
    assertEquals(vectors.length(), expectedScores.length());

    // Bundled frozen set S must load (same asset path as ScanService extractor).
    MldpPrunedPermissionExtractor.fromAssets(context);
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpPrunedOnnxRunner runner = MldpPrunedOnnxRunner.create(context, env);
    String expectedModelType =
        new JSONObject(ModelAssetHelper.readAssetText(context, MANIFEST_ASSET))
            .getString("model_type");
    try {
      assertEquals(expectedModelType, runner.getModelType());
      double maxDiff = 0.0;
      for (int i = 0; i < vectors.length(); i++) {
        float[] features = jsonRowToFloats(vectors.getJSONArray(i));
        assertEquals(MldpPrunedPermissionExtractor.FEATURE_DIM, features.length);

        float score = runner.predict(features);
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
