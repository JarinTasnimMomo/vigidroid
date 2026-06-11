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
 * A4: LinRegDroid parity — Java ONNX runner on device vs PC export parity_samples (±1e-4).
 * Parity vectors were built with the same permission vocab + normalization as
 * {@link LinRegPermissionExtractor} on the training pipeline.
 */
@RunWith(AndroidJUnit4.class)
public class LinRegDroidParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final String PARITY_ASSET =
      "models/linregdroid_permission/parity_samples/parity_vectors.json";

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

    // Bundled vocab must load (same asset path as ScanService extractor).
    LinRegPermissionExtractor extractor = LinRegPermissionExtractor.fromAssets(context);
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    LinRegDroidOnnxRunner runner = LinRegDroidOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < vectors.length(); i++) {
        float[] features = jsonRowToFloats(vectors.getJSONArray(i));
        assertEquals(extractor.featureDim(), features.length);

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
