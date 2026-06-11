package com.msh.vigidroid;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.InputStream;

import ai.onnxruntime.OrtEnvironment;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A4 — Full device parity gate for broadcast_mldp_hybrid.
 *
 * <p>Validates (1) Java manifest extraction vs PC parity vectors, (2) ONNX scores vs
 * {@code expected_prob} (±1e-4), and (3) end-to-end extract → infer on golden manifests.
 * Run before release: {@code Android_Works/run_broadcast_mldp_hybrid_a4.sh}
 */
@RunWith(AndroidJUnit4.class)
public class BroadcastMldpHybridA4ParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final String PARITY_VECTORS_ASSET =
      "models/broadcast_mldp_hybrid/parity_samples/parity_vectors.json";
  private static final String EXTRACTION_FIXTURES_ASSET =
      "models/broadcast_mldp_hybrid/parity_samples/parity_extraction_fixtures.json";
  private static final String MANIFEST_ASSET_PREFIX =
      "models/broadcast_mldp_hybrid/parity_samples/manifests/";

  @Test
  public void onnxInference_onBundledParityVectors_matchesPcExport() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, PARITY_VECTORS_ASSET));
    JSONArray vectors = root.getJSONArray("vectors");
    JSONArray expectedScores = root.getJSONArray("expected_malware_probability");
    JSONArray sampleIds = root.optJSONArray("sample_ids");

    assertEquals("Expected 10 parity samples", 10, vectors.length());
    assertEquals(vectors.length(), expectedScores.length());

    BroadcastMldpHybridExtractor.fromAssets(context);
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    BroadcastMldpHybridOnnxRunner runner = BroadcastMldpHybridOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < vectors.length(); i++) {
        float[] features = jsonRowToFloats(vectors.getJSONArray(i));
        assertEquals(BroadcastMldpHybridExtractor.FEATURE_DIM, features.length);

        float score = runner.predict(features);
        double expected = expectedScores.getDouble(i);
        maxDiff = Math.max(maxDiff, Math.abs(score - expected));
        String label = sampleIds != null ? sampleIds.getString(i) : ("sample_" + i);
        assertEquals("ONNX parity failed for " + label, expected, (double) score, TOLERANCE);
      }
      assertTrue("max ONNX diff should be < tolerance", maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  @Test
  public void manifestExtraction_matchesPcParityVectors_allTenSamples() throws Exception {
    Context context = TestAssetHelper.appContext();
    BroadcastMldpHybridExtractor extractor = BroadcastMldpHybridExtractor.fromAssets(context);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    assertEquals(BroadcastMldpHybridOnnxRunner.MODEL_ID, root.getString("model_id"));
    assertEquals(BroadcastMldpHybridOnnxRunner.DOMAIN, root.getString("domain"));

    JSONArray fixtures = root.getJSONArray("fixtures");
    assertEquals("Expected 10 extraction fixtures", 10, fixtures.length());

    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      float[] expected = jsonRowToFloats(fixture.getJSONArray("expected_vector"));

      try (InputStream is = TestAssetHelper.openTestAsset(MANIFEST_ASSET_PREFIX + sampleId + ".xml")) {
        BroadcastMldpHybridExtractor.ExtractionResult result = extractor.extractManifest(is);
        assertEquals(BroadcastMldpHybridExtractor.FEATURE_DIM, result.vector.length);
        assertArrayEquals(
            "Manifest vector mismatch for " + sampleId, expected, result.vector, 0f);
      }
    }
  }

  @Test
  public void endToEnd_extractAndInfer_matchesExpectedProb_allTenSamples() throws Exception {
    Context context = TestAssetHelper.appContext();
    BroadcastMldpHybridExtractor extractor = BroadcastMldpHybridExtractor.fromAssets(context);
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    BroadcastMldpHybridOnnxRunner runner = BroadcastMldpHybridOnnxRunner.create(context, env);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    JSONArray fixtures = root.getJSONArray("fixtures");

    try {
      double maxDiff = 0.0;
      for (int i = 0; i < fixtures.length(); i++) {
        JSONObject fixture = fixtures.getJSONObject(i);
        String sampleId = fixture.getString("sample_id");
        double expectedProb = fixture.getDouble("expected_malware_probability");

        try (InputStream is = TestAssetHelper.openTestAsset(MANIFEST_ASSET_PREFIX + sampleId + ".xml")) {
          BroadcastMldpHybridExtractor.ExtractionResult extraction = extractor.extractManifest(is);
          float score = runner.predict(extraction.vector);
          double diff = Math.abs(score - expectedProb);
          maxDiff = Math.max(maxDiff, diff);
          assertEquals(
              "End-to-end parity failed for " + sampleId, expectedProb, (double) score, TOLERANCE);
        }
      }
      assertTrue("max end-to-end diff should be < tolerance", maxDiff < TOLERANCE);
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
