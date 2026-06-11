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
 * A4: BM1 parity — ONNX on device vs PC export parity_samples (tolerance 1e-4).
 */
@RunWith(AndroidJUnit4.class)
public class MlpHeaderParityTest {

    private static final double TOLERANCE = 1e-4;
    private static final String PARITY_ASSET = "models/mlp_header/parity_samples/parity_vectors.json";

    @Test
    public void paritySamples_matchPcExport() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        String json = ModelAssetHelper.readAssetText(context, PARITY_ASSET);
        JSONObject root = new JSONObject(json);
        JSONArray vectors = root.getJSONArray("vectors");
        JSONArray expectedScores = root.getJSONArray("expected_scores");
        JSONArray sampleIds = root.optJSONArray("sample_ids");

        assertEquals("Expected 8 parity samples", 8, vectors.length());
        assertEquals(vectors.length(), expectedScores.length());

        OrtEnvironment env = OrtEnvironment.getEnvironment();
        MlpHeaderOnnxRunner runner = MlpHeaderOnnxRunner.create(context, env);
        try {
            double maxDiff = 0.0;
            for (int i = 0; i < vectors.length(); i++) {
                JSONArray row = vectors.getJSONArray(i);
                float[] features = new float[row.length()];
                for (int j = 0; j < row.length(); j++) {
                    features[j] = (float) row.getDouble(j);
                }
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
}
