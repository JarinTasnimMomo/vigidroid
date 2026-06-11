package com.msh.vigidroid;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

import ai.onnxruntime.OrtEnvironment;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A4 — Full device parity gate for dexheader_broadcast_fusion.
 *
 * <p>Validates ONNX scores, APK extraction vs PC vectors, and end-to-end extract → infer.
 * Run before release: {@code Android_Works/run_dexheader_broadcast_fusion_a4.sh}
 */
@RunWith(AndroidJUnit4.class)
public class DexheaderBroadcastFusionA4ParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final float VECTOR_TOLERANCE = 1e-4f;
  private static final String PARITY_VECTORS_ASSET =
      "models/dexheader_broadcast_fusion/parity_samples/parity_onnx_vectors.json";
  private static final String EXTRACTION_FIXTURES_ASSET =
      "models/dexheader_broadcast_fusion/parity_samples/parity_extraction_fixtures.json";
  private static final String MLDP_APK_ASSET_PREFIX =
      "models/mldp_dexheader_cascade/parity_samples/apks/";

  @Test
  public void onnxInference_onBundledParityVectors_matchesPcExport() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, PARITY_VECTORS_ASSET));
    JSONArray headers = root.getJSONArray("headers");
    JSONArray receivers = root.getJSONArray("receivers");
    JSONArray expectedScores = root.getJSONArray("expected_malware_probability");
    JSONArray sampleIds = root.optJSONArray("sample_ids");

    assertEquals(10, headers.length());
    assertEquals(headers.length(), receivers.length());
    assertEquals(headers.length(), expectedScores.length());

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    DexheaderBroadcastFusionOnnxRunner runner =
        DexheaderBroadcastFusionOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < headers.length(); i++) {
        float[] h = ParityVectorAssert.jsonToFloats(headers.getJSONArray(i));
        float[] r = ParityVectorAssert.jsonToFloats(receivers.getJSONArray(i));
        float score = runner.predict(h, r);
        double expected = expectedScores.getDouble(i);
        maxDiff = Math.max(maxDiff, Math.abs(score - expected));
        String label = sampleIds != null ? sampleIds.getString(i) : ("sample_" + i);
        assertEquals("ONNX parity failed for " + label, expected, (double) score, TOLERANCE);
      }
      assertTrue(maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  @Test
  public void apkExtraction_matchesPcParityVectors_availableGoldenApks() throws Exception {
    Context context = TestAssetHelper.appContext();
    DexheaderBroadcastFusionExtractor extractor =
        DexheaderBroadcastFusionExtractor.fromAssets(context);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    assertEquals(DexheaderBroadcastFusionOnnxRunner.MODEL_ID, root.getString("model_id"));
    assertEquals(DexheaderBroadcastFusionOnnxRunner.DOMAIN, root.getString("domain"));

    JSONArray fixtures = root.getJSONArray("fixtures");
    float maxDiff = 0f;
    int tested = 0;
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      String wantSha = fixture.optString("sha256", "").toLowerCase();
      File apkFile = resolveGoldenApkBySha(context, sampleId, wantSha);
      if (apkFile == null) {
        continue;
      }
      tested++;
      float[] expectedHeader = ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_header"));
      float[] expectedReceiver =
          ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_receiver"));

      DexheaderBroadcastFusionExtractor.ExtractionResult result = extractor.extract(apkFile);
      maxDiff = Math.max(maxDiff, ParityVectorAssert.maxAbsDiff(expectedHeader, result.header));
      maxDiff = Math.max(maxDiff, ParityVectorAssert.maxAbsDiff(expectedReceiver, result.receiver));
      assertArrayEquals("header mismatch " + sampleId, expectedHeader, result.header, VECTOR_TOLERANCE);
      assertArrayEquals("receiver mismatch " + sampleId, expectedReceiver, result.receiver, VECTOR_TOLERANCE);
    }
    Assume.assumeTrue(
        "No golden APK with matching sha256 — bundle mldp parity APKs or skip extraction gate",
        tested > 0);
    assertTrue("max extraction diff", maxDiff <= VECTOR_TOLERANCE);
  }

  @Test
  public void endToEnd_extractAndInfer_matchesExpectedProb_availableGoldenApks() throws Exception {
    Context context = TestAssetHelper.appContext();
    DexheaderBroadcastFusionExtractor extractor =
        DexheaderBroadcastFusionExtractor.fromAssets(context);
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    DexheaderBroadcastFusionOnnxRunner runner =
        DexheaderBroadcastFusionOnnxRunner.create(context, env);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    JSONArray fixtures = root.getJSONArray("fixtures");

    try {
      double maxDiff = 0.0;
      int tested = 0;
      for (int i = 0; i < fixtures.length(); i++) {
        JSONObject fixture = fixtures.getJSONObject(i);
        String sampleId = fixture.getString("sample_id");
        String wantSha = fixture.optString("sha256", "").toLowerCase();
        File apkFile = resolveGoldenApkBySha(context, sampleId, wantSha);
        if (apkFile == null) {
          continue;
        }
        tested++;
        double expectedProb = fixture.getDouble("expected_malware_probability");
        DexheaderBroadcastFusionExtractor.ExtractionResult extraction = extractor.extract(apkFile);
        float score = runner.predict(extraction.header, extraction.receiver);
        maxDiff = Math.max(maxDiff, Math.abs(score - expectedProb));
        assertEquals(
            "End-to-end parity failed for " + sampleId, expectedProb, (double) score, TOLERANCE);
      }
      Assume.assumeTrue("No golden APK assets bundled", tested > 0);
      assertTrue(maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  /** Returns cached APK only when bundled asset sha256 matches the fusion parity fixture. */
  private static File resolveGoldenApkBySha(Context context, String sampleId, String wantSha)
      throws Exception {
    if (wantSha == null || wantSha.isEmpty()) {
      return null;
    }
    String apkAsset = MLDP_APK_ASSET_PREFIX + sampleId + ".apk";
    if (!TestAssetHelper.testAssetExists(apkAsset)) {
      return null;
    }
    File apkFile = copyApkAssetToCache(context, apkAsset);
    try (FeatureContext ctx = FeatureContext.open(apkFile)) {
      if (!wantSha.equalsIgnoreCase(ctx.sha256Hex())) {
        return null;
      }
    }
    return apkFile;
  }

  private static File copyApkAssetToCache(Context context, String assetPath) throws Exception {
    File out = new File(context.getCacheDir(), "fusion_a4_" + assetPath.replace('/', '_'));
    try (InputStream is = TestAssetHelper.openTestAsset(assetPath);
        FileOutputStream fos = new FileOutputStream(out)) {
      byte[] buf = new byte[8192];
      int read;
      while ((read = is.read(buf)) != -1) {
        fos.write(buf, 0, read);
      }
    }
    return out;
  }
}
