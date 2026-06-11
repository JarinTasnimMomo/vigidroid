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
 * A4 — Full device parity gate for mldp_dexheader_cascade (extract + ONNX ±1e-4).
 *
 * <p>Validates golden APK extraction, Mode A fused inference, Mode B cascade scores, and
 * end-to-end extract → infer on bundled parity APKs. Run before release:
 * {@code Android_Works/run_mldp_dexheader_a4.sh}
 */
@RunWith(AndroidJUnit4.class)
public class MldpDexHeaderA4ParityTest {

  private static final double TOLERANCE = 1e-4;
  private static final float VECTOR_TOLERANCE = 1e-4f;
  private static final String PARITY_VECTORS_ASSET =
      "models/mldp_dexheader_cascade/parity_samples/parity_onnx_vectors.json";
  private static final String EXTRACTION_FIXTURES_ASSET =
      "models/mldp_dexheader_cascade/parity_samples/parity_extraction_fixtures.json";
  private static final String APK_ASSET_PREFIX =
      "models/mldp_dexheader_cascade/parity_samples/apks/";

  @Test
  public void apkExtraction_matchesPcParityVectors_allGoldenApks() throws Exception {
    Context context = TestAssetHelper.appContext();
    MldpDexHeaderExtractor extractor = MldpDexHeaderExtractor.fromAssets(context);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    assertEquals(MldpDexHeaderExtractor.MODEL_FAMILY_ID, root.getString("model_id"));
    assertEquals(MldpDexHeaderExtractor.DOMAIN, root.getString("domain"));

    JSONArray fixtures = root.getJSONArray("fixtures");
    float maxDiff = 0f;
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      float[] expectedXS = jsonToFloats(fixture.getJSONArray("expected_x_s"));
      float[] expectedH = jsonToFloats(fixture.getJSONArray("expected_h"));
      float[] expectedX = jsonToFloats(fixture.getJSONArray("expected_x"));

      String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
      assumeApkAssetPresent(apkAsset);
      File apkFile = copyApkAssetToCache(context, apkAsset);

      MldpDexHeaderExtractor.ExtractionResult result = extractor.extract(apkFile);
      maxDiff = Math.max(maxDiff, maxAbsDiff(expectedXS, result.xS));
      maxDiff = Math.max(maxDiff, maxAbsDiff(expectedH, result.h));
      maxDiff = Math.max(maxDiff, maxAbsDiff(expectedX, result.x));

      assertArrayEquals("x_S mismatch for " + sampleId, expectedXS, result.xS, VECTOR_TOLERANCE);
      assertArrayEquals("H mismatch for " + sampleId, expectedH, result.h, VECTOR_TOLERANCE);
      assertArrayEquals("x mismatch for " + sampleId, expectedX, result.x, VECTOR_TOLERANCE);
    }
    assertTrue("max vector diff should be within tolerance", maxDiff <= VECTOR_TOLERANCE);
  }

  @Test
  public void modeA_onnxInference_matchesPcExport_allTenSamples() throws Exception {
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
  public void modeB_stage1AndStage2_onnxInference_matchesPcExport_allTenSamples() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root = new JSONObject(ModelAssetHelper.readAssetText(context, PARITY_VECTORS_ASSET));
    JSONArray xSVectors = root.getJSONArray("x_s_vectors");
    JSONArray hVectors = root.getJSONArray("h_vectors");
    JSONArray expectedS1 = root.getJSONArray("expected_stage1_prob");
    JSONArray expectedS2 = root.getJSONArray("expected_stage2_prob");

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpDexHeaderModeBOnnxRunner runner = MldpDexHeaderModeBOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < xSVectors.length(); i++) {
        float s1 = runner.predictStage1(jsonToFloats(xSVectors.getJSONArray(i)));
        float s2 = runner.predictStage2(jsonToFloats(hVectors.getJSONArray(i)));
        maxDiff = Math.max(maxDiff, Math.abs(s1 - expectedS1.getDouble(i)));
        maxDiff = Math.max(maxDiff, Math.abs(s2 - expectedS2.getDouble(i)));
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
      assertTrue(maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  @Test
  public void endToEnd_modeA_extractAndInfer_matchesExpectedProb_allGoldenApks() throws Exception {
    Context context = TestAssetHelper.appContext();
    MldpDexHeaderExtractor extractor = MldpDexHeaderExtractor.fromAssets(context);
    JSONObject fixturesRoot = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    JSONArray fixtures = fixturesRoot.getJSONArray("fixtures");

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpDexHeaderModeAOnnxRunner runner = MldpDexHeaderModeAOnnxRunner.create(context, env);
    try {
      double maxDiff = 0.0;
      for (int i = 0; i < fixtures.length(); i++) {
        JSONObject fixture = fixtures.getJSONObject(i);
        String sampleId = fixture.getString("sample_id");
        double expectedProb = fixture.getDouble("expected_mode_a_malware_prob");

        String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
        assumeApkAssetPresent(apkAsset);
        File apkFile = copyApkAssetToCache(context, apkAsset);

        MldpDexHeaderExtractor.ExtractionResult extraction = extractor.extract(apkFile);
        float score = runner.predict(extraction.x);
        double diff = Math.abs(score - expectedProb);
        maxDiff = Math.max(maxDiff, diff);
        assertEquals(
            "Mode A end-to-end parity failed for " + sampleId,
            expectedProb,
            (double) score,
            TOLERANCE);
      }
      assertTrue(maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  @Test
  public void endToEnd_modeB_cascade_matchesExpectedProb_allGoldenApks() throws Exception {
    Context context = TestAssetHelper.appContext();
    MldpDexHeaderExtractor extractor = MldpDexHeaderExtractor.fromAssets(context);
    JSONObject fixturesRoot = new JSONObject(TestAssetHelper.readTestAssetText(EXTRACTION_FIXTURES_ASSET));
    JSONArray fixtures = fixturesRoot.getJSONArray("fixtures");

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpDexHeaderModeBOnnxRunner runner = MldpDexHeaderModeBOnnxRunner.create(context, env);
    try {
      MldpDexHeaderCascadeThresholds thresholds = runner.getThresholds();
      double maxDiff = 0.0;
      for (int i = 0; i < fixtures.length(); i++) {
        JSONObject fixture = fixtures.getJSONObject(i);
        String sampleId = fixture.getString("sample_id");
        double expectedS1 = fixture.getDouble("expected_stage1_prob");
        double expectedS2 = fixture.getDouble("expected_stage2_prob");

        String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
        assumeApkAssetPresent(apkAsset);
        File apkFile = copyApkAssetToCache(context, apkAsset);

        MldpDexHeaderExtractor.PermissionBlockResult perm =
            extractor.extractPermissionBlock(apkFile);
        float s1 = runner.predictStage1(perm.xS);
        maxDiff = Math.max(maxDiff, Math.abs(s1 - expectedS1));
        assertEquals(
            "Mode B Stage-1 end-to-end failed for " + sampleId,
            expectedS1,
            (double) s1,
            TOLERANCE);

        if (!thresholds.isEarlyExitBenign(s1) && !thresholds.isEarlyExitMalware(s1)) {
          MldpDexHeaderExtractor.DexBlockResult dex = extractor.extractDexBlock(apkFile);
          float s2 = runner.predictStage2(dex.h);
          maxDiff = Math.max(maxDiff, Math.abs(s2 - expectedS2));
          assertEquals(
              "Mode B Stage-2 end-to-end failed for " + sampleId,
              expectedS2,
              (double) s2,
              TOLERANCE);
        }
      }
      assertTrue(maxDiff < TOLERANCE);
    } finally {
      runner.close();
    }
  }

  private static void assumeApkAssetPresent(String assetPath) throws Exception {
    if (!TestAssetHelper.testAssetExists(assetPath)) {
      Assume.assumeTrue(
          "Missing APK asset " + assetPath + " — run generate_a4_parity_fixtures.sh", false);
    }
  }

  private static File copyApkAssetToCache(Context context, String assetPath) throws Exception {
    File out = new File(context.getCacheDir(), "a4_parity_" + assetPath.replace('/', '_'));
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

  private static float maxAbsDiff(float[] expected, float[] actual) {
    float max = 0f;
    for (int i = 0; i < expected.length; i++) {
      max = Math.max(max, Math.abs(expected[i] - actual[i]));
    }
    return max;
  }

  private static float[] jsonToFloats(JSONArray row) throws Exception {
    float[] values = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      values[i] = (float) row.getDouble(i);
    }
    return values;
  }
}
