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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A1 — Instrumented extraction parity on 3 APKs vs Python dumps.
 *
 * <p>Run fixture generator first:
 * {@code mldp_dexheader_cascade/scripts/generate_a1_parity_fixtures.sh}
 */
@RunWith(AndroidJUnit4.class)
public class MldpDexHeaderA1ParityTest {

  private static final float TOLERANCE = 1e-4f;
  private static final String FIXTURES_ASSET =
      "models/mldp_dexheader_cascade/parity_samples/parity_extraction_fixtures.json";
  private static final String APK_ASSET_PREFIX =
      "models/mldp_dexheader_cascade/parity_samples/apks/";

  @Test
  public void apkExtraction_matchesPythonDump_allThreeSamples() throws Exception {
    Context context = TestAssetHelper.appContext();
    MldpDexHeaderExtractor extractor = MldpDexHeaderExtractor.fromAssets(context);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(FIXTURES_ASSET));
    JSONArray fixtures = root.getJSONArray("fixtures");
    assertEquals("Expected 3 A1 fixtures", 3, fixtures.length());

    float maxDiff = 0f;
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      float[] expectedXS = jsonToFloats(fixture.getJSONArray("expected_x_s"));
      float[] expectedH = jsonToFloats(fixture.getJSONArray("expected_h"));
      float[] expectedX = jsonToFloats(fixture.getJSONArray("expected_x"));

      String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
      if (!TestAssetHelper.testAssetExists(apkAsset)) {
        Assume.assumeTrue(
            "Missing APK asset " + apkAsset + " — run generate_a1_parity_fixtures.sh",
            false);
      }
      File apkFile = copyApkAssetToCache(context, apkAsset);

      MldpDexHeaderExtractor.ExtractionResult result = extractor.extract(apkFile);
      assertEquals(MldpDexHeaderExtractor.S_DIM, result.xS.length);
      assertEquals(MldpDexHeaderExtractor.H_DIM, result.h.length);
      assertEquals(MldpDexHeaderExtractor.D_DIM, result.x.length);
      assertTrue("Expected at least one dex file", result.dexFilesFound > 0);

      maxDiff = Math.max(maxDiff, maxAbsDiff(expectedXS, result.xS));
      maxDiff = Math.max(maxDiff, maxAbsDiff(expectedH, result.h));
      maxDiff = Math.max(maxDiff, maxAbsDiff(expectedX, result.x));

      assertArrayEquals(
          "x_S mismatch for " + sampleId, expectedXS, result.xS, TOLERANCE);
      assertArrayEquals("H mismatch for " + sampleId, expectedH, result.h, TOLERANCE);
      assertArrayEquals("x mismatch for " + sampleId, expectedX, result.x, TOLERANCE);
    }
    assertTrue("max vector diff should be within tolerance", maxDiff <= TOLERANCE);
  }

  private static File copyApkAssetToCache(Context context, String assetPath) throws Exception {
    File out = new File(context.getCacheDir(), "a1_parity_" + assetPath.replace('/', '_'));
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
