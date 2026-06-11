package com.msh.vigidroid;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Phase 2 — {@link FeatureContext} extraction parity (step 2.1).
 *
 * <p>Golden APKs: bundled under androidTest mldp_dexheader cascade parity samples. Eval APK:
 * {@code scan_1514_malware.apk} on device (see {@link EvalApkPaths}).
 */
@RunWith(AndroidJUnit4.class)
public class Phase2FeatureContextExtractionTest {

  private static final String MLDP_FIXTURES =
      "models/mldp_dexheader_cascade/parity_samples/parity_extraction_fixtures.json";
  private static final String BROADCAST_FIXTURES =
      "models/broadcast_mldp_hybrid/parity_samples/parity_extraction_fixtures.json";
  private static final String APK_ASSET_PREFIX =
      "models/mldp_dexheader_cascade/parity_samples/apks/";
  private static final String PHASE2_EVAL_FIXTURE =
      "phase2/scan_1514_extraction_fixture.json";

  @Test
  public void mldpDexheader_featureContext_matchesFileAndPcFixtures_goldenApks()
      throws Exception {
    var context = TestAssetHelper.appContext();
    MldpDexHeaderExtractor extractor = MldpDexHeaderExtractor.fromAssets(context);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(MLDP_FIXTURES));
    JSONArray fixtures = root.getJSONArray("fixtures");

    float maxPcDiff = 0f;
    float maxPathDiff = 0f;
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
      assumeApkAssetPresent(apkAsset);
      File apkFile = copyApkAssetToCache(context, apkAsset);

      MldpDexHeaderExtractor.ExtractionResult fromFile = extractor.extract(apkFile);
      try (FeatureContext ctx = FeatureContext.open(apkFile)) {
        MldpDexHeaderExtractor.ExtractionResult fromCtx = extractor.extract(ctx);
        maxPathDiff =
            Math.max(maxPathDiff, ParityVectorAssert.maxAbsDiff(fromFile.x, fromCtx.x));
        maxPathDiff =
            Math.max(maxPathDiff, ParityVectorAssert.maxAbsDiff(fromFile.xS, fromCtx.xS));
        maxPathDiff =
            Math.max(maxPathDiff, ParityVectorAssert.maxAbsDiff(fromFile.h, fromCtx.h));

        ParityVectorAssert.assertWithinTolerance(
            "FeatureContext vs File x for " + sampleId,
            fromFile.x,
            fromCtx.x,
            ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);

        float[] expectedX = ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_x"));
        maxPcDiff =
            Math.max(
                maxPcDiff, ParityVectorAssert.maxAbsDiff(expectedX, fromCtx.x));
        ParityVectorAssert.assertWithinTolerance(
            "FeatureContext vs PC x for " + sampleId,
            expectedX,
            fromCtx.x,
            ParityVectorAssert.PC_TOLERANCE);
      }
    }
    assertTrue("max File vs FeatureContext diff", maxPathDiff <= ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
    assertTrue("max PC diff", maxPcDiff <= ParityVectorAssert.PC_TOLERANCE);
  }

  @Test
  public void broadcastHybrid_featureContext_matchesFileAndPcFixtures_goldenApks()
      throws Exception {
    var context = TestAssetHelper.appContext();
    BroadcastMldpHybridExtractor extractor = BroadcastMldpHybridExtractor.fromAssets(context);
    JSONObject broadcastRoot =
        new JSONObject(TestAssetHelper.readTestAssetText(BROADCAST_FIXTURES));
    JSONObject mldpRoot = new JSONObject(TestAssetHelper.readTestAssetText(MLDP_FIXTURES));
    JSONArray apkFixtures = mldpRoot.getJSONArray("fixtures");

    float maxPcDiff = 0f;
    float maxPathDiff = 0f;
    for (int i = 0; i < apkFixtures.length(); i++) {
      String sampleId = apkFixtures.getJSONObject(i).getString("sample_id");
      JSONObject fixture = findFixtureBySampleId(broadcastRoot.getJSONArray("fixtures"), sampleId);
      String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
      assumeApkAssetPresent(apkAsset);
      File apkFile = copyApkAssetToCache(context, apkAsset);

      BroadcastMldpHybridExtractor.ExtractionResult fromFile = extractor.extract(apkFile);
      try (FeatureContext ctx = FeatureContext.open(apkFile)) {
        BroadcastMldpHybridExtractor.ExtractionResult fromCtx = extractor.extract(ctx);
        maxPathDiff =
            Math.max(
                maxPathDiff,
                ParityVectorAssert.maxAbsDiff(fromFile.vector, fromCtx.vector));
        ParityVectorAssert.assertWithinTolerance(
            "FeatureContext vs File for " + sampleId,
            fromFile.vector,
            fromCtx.vector,
            ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);

        float[] expected =
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_vector"));
        maxPcDiff =
            Math.max(
                maxPcDiff, ParityVectorAssert.maxAbsDiff(expected, fromCtx.vector));
        ParityVectorAssert.assertWithinTolerance(
            "FeatureContext vs PC for " + sampleId,
            expected,
            fromCtx.vector,
            ParityVectorAssert.PC_TOLERANCE);
      }
    }
    assertTrue("max File vs FeatureContext diff", maxPathDiff <= ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
    assertTrue("max PC diff", maxPcDiff <= ParityVectorAssert.PC_TOLERANCE);
  }

  @Test
  public void dexFusion_featureContext_matchesFile_goldenApks() throws Exception {
    var context = TestAssetHelper.appContext();
    DexheaderBroadcastFusionExtractor extractor =
        DexheaderBroadcastFusionExtractor.fromAssets(context);
    JSONObject root = new JSONObject(TestAssetHelper.readTestAssetText(MLDP_FIXTURES));
    JSONArray fixtures = root.getJSONArray("fixtures");

    float maxPathDiff = 0f;
    for (int i = 0; i < fixtures.length(); i++) {
      String sampleId = fixtures.getJSONObject(i).getString("sample_id");
      String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
      assumeApkAssetPresent(apkAsset);
      File apkFile = copyApkAssetToCache(context, apkAsset);

      DexheaderBroadcastFusionExtractor.ExtractionResult fromFile = extractor.extract(apkFile);
      try (FeatureContext ctx = FeatureContext.open(apkFile)) {
        DexheaderBroadcastFusionExtractor.ExtractionResult fromCtx = extractor.extract(ctx);
        maxPathDiff =
            Math.max(
                maxPathDiff,
                ParityVectorAssert.maxAbsDiff(fromFile.header, fromCtx.header));
        maxPathDiff =
            Math.max(
                maxPathDiff,
                ParityVectorAssert.maxAbsDiff(fromFile.receiver, fromCtx.receiver));
        ParityVectorAssert.assertWithinTolerance(
            "header File vs FeatureContext " + sampleId,
            fromFile.header,
            fromCtx.header,
            ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
        ParityVectorAssert.assertWithinTolerance(
            "receiver File vs FeatureContext " + sampleId,
            fromFile.receiver,
            fromCtx.receiver,
            ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
        assertEquals(70, fromCtx.receiver.length);
      }
    }
    assertTrue("max File vs FeatureContext diff", maxPathDiff <= ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
  }

  @Test
  public void dexFusion_featureContext_matchesPcFixtures_whenBundled() throws Exception {
    if (!TestAssetHelper.testAssetExists("phase2/fusion_extraction_fixtures.json")) {
      Assume.assumeTrue("Run generate_phase2_extraction_fixtures.sh to enable PC fusion parity", false);
    }
    var context = TestAssetHelper.appContext();
    DexheaderBroadcastFusionExtractor extractor =
        DexheaderBroadcastFusionExtractor.fromAssets(context);
    JSONObject root =
        new JSONObject(TestAssetHelper.readTestAssetText("phase2/fusion_extraction_fixtures.json"));
    JSONArray fixtures = root.getJSONArray("fixtures");

    float maxPcDiff = 0f;
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      String apkAsset = APK_ASSET_PREFIX + sampleId + ".apk";
      assumeApkAssetPresent(apkAsset);
      File apkFile = copyApkAssetToCache(context, apkAsset);

      try (FeatureContext ctx = FeatureContext.open(apkFile)) {
        DexheaderBroadcastFusionExtractor.ExtractionResult result = extractor.extract(ctx);
        float[] expectedHeader =
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_header"));
        float[] expectedReceiver =
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_receiver"));
        maxPcDiff =
            Math.max(maxPcDiff, ParityVectorAssert.maxAbsDiff(expectedHeader, result.header));
        maxPcDiff =
            Math.max(maxPcDiff, ParityVectorAssert.maxAbsDiff(expectedReceiver, result.receiver));
        ParityVectorAssert.assertWithinTolerance(
            "fusion header PC " + sampleId,
            expectedHeader,
            result.header,
            ParityVectorAssert.PC_TOLERANCE);
        ParityVectorAssert.assertWithinTolerance(
            "fusion receiver PC " + sampleId,
            expectedReceiver,
            result.receiver,
            ParityVectorAssert.PC_TOLERANCE);
      }
    }
    assertTrue("max PC fusion diff", maxPcDiff <= ParityVectorAssert.PC_TOLERANCE);
  }

  @Test
  public void evalApk_scan1514_featureContext_matchesFile_allThreeFamilies() throws Exception {
    var context = TestAssetHelper.appContext();
    File apk = EvalApkPaths.resolveScan1514(context);
    Assume.assumeTrue("Missing scan_1514 — run run_p1_exit_scan.sh", apk.isFile());

    MldpDexHeaderExtractor mldp = MldpDexHeaderExtractor.fromAssets(context);
    BroadcastMldpHybridExtractor broadcast = BroadcastMldpHybridExtractor.fromAssets(context);
    DexheaderBroadcastFusionExtractor fusion =
        DexheaderBroadcastFusionExtractor.fromAssets(context);

    MldpDexHeaderExtractor.ExtractionResult mldpFile = mldp.extract(apk);
    BroadcastMldpHybridExtractor.ExtractionResult broadcastFile = broadcast.extract(apk);
    DexheaderBroadcastFusionExtractor.ExtractionResult fusionFile = fusion.extract(apk);

    try (FeatureContext ctx = FeatureContext.open(apk)) {
      ParityVectorAssert.assertWithinTolerance(
          "mldp x File vs FeatureContext",
          mldpFile.x,
          mldp.extract(ctx).x,
          ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
      ParityVectorAssert.assertWithinTolerance(
          "broadcast File vs FeatureContext",
          broadcastFile.vector,
          broadcast.extract(ctx).vector,
          ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
      DexheaderBroadcastFusionExtractor.ExtractionResult fusionCtx = fusion.extract(ctx);
      ParityVectorAssert.assertWithinTolerance(
          "fusion header File vs FeatureContext",
          fusionFile.header,
          fusionCtx.header,
          ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
      ParityVectorAssert.assertWithinTolerance(
          "fusion receiver File vs FeatureContext",
          fusionFile.receiver,
          fusionCtx.receiver,
          ParityVectorAssert.FEATURE_CONTEXT_TOLERANCE);
    }

    if (TestAssetHelper.testAssetExists(PHASE2_EVAL_FIXTURE)) {
      JSONObject fixture = new JSONObject(TestAssetHelper.readTestAssetText(PHASE2_EVAL_FIXTURE));
      try (FeatureContext ctx = FeatureContext.open(apk)) {
        MldpDexHeaderExtractor.ExtractionResult mldpCtx = mldp.extract(ctx);
        ParityVectorAssert.assertWithinTolerance(
            "scan_1514 mldp x vs PC",
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_mldp_x")),
            mldpCtx.x,
            ParityVectorAssert.PC_TOLERANCE);
        ParityVectorAssert.assertWithinTolerance(
            "scan_1514 broadcast vs PC",
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_broadcast_vector")),
            broadcast.extract(ctx).vector,
            ParityVectorAssert.PC_TOLERANCE);
        DexheaderBroadcastFusionExtractor.ExtractionResult fusionCtx = fusion.extract(ctx);
        ParityVectorAssert.assertWithinTolerance(
            "scan_1514 fusion header vs PC",
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_fusion_header")),
            fusionCtx.header,
            ParityVectorAssert.PC_TOLERANCE);
        ParityVectorAssert.assertWithinTolerance(
            "scan_1514 fusion receiver vs PC",
            ParityVectorAssert.jsonToFloats(fixture.getJSONArray("expected_fusion_receiver")),
            fusionCtx.receiver,
            ParityVectorAssert.PC_TOLERANCE);
      }
    }
  }

  private static JSONObject findFixtureBySampleId(JSONArray fixtures, String sampleId)
      throws Exception {
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      if (sampleId.equals(fixture.getString("sample_id"))) {
        return fixture;
      }
    }
    throw new IllegalArgumentException("No broadcast fixture for " + sampleId);
  }

  private static void assumeApkAssetPresent(String assetPath) throws Exception {
    if (!TestAssetHelper.testAssetExists(assetPath)) {
      Assume.assumeTrue(
          "Missing APK asset " + assetPath + " — run generate_a4_parity_fixtures.sh", false);
    }
  }

  private static File copyApkAssetToCache(android.content.Context context, String assetPath)
      throws Exception {
    File out = new File(context.getCacheDir(), "phase2_" + assetPath.replace('/', '_'));
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
