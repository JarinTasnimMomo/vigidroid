package com.msh.vigidroid;

import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.msh.vigidroid.pipeline.LegacyScanRunner;
import com.msh.vigidroid.pipeline.ScanApkResult;
import com.msh.vigidroid.pipeline.StageResult;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Locale;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * P1 exit gate — full legacy all-models scan on a real eval APK ({@code scan_1514_malware.apk}).
 *
 * <p>Push APK first: {@code Android_Works/run_p1_exit_scan.sh}
 */
@RunWith(AndroidJUnit4.class)
public class P1ExitLegacyScanTest {

  private static final String TAG = "P1ExitScan";
  private static final String[] PREVIOUSLY_FAILING =
      new String[] {
        MldpDexHeaderModeAOnnxRunner.MODEL_ID,
        BroadcastMldpHybridOnnxRunner.MODEL_ID,
        DexheaderBroadcastFusionOnnxRunner.MODEL_ID
      };

  @Test
  public void legacyAllModelsScan_scan1514_allStagesOk() throws Exception {
    var context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    File apk = EvalApkPaths.resolveScan1514(context);
    if (!apk.isFile()) {
      fail("Missing eval APK — run Android_Works/run_p1_exit_scan.sh");
    }

    try (ScanPipelineTestHelper helper = ScanPipelineTestHelper.create(context);
        FeatureContext ctx = FeatureContext.open(apk)) {

      LegacyScanRunner runner =
          new LegacyScanRunner(helper.deps, CascadePolicy.disabledDefault());
      ScanApkResult result =
          runner.run(ctx, apk.getName(), (message, status) -> Log.i(TAG, message));

      assertEquals("Expected 11 legacy stages", 11, result.stages.size());

      int okCount = 0;
      StringBuilder summary = new StringBuilder();
      for (StageResult stage : result.stages) {
        summary.append(
            String.format(
                Locale.US,
                "%n  %s [%s] score=%.4f infer=%.2fms",
                stage.modelId,
                stage.status,
                stage.score,
                stage.inferenceMs));
        if (StageResult.STATUS_OK.equals(stage.status)) {
          okCount++;
        } else {
          summary.append(" error=").append(stage.errorMessage);
        }
      }
      Log.i(
          TAG,
          "scan_1514 wall="
              + result.wallMs
              + "ms shared_parse="
              + result.sharedParseMs
              + "ms ensemble="
              + result.ensembleScore
              + " ("
              + result.ensembleDecision
              + ")"
              + summary);

      for (String modelId : PREVIOUSLY_FAILING) {
        StageResult stage = findStage(result, modelId);
        assertNotNull("Missing stage " + modelId, stage);
        assertEquals(modelId + " should be ok", StageResult.STATUS_OK, stage.status);
        assertTrue(
            modelId + " infer time should be > 0",
            stage.inferenceMs > 0.0 || stage.earlyExit);
      }

      assertEquals("All 11 stages should be ok", 11, okCount);
    }
  }

  private static StageResult findStage(ScanApkResult result, String modelId) {
    for (StageResult stage : result.stages) {
      if (modelId.equals(stage.modelId)) {
        return stage;
      }
    }
    return null;
  }
}
