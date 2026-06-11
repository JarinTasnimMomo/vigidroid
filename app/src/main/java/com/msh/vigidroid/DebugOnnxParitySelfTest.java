package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import java.util.List;

/**
 * Debug-build smoke check: one ONNX parity vector per critical runner after {@link ScanService}
 * init. Failures are logged as warnings only (non-blocking).
 */
final class DebugOnnxParitySelfTest {

  private static final String TAG = "DebugOnnxParitySelfTest";

  private DebugOnnxParitySelfTest() {}

  static void runIfDebug(
      Context context,
      MldpDexHeaderModeAOnnxRunner modeARunner,
      BroadcastMldpHybridOnnxRunner broadcastRunner,
      DexheaderBroadcastFusionOnnxRunner fusionRunner) {
    if (!BuildConfig.DEBUG) {
      return;
    }
    List<ModelHealthChecker.Result> results =
        ModelHealthChecker.runAll(context, modeARunner, broadcastRunner, fusionRunner);
    boolean allOk = true;
    for (ModelHealthChecker.Result result : results) {
      if (result.ok) {
        Log.i(TAG, result.modelId + " OK — " + result.detail);
      } else {
        allOk = false;
        Log.w(TAG, result.modelId + " FAIL — " + result.detail);
      }
    }
    if (allOk) {
      Log.i(TAG, "Debug ONNX parity self-test OK");
    }
  }
}
