package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import ai.onnxruntime.OrtSession;

/** Build tuned {@link OrtSession.SessionOptions} from {@code assets/ort_config.json} (A4). */
public final class OnnxSessionFactory {

  private static final String TAG = "OnnxSessionFactory";
  public static final String ASSET_PATH = "ort_config.json";

  private OnnxSessionFactory() {}

  public static OrtSession.SessionOptions createOptions(Context context) {
    OrtSession.SessionOptions options = new OrtSession.SessionOptions();
    try {
      JSONObject cfg = new JSONObject(ModelAssetHelper.readAssetText(context, ASSET_PATH));
      int threads = cfg.optInt("intra_op_num_threads", 0);
      if (threads > 0) {
        options.setIntraOpNumThreads(threads);
      }
      String optLevel = cfg.optString("optimization_level", "ALL_OPT");
      options.setOptimizationLevel(parseOptLevel(optLevel));
      if (cfg.optBoolean("use_nnapi", false)) {
        try {
          options.addNnapi();
          Log.i(TAG, "NNAPI execution provider enabled");
        } catch (Exception ex) {
          Log.w(TAG, "NNAPI unavailable, using CPU", ex);
        }
      }
    } catch (Exception ex) {
      Log.w(TAG, "ort_config.json not loaded; using ORT defaults", ex);
    }
    return options;
  }

  private static OrtSession.SessionOptions.OptLevel parseOptLevel(String value) {
    if (value == null) {
      return OrtSession.SessionOptions.OptLevel.ALL_OPT;
    }
    switch (value.toUpperCase()) {
      case "NO_OPT":
        return OrtSession.SessionOptions.OptLevel.NO_OPT;
      case "BASIC_OPT":
        return OrtSession.SessionOptions.OptLevel.BASIC_OPT;
      case "EXTENDED_OPT":
        return OrtSession.SessionOptions.OptLevel.EXTENDED_OPT;
      case "ALL_OPT":
      default:
        return OrtSession.SessionOptions.OptLevel.ALL_OPT;
    }
  }
}
