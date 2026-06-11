package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.Closeable;
import java.util.Collections;
import java.util.Map;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

/**
 * A2 — Mode A ONNX inference: fused x [1, d] → malware_prob (sigmoid in graph).
 */
public final class MldpDexHeaderModeAOnnxRunner implements Closeable {

  private static final String TAG = "MldpDexHeaderModeAOnnx";
  public static final String MODEL_ID = "mldp_dexheader_cascade_mode_a";
  public static final String DOMAIN = "manifest_mldp_perm_dex_header";
  private static final String ASSET_PREFIX = "models/mldp_dexheader_cascade/mode_a/";
  private static final String MODEL_ASSET = ASSET_PREFIX + "model.onnx";
  private static final String MANIFEST_ASSET = ASSET_PREFIX + "export_manifest.json";
  private static final String THRESHOLDS_ASSET = "models/mldp_dexheader_cascade/thresholds.json";
  private static final String CACHE_FILE = "mldp_dexheader_cascade_mode_a.onnx";

  private final OrtEnvironment environment;
  private final OrtSession session;
  private final String inputName;
  private final String outputName;
  private final MldpDexHeaderCascadeThresholds thresholds;

  private MldpDexHeaderModeAOnnxRunner(
      OrtEnvironment environment,
      OrtSession session,
      String inputName,
      String outputName,
      MldpDexHeaderCascadeThresholds thresholds) {
    this.environment = environment;
    this.session = session;
    this.inputName = inputName;
    this.outputName = outputName;
    this.thresholds = thresholds;
  }

  public static MldpDexHeaderModeAOnnxRunner create(Context context, OrtEnvironment sharedEnv)
      throws Exception {
    JSONObject manifest = new JSONObject(ModelAssetHelper.readAssetText(context, MANIFEST_ASSET));
    String inputName = OnnxManifestIo.inputName(manifest, "features");
    String outputName = OnnxManifestIo.malwareOutputName(manifest);
    MldpDexHeaderCascadeThresholds thresholds =
        MldpDexHeaderCascadeThresholds.fromAsset(context, THRESHOLDS_ASSET);
    java.io.File modelFile = ModelAssetHelper.copyAssetToCache(context, MODEL_ASSET, CACHE_FILE);
    OrtSession session =
        sharedEnv.createSession(
            modelFile.getAbsolutePath(), OnnxSessionFactory.createOptions(context));
    OnnxSessionDiagnostics.logSingleIo(TAG, MODEL_ID, session, inputName, outputName);
    Log.i(
        TAG,
        "Loaded Mode A ONNX (threshold="
            + thresholds.getModeATuned()
            + ") from "
            + modelFile.getAbsolutePath());
    return new MldpDexHeaderModeAOnnxRunner(
        sharedEnv, session, inputName, outputName, thresholds);
  }

  public MldpDexHeaderCascadeThresholds getThresholds() {
    return thresholds;
  }

  /** Returns sigmoid malware probability in [0, 1]. */
  public float predict(float[] fusedFeatures) throws OrtException {
    if (fusedFeatures.length != MldpDexHeaderExtractor.D_DIM) {
      throw new IllegalArgumentException(
          "Expected "
              + MldpDexHeaderExtractor.D_DIM
              + " fused features, got "
              + fusedFeatures.length);
    }
    return runSession(session, inputName, outputName, environment, fusedFeatures);
  }

  public boolean isMalware(float malwareProbability) {
    return thresholds.isMalwareModeA(malwareProbability);
  }

  static float runSession(
      OrtSession session,
      String inputName,
      String outputName,
      OrtEnvironment environment,
      float[] features)
      throws OrtException {
    long[] shape = OnnxTensorFactory.batchRowShape(features.length);
    try (OnnxTensor tensor = OnnxTensorFactory.createFloatTensor(environment, features, shape)) {
      Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, tensor);
      try (OrtSession.Result result = session.run(inputs)) {
        return OnnxProbabilityReader.readFromResult(result, outputName);
      }
    }
  }

  @Override
  public void close() {
    if (session != null) {
      try {
        session.close();
      } catch (Exception ignored) {
      }
    }
  }
}
