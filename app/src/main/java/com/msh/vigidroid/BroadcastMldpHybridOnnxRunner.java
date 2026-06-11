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
 * A2 — ONNX inference for broadcast + MLDP hybrid (92-d early-fused features → malware_prob).
 * Input {@code features} [1, 92] float32; output sigmoid probability in [0, 1].
 */
public final class BroadcastMldpHybridOnnxRunner implements Closeable {

  private static final String TAG = "BroadcastMldpHybridOnnxRunner";
  public static final String MODEL_ID = "broadcast_mldp_hybrid";
  public static final String DOMAIN = "manifest_mldp_perm_receiver_actions";
  private static final String MODEL_ASSET = "models/broadcast_mldp_hybrid/model.onnx";
  private static final String MANIFEST_ASSET = "models/broadcast_mldp_hybrid/export_manifest.json";
  private static final String THRESHOLDS_ASSET = "models/broadcast_mldp_hybrid/thresholds.json";
  private static final String CACHE_FILE = "broadcast_mldp_hybrid_model.onnx";

  private final OrtEnvironment environment;
  private final OrtSession session;
  private final String inputName;
  private final String outputName;
  private final ModelThresholds thresholds;

  private BroadcastMldpHybridOnnxRunner(
      OrtEnvironment environment,
      OrtSession session,
      String inputName,
      String outputName,
      ModelThresholds thresholds) {
    this.environment = environment;
    this.session = session;
    this.inputName = inputName;
    this.outputName = outputName;
    this.thresholds = thresholds;
  }

  public static BroadcastMldpHybridOnnxRunner create(Context context, OrtEnvironment sharedEnv)
      throws Exception {
    String manifestJson = ModelAssetHelper.readAssetText(context, MANIFEST_ASSET);
    JSONObject manifest = new JSONObject(manifestJson);
    String inputName = OnnxManifestIo.inputName(manifest, "features");
    String outputName = OnnxManifestIo.malwareOutputName(manifest);
    ModelThresholds thresholds = ModelThresholds.fromAsset(context, THRESHOLDS_ASSET);
    java.io.File modelFile = ModelAssetHelper.copyAssetToCache(context, MODEL_ASSET, CACHE_FILE);
    OrtSession session =
        sharedEnv.createSession(
            modelFile.getAbsolutePath(), OnnxSessionFactory.createOptions(context));
    OnnxSessionDiagnostics.logSingleIo(TAG, MODEL_ID, session, inputName, outputName);
    Log.i(
        TAG,
        "Loaded broadcast_mldp_hybrid ONNX (threshold="
            + thresholds.getMalwareThreshold()
            + ") from "
            + modelFile.getAbsolutePath());
    return new BroadcastMldpHybridOnnxRunner(
        sharedEnv, session, inputName, outputName, thresholds);
  }

  public ModelThresholds getThresholds() {
    return thresholds;
  }

  public String getModelType() {
    String modelType = thresholds.getModelType();
    if (modelType.isEmpty() || "linear_svc".equals(modelType)) {
      return "tiny_mlp";
    }
    return modelType;
  }

  /** Returns sigmoid-calibrated malware probability in [0, 1]. */
  public float predict(float[] features) throws OrtException {
    if (features.length != BroadcastMldpHybridExtractor.FEATURE_DIM) {
      throw new IllegalArgumentException(
          "Expected "
              + BroadcastMldpHybridExtractor.FEATURE_DIM
              + " features, got "
              + features.length);
    }
    long[] shape = OnnxTensorFactory.batchRowShape(features.length);
    try (OnnxTensor tensor = OnnxTensorFactory.createFloatTensor(environment, features, shape)) {
      Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, tensor);
      try (OrtSession.Result result = session.run(inputs)) {
        return OnnxProbabilityReader.readFromResult(result, outputName);
      }
    }
  }

  /** Malware when sigmoid probability >= tuned threshold from thresholds.json. */
  public boolean isMalware(float malwareProbability) {
    return thresholds.isMalware(malwareProbability);
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
