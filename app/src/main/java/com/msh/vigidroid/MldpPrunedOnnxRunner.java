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
 * ONNX inference for MLDP-pruned permissions (40-d → sigmoid malware_probability).
 * Supports exported linear_svc and tiny_mlp bundles (same I/O contract; model_type
 * recorded in export_manifest.json / thresholds.json).
 */
public final class MldpPrunedOnnxRunner implements Closeable {

  private static final String TAG = "MldpPrunedOnnxRunner";
  public static final String MODEL_ID = "mldp_pruned_permission";
  public static final String DOMAIN = "manifest_permissions_mldp";
  private static final String MODEL_ASSET = "models/mldp_pruned_permission/model.onnx";
  private static final String MANIFEST_ASSET = "models/mldp_pruned_permission/export_manifest.json";
  private static final String THRESHOLDS_ASSET = "models/mldp_pruned_permission/thresholds.json";
  private static final String CACHE_FILE = "mldp_pruned_permission_model.onnx";

  private final OrtEnvironment environment;
  private final OrtSession session;
  private final String inputName;
  private final String outputName;
  private final ModelThresholds thresholds;
  private final String modelType;

  private MldpPrunedOnnxRunner(
      OrtEnvironment environment,
      OrtSession session,
      String inputName,
      String outputName,
      ModelThresholds thresholds,
      String modelType) {
    this.environment = environment;
    this.session = session;
    this.inputName = inputName;
    this.outputName = outputName;
    this.thresholds = thresholds;
    this.modelType = modelType;
  }

  public static MldpPrunedOnnxRunner create(Context context, OrtEnvironment sharedEnv)
      throws Exception {
    JSONObject manifest = new JSONObject(ModelAssetHelper.readAssetText(context, MANIFEST_ASSET));
    String inputName = OnnxManifestIo.inputName(manifest, "permissions");
    String outputName = OnnxManifestIo.malwareOutputName(manifest);
    String modelType = manifest.optString("model_type", "linear_svc");
    ModelThresholds thresholds = ModelThresholds.fromAsset(context, THRESHOLDS_ASSET);
    if (!thresholds.getModelType().isEmpty()) {
      modelType = thresholds.getModelType();
    }
    if (!"linear_svc".equals(modelType) && !"tiny_mlp".equals(modelType)) {
      throw new IllegalStateException("Unsupported MLDP model_type: " + modelType);
    }
    java.io.File modelFile = ModelAssetHelper.copyAssetToCache(context, MODEL_ASSET, CACHE_FILE);
    OrtSession session =
        sharedEnv.createSession(
            modelFile.getAbsolutePath(), OnnxSessionFactory.createOptions(context));
    OnnxSessionDiagnostics.logSingleIo(TAG, MODEL_ID, session, inputName, outputName);
    Log.i(
        TAG,
        "Loaded MLDP ONNX (model_type="
            + modelType
            + ", threshold="
            + thresholds.getMalwareThreshold()
            + ") from "
            + modelFile.getAbsolutePath());
    return new MldpPrunedOnnxRunner(
        sharedEnv, session, inputName, outputName, thresholds, modelType);
  }

  public ModelThresholds getThresholds() {
    return thresholds;
  }

  public String getModelType() {
    return modelType;
  }

  /** Returns sigmoid-calibrated malware probability in [0, 1]. */
  public float predict(float[] permissions) throws OrtException {
    if (permissions.length != MldpPrunedPermissionExtractor.FEATURE_DIM) {
      throw new IllegalArgumentException(
          "Expected "
              + MldpPrunedPermissionExtractor.FEATURE_DIM
              + " permissions, got "
              + permissions.length);
    }
    long[] shape = OnnxTensorFactory.batchRowShape(permissions.length);
    try (OnnxTensor tensor = OnnxTensorFactory.createFloatTensor(environment, permissions, shape)) {
      Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, tensor);
      try (OrtSession.Result result = session.run(inputs)) {
        return OnnxProbabilityReader.readFromResult(result, outputName);
      }
    }
  }

  /** MLDP: malware when sigmoid probability >= threshold. */
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
