package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.Closeable;
import java.util.HashMap;
import java.util.Map;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

/**
 * A2 — Two-input ONNX inference for dexheader_broadcast_fusion.
 * Inputs: dex_header [1,104], receiver [1,R] → malware_prob.
 */
public final class DexheaderBroadcastFusionOnnxRunner implements Closeable {

  private static final String TAG = "DexheaderBroadcastFusionOnnxRunner";
  public static final String MODEL_ID = "dexheader_broadcast_fusion";
  public static final String DOMAIN = "dex_header_receiver_actions";
  private static final String MODEL_ASSET = "models/dexheader_broadcast_fusion/model.onnx";
  private static final String MANIFEST_ASSET =
      "models/dexheader_broadcast_fusion/export_manifest.json";
  private static final String THRESHOLDS_ASSET =
      "models/dexheader_broadcast_fusion/thresholds.json";
  private static final String CACHE_FILE = "dexheader_broadcast_fusion_model.onnx";

  private final OrtEnvironment environment;
  private final OrtSession session;
  private final String dexInputName;
  private final String receiverInputName;
  private final String outputName;
  private final ModelThresholds thresholds;

  private DexheaderBroadcastFusionOnnxRunner(
      OrtEnvironment environment,
      OrtSession session,
      String dexInputName,
      String receiverInputName,
      String outputName,
      ModelThresholds thresholds) {
    this.environment = environment;
    this.session = session;
    this.dexInputName = dexInputName;
    this.receiverInputName = receiverInputName;
    this.outputName = outputName;
    this.thresholds = thresholds;
  }

  public static DexheaderBroadcastFusionOnnxRunner create(Context context, OrtEnvironment sharedEnv)
      throws Exception {
    String manifestJson = ModelAssetHelper.readAssetText(context, MANIFEST_ASSET);
    JSONObject manifest = new JSONObject(manifestJson);
    String dexInputName = OnnxManifestIo.namedInput(manifest, "dex_header");
    String receiverInputName = OnnxManifestIo.namedInput(manifest, "receiver");
    String outputName = OnnxManifestIo.malwareOutputName(manifest);
    ModelThresholds thresholds = ModelThresholds.fromAsset(context, THRESHOLDS_ASSET);
    java.io.File modelFile = ModelAssetHelper.copyAssetToCache(context, MODEL_ASSET, CACHE_FILE);
    OrtSession session =
        sharedEnv.createSession(
            modelFile.getAbsolutePath(), OnnxSessionFactory.createOptions(context));
    OnnxSessionDiagnostics.logDualInput(
        TAG, MODEL_ID, session, dexInputName, receiverInputName, outputName);
    Log.i(
        TAG,
        "Loaded dexheader_broadcast_fusion ONNX (threshold="
            + thresholds.getMalwareThreshold()
            + ")");
    return new DexheaderBroadcastFusionOnnxRunner(
        sharedEnv, session, dexInputName, receiverInputName, outputName, thresholds);
  }

  public ModelThresholds getThresholds() {
    return thresholds;
  }

  public float predict(float[] header, float[] receiver) throws OrtException {
    if (header.length != DexHeaderFeatureExtractor.FEATURE_DIM) {
      throw new IllegalArgumentException(
          "Expected header dim " + DexHeaderFeatureExtractor.FEATURE_DIM + ", got " + header.length);
    }
    if (receiver.length == 0) {
      throw new IllegalArgumentException("Receiver vector is empty");
    }

    long[] hShape = OnnxTensorFactory.batchRowShape(header.length);
    long[] rShape = OnnxTensorFactory.batchRowShape(receiver.length);
    try (OnnxTensor hTensor = OnnxTensorFactory.createFloatTensor(environment, header, hShape);
        OnnxTensor rTensor = OnnxTensorFactory.createFloatTensor(environment, receiver, rShape)) {
      Map<String, OnnxTensor> inputs = new HashMap<>();
      inputs.put(dexInputName, hTensor);
      inputs.put(receiverInputName, rTensor);
      try (OrtSession.Result result = session.run(inputs)) {
        return OnnxProbabilityReader.readFromResult(result, outputName);
      }
    }
  }

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
