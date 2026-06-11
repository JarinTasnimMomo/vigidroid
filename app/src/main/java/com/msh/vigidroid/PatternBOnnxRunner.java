package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.Closeable;
import java.util.HashMap;
import java.util.Map;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

/** ONNX inference for dual_branch_dex_manifest (header + manifest BoW → fused malware probability). */
public final class PatternBOnnxRunner implements Closeable {

  private static final String TAG = "PatternBOnnxRunner";
  public static final String MODEL_ID = "dual_branch_dex_manifest";
  public static final String DOMAIN = "dex_header_manifest_dual";
  private static final String MODEL_ASSET = "models/dual_branch_dex_manifest/model.onnx";
  private static final String MANIFEST_ASSET = "models/dual_branch_dex_manifest/export_manifest.json";
  private static final String CACHE_FILE = "dual_branch_dex_manifest_model.onnx";

  private final OrtEnvironment environment;
  private final OrtSession session;
  private final String headerInputName;
  private final String bowInputName;
  private final String outputName;

  private PatternBOnnxRunner(
      OrtEnvironment environment,
      OrtSession session,
      String headerInputName,
      String bowInputName,
      String outputName) {
    this.environment = environment;
    this.session = session;
    this.headerInputName = headerInputName;
    this.bowInputName = bowInputName;
    this.outputName = outputName;
  }

  public static PatternBOnnxRunner create(Context context, OrtEnvironment sharedEnv) throws Exception {
    JSONObject manifest = new JSONObject(ModelAssetHelper.readAssetText(context, MANIFEST_ASSET));
    String headerName = "header";
    String bowName = "bow";
    JSONObject onnxCheck = manifest.optJSONObject("onnx_runtime_check");
    if (onnxCheck != null) {
      JSONArray inputNames = onnxCheck.optJSONArray("input_names");
      if (inputNames != null && inputNames.length() >= 2) {
        headerName = inputNames.getString(0);
        bowName = inputNames.getString(1);
      }
    } else {
      JSONArray inputs = manifest.optJSONArray("inputs");
      if (inputs != null && inputs.length() >= 2) {
        headerName = inputs.getJSONObject(0).optString("name", headerName);
        bowName = inputs.getJSONObject(1).optString("name", bowName);
      }
    }
    String outputName = OnnxManifestIo.malwareOutputName(manifest);
    java.io.File modelFile = ModelAssetHelper.copyAssetToCache(context, MODEL_ASSET, CACHE_FILE);
    OrtSession.SessionOptions options = OnnxSessionFactory.createOptions(context);
    OrtSession session = sharedEnv.createSession(modelFile.getAbsolutePath(), options);
    OnnxSessionDiagnostics.logDualInput(
        TAG, MODEL_ID, session, headerName, bowName, outputName);
    Log.i(TAG, "Loaded dual-branch Dex+manifest ONNX from " + modelFile.getAbsolutePath());
    return new PatternBOnnxRunner(sharedEnv, session, headerName, bowName, outputName);
  }

  public float predict(float[] header, float[] bow) throws OrtException {
    if (header.length != DexHeaderFeatureExtractor.FEATURE_DIM) {
      throw new IllegalArgumentException(
          "Expected header dim " + DexHeaderFeatureExtractor.FEATURE_DIM + ", got " + header.length);
    }
    if (bow.length != ManifestBowExtractor.BOW_DIM) {
      throw new IllegalArgumentException(
          "Expected bow dim " + ManifestBowExtractor.BOW_DIM + ", got " + bow.length);
    }

    long[] headerShape = OnnxTensorFactory.batchRowShape(header.length);
    long[] bowShape = OnnxTensorFactory.batchRowShape(bow.length);
    try (OnnxTensor headerTensor =
            OnnxTensorFactory.createFloatTensor(environment, header, headerShape);
        OnnxTensor bowTensor = OnnxTensorFactory.createFloatTensor(environment, bow, bowShape)) {
      Map<String, OnnxTensor> inputs = new HashMap<>();
      inputs.put(headerInputName, headerTensor);
      inputs.put(bowInputName, bowTensor);
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
