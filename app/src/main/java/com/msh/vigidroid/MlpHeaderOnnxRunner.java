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

/** ONNX inference for BM1 mlp_header (104-d Dex header → malware probability). */
public final class MlpHeaderOnnxRunner implements Closeable {

    private static final String TAG = "MlpHeaderOnnxRunner";
    public static final String MODEL_ID = "mlp_header";
    public static final String DOMAIN = "dex_header_d3";
    private static final String MODEL_ASSET = "models/mlp_header/model.onnx";
    private static final String MANIFEST_ASSET = "models/mlp_header/export_manifest.json";
    private static final String CACHE_FILE = "mlp_header_model.onnx";

    private final OrtEnvironment environment;
    private final OrtSession session;
    private final String inputName;
    private final String outputName;

    private MlpHeaderOnnxRunner(
            OrtEnvironment environment,
            OrtSession session,
            String inputName,
            String outputName) {
        this.environment = environment;
        this.session = session;
        this.inputName = inputName;
        this.outputName = outputName;
    }

    public static MlpHeaderOnnxRunner create(Context context, OrtEnvironment sharedEnv) throws Exception {
        JSONObject manifest = new JSONObject(ModelAssetHelper.readAssetText(context, MANIFEST_ASSET));
        String inputName = OnnxManifestIo.inputName(manifest, "features");
        String outputName = OnnxManifestIo.malwareOutputName(manifest);
        java.io.File modelFile = ModelAssetHelper.copyAssetToCache(context, MODEL_ASSET, CACHE_FILE);
        OrtSession.SessionOptions options = OnnxSessionFactory.createOptions(context);
        OrtSession session = sharedEnv.createSession(modelFile.getAbsolutePath(), options);
        OnnxSessionDiagnostics.logSingleIo(TAG, MODEL_ID, session, inputName, outputName);
        Log.i(TAG, "Loaded BM1 ONNX from " + modelFile.getAbsolutePath());
        return new MlpHeaderOnnxRunner(sharedEnv, session, inputName, outputName);
    }

    public float predict(float[] features) throws OrtException {
        if (features.length != DexHeaderFeatureExtractor.FEATURE_DIM) {
            throw new IllegalArgumentException(
                    "Expected " + DexHeaderFeatureExtractor.FEATURE_DIM + " features, got "
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
