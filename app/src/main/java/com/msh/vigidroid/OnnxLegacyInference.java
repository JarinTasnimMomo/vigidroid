package com.msh.vigidroid;

import java.nio.LongBuffer;
import java.util.Collections;
import java.util.Map;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

/** Legacy root-level XGBoost + ByteCNN ONNX inference (not in {@link ModelRegistry}). */
public final class OnnxLegacyInference {

  private OnnxLegacyInference() {}

  public static float runXgb(OrtEnvironment env, OrtSession session, float[] inputVector) {
    if (env == null || session == null) {
      return -1f;
    }
    try (OrtSession.Result result = runXgbSession(env, session, inputVector)) {
      return OnnxProbabilityReader.readFromResult(result, null);
    } catch (Exception e) {
      return -1f;
    }
  }

  private static OrtSession.Result runXgbSession(
      OrtEnvironment env, OrtSession session, float[] inputVector) throws OrtException {
    long[] shape = OnnxTensorFactory.batchRowShape(inputVector.length);
    String inputName = session.getInputNames().iterator().next();
    try (OnnxTensor tensor = OnnxTensorFactory.createFloatTensor(env, inputVector, shape)) {
      Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, tensor);
      return session.run(inputs);
    }
  }

  public static float runCnn(OrtEnvironment env, OrtSession session, long[] inputVector) {
    if (env == null || session == null) {
      return -1f;
    }
    try {
      long[] shape = new long[] {1, inputVector.length};
      LongBuffer lb = LongBuffer.wrap(inputVector);
      String inputName = session.getInputNames().iterator().next();
      try (OnnxTensor tensor = OnnxTensor.createTensor(env, lb, shape)) {
        Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, tensor);
        try (OrtSession.Result result = session.run(inputs)) {
          Object o = result.get(0).getValue();
          if (o instanceof float[][]) {
            float[][] out = (float[][]) o;
            double exp0 = Math.exp(out[0][0]);
            double exp1 = Math.exp(out[0][1]);
            return (float) (exp1 / (exp0 + exp1));
          }
          return -1f;
        }
      }
    } catch (Exception e) {
      return -1f;
    }
  }
}
