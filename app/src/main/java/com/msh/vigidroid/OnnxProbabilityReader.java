package com.msh.vigidroid;

import ai.onnxruntime.OnnxValue;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

/** Shared ONNX output parsing for scalar malware probabilities (P1). */
public final class OnnxProbabilityReader {

  private OnnxProbabilityReader() {}

  public static float readFromResult(OrtSession.Result result, String outputName)
      throws OrtException {
    if (outputName != null && !outputName.isEmpty()) {
      java.util.Optional<OnnxValue> named = result.get(outputName);
      if (named.isPresent()) {
        return readScalar(named.get().getValue());
      }
    }
    return readScalar(result.get(0).getValue());
  }

  public static float readScalar(Object value) {
    if (value instanceof float[][]) {
      return ((float[][]) value)[0][0];
    }
    if (value instanceof float[]) {
      return ((float[]) value)[0];
    }
    if (value instanceof double[][]) {
      return (float) ((double[][]) value)[0][0];
    }
    if (value instanceof double[]) {
      return (float) ((double[]) value)[0];
    }
    if (value instanceof long[][]) {
      return (float) ((long[][]) value)[0][0];
    }
    if (value instanceof long[]) {
      return (float) ((long[]) value)[0];
    }
    if (value instanceof int[][]) {
      return (float) ((int[][]) value)[0][0];
    }
    if (value instanceof int[]) {
      return (float) ((int[]) value)[0];
    }
    if (value instanceof Number) {
      return ((Number) value).floatValue();
    }
    throw new IllegalStateException("Unexpected ONNX output type: " + value.getClass().getName());
  }
}
