package com.msh.vigidroid;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;

/** Direct native-order float tensors for ONNX Runtime Android (P1). */
public final class OnnxTensorFactory {

  private OnnxTensorFactory() {}

  /** Shape {@code [1, data.length]} from a row vector. */
  public static long[] batchRowShape(int featureDim) {
    return new long[] {1, featureDim};
  }

  /**
   * Creates a float32 input tensor backed by a direct {@link ByteBuffer} in native byte order.
   * ORT copies heap {@link FloatBuffer#wrap(float[])} on some Android builds; direct buffers are
   * the supported zero-copy path.
   */
  public static OnnxTensor createFloatTensor(OrtEnvironment env, float[] data, long[] shape)
      throws OrtException {
    int elementCount = 1;
    for (long dim : shape) {
      elementCount *= (int) dim;
    }
    if (elementCount != data.length) {
      throw new IllegalArgumentException(
          "Shape "
              + java.util.Arrays.toString(shape)
              + " requires "
              + elementCount
              + " elements but got "
              + data.length);
    }
    FloatBuffer floatBuffer =
        ByteBuffer.allocateDirect(data.length * Float.BYTES)
            .order(ByteOrder.nativeOrder())
            .asFloatBuffer();
    floatBuffer.put(data);
    floatBuffer.flip();
    return OnnxTensor.createTensor(env, floatBuffer, shape);
  }
}
