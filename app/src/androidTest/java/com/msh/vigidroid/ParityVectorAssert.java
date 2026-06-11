package com.msh.vigidroid;

import org.json.JSONArray;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

/** Shared float-vector parity helpers for instrumented tests. */
public final class ParityVectorAssert {

  public static final float PC_TOLERANCE = 1e-4f;
  public static final float FEATURE_CONTEXT_TOLERANCE = 1e-6f;

  private ParityVectorAssert() {}

  public static float maxAbsDiff(float[] expected, float[] actual) {
    if (expected.length != actual.length) {
      throw new IllegalArgumentException(
          "length mismatch: expected " + expected.length + " got " + actual.length);
    }
    float max = 0f;
    for (int i = 0; i < expected.length; i++) {
      max = Math.max(max, Math.abs(expected[i] - actual[i]));
    }
    return max;
  }

  public static void assertWithinTolerance(
      String message, float[] expected, float[] actual, float tolerance) {
    float max = maxAbsDiff(expected, actual);
    assertTrue(message + " (max_diff=" + max + ")", max <= tolerance);
    assertArrayEquals(message, expected, actual, tolerance);
  }

  public static float[] jsonToFloats(JSONArray row) throws Exception {
    float[] values = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      values[i] = (float) row.getDouble(i);
    }
    return values;
  }
}
