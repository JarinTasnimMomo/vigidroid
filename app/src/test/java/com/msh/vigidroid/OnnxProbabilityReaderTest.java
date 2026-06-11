package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class OnnxProbabilityReaderTest {

  @Test
  public void readScalar_handlesLongTensorLayouts() {
    assertEquals(1.0f, OnnxProbabilityReader.readScalar(new long[] {1}), 1e-6f);
    assertEquals(0.0f, OnnxProbabilityReader.readScalar(new long[][] {{0}, {1}}), 1e-6f);
    assertEquals(99.0f, OnnxProbabilityReader.readScalar(new long[][] {{99}}), 1e-6f);
  }

  @Test
  public void readScalar_handlesFloatTensorLayouts() {
    assertEquals(0.25f, OnnxProbabilityReader.readScalar(new float[] {0.25f}), 1e-6f);
    assertEquals(0.9f, OnnxProbabilityReader.readScalar(new float[][] {{0.9f}}), 1e-6f);
  }

  @Test
  public void readScalar_handlesNumberBoxedScalar() {
    assertEquals(0.42f, OnnxProbabilityReader.readScalar(Double.valueOf(0.42)), 1e-6f);
  }
}
