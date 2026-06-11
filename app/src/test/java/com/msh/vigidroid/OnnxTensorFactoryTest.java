package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class OnnxTensorFactoryTest {

  @Test
  public void batchRowShape_isOneByFeatureDim() {
    long[] shape = OnnxTensorFactory.batchRowShape(92);
    assertEquals(2, shape.length);
    assertEquals(1L, shape[0]);
    assertEquals(92L, shape[1]);
  }
}
