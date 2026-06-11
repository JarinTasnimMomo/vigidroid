package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ModelThresholdsTest {

  @Test
  public void isMalware_linregdroid1ThresholdRule() {
    ModelThresholds thresholds = new ModelThresholds(0.5f, "linregdroid1", "");
    assertFalse(thresholds.isMalware(0.49f));
    assertTrue(thresholds.isMalware(0.5f));
    assertTrue(thresholds.isMalware(0.51f));
  }

  @Test
  public void isMalware_mldpSigmoidThresholdRule() {
    ModelThresholds thresholds = new ModelThresholds(0.5f, "", "linear_svc");
    assertFalse(thresholds.isMalware(0.0f));
    assertTrue(thresholds.isMalware(0.906f));
  }

  @Test
  public void isMalware_broadcastTunedValThresholdRule() {
    ModelThresholds thresholds = new ModelThresholds(0.65f, "", "tiny_mlp");
    assertFalse(thresholds.isMalware(0.64f));
    assertTrue(thresholds.isMalware(0.65f));
    assertTrue(thresholds.isMalware(0.99f));
  }

  @Test
  public void defaultThreshold_isHalf() {
    assertEquals(0.5f, ModelThresholds.DEFAULT_MALWARE_THRESHOLD, 0f);
  }
}
