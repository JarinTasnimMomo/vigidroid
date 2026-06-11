package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class BroadcastMldpHybridOnnxRunnerTest {

  @Test
  public void constants_matchExportManifest() {
    assertEquals("broadcast_mldp_hybrid", BroadcastMldpHybridOnnxRunner.MODEL_ID);
    assertEquals("manifest_mldp_perm_receiver_actions", BroadcastMldpHybridOnnxRunner.DOMAIN);
    assertEquals(BroadcastMldpHybridExtractor.S_DIM, 22);
    assertEquals(BroadcastMldpHybridExtractor.R_DIM, 70);
    assertEquals(BroadcastMldpHybridExtractor.FEATURE_DIM, 92);
  }
}
