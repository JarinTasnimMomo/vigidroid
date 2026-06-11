package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DexheaderBroadcastFusionOnnxRunnerTest {

  @Test
  public void constants_matchExportManifest() {
    assertEquals("dexheader_broadcast_fusion", DexheaderBroadcastFusionOnnxRunner.MODEL_ID);
    assertEquals("dex_header_receiver_actions", DexheaderBroadcastFusionOnnxRunner.DOMAIN);
    assertEquals(DexHeaderFeatureExtractor.FEATURE_DIM, DexheaderBroadcastFusionExtractor.H_DIM);
  }
}
