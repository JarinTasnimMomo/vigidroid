package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MldpDexHeaderOnnxRunnerTest {

  @Test
  public void modeA_constants_matchExportManifest() {
    assertEquals("mldp_dexheader_cascade_mode_a", MldpDexHeaderModeAOnnxRunner.MODEL_ID);
    assertEquals("manifest_mldp_perm_dex_header", MldpDexHeaderModeAOnnxRunner.DOMAIN);
    assertEquals(126, MldpDexHeaderExtractor.D_DIM);
  }

  @Test
  public void modeB_constants_matchExportManifest() {
    assertEquals("mldp_dexheader_cascade_mode_b", MldpDexHeaderModeBOnnxRunner.MODEL_ID);
    assertEquals("manifest_mldp_perm_dex_header", MldpDexHeaderModeBOnnxRunner.DOMAIN);
    assertEquals(22, MldpDexHeaderExtractor.S_DIM);
    assertEquals(104, MldpDexHeaderExtractor.H_DIM);
  }

  @Test
  public void cascadeThresholds_earlyExitBands_areOrdered() throws Exception {
    MldpDexHeaderCascadeThresholds thresholds =
        new MldpDexHeaderCascadeThresholds(0.5f, 0.6f, 0.08f, 0.83f);
    assertTrue(thresholds.getStage1TLow() < thresholds.getStage1THigh());
    assertTrue(thresholds.isEarlyExitBenign(0.05f));
    assertTrue(thresholds.isEarlyExitMalware(0.9f));
    assertTrue(thresholds.isUncertainBand(0.5f));
  }
}
