package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ModelRegistryTest {

  @Test
  public void linregdroid_assetsMatchExportManifest() {
    assertEquals("linregdroid_permission", ModelRegistry.LINREGDROID_PERMISSION.modelId);
    assertEquals("manifest_permissions", ModelRegistry.LINREGDROID_PERMISSION.domain);
    assertEquals(LinRegDroidOnnxRunner.MODEL_ID, ModelRegistry.LINREGDROID_PERMISSION.modelId);
    assertEquals(LinRegDroidOnnxRunner.DOMAIN, ModelRegistry.LINREGDROID_PERMISSION.domain);
    assertTrue(ModelRegistry.LINREGDROID_PERMISSION.assetsPrefix.contains("linregdroid_permission"));
  }

  @Test
  public void mldp_assetsMatchExportManifest() {
    assertEquals("mldp_pruned_permission", ModelRegistry.MLDP_PRUNED_PERMISSION.modelId);
    assertEquals("manifest_permissions_mldp", ModelRegistry.MLDP_PRUNED_PERMISSION.domain);
    assertEquals(MldpPrunedOnnxRunner.MODEL_ID, ModelRegistry.MLDP_PRUNED_PERMISSION.modelId);
    assertEquals(MldpPrunedOnnxRunner.DOMAIN, ModelRegistry.MLDP_PRUNED_PERMISSION.domain);
    assertTrue(ModelRegistry.MLDP_PRUNED_PERMISSION.assetsPrefix.contains("mldp_pruned_permission"));
  }

  @Test
  public void dexheaderBroadcastFusion_assetsMatchExportManifest() {
    assertEquals(
        "dexheader_broadcast_fusion", ModelRegistry.DEXHEADER_BROADCAST_FUSION.modelId);
    assertEquals(
        DexheaderBroadcastFusionOnnxRunner.DOMAIN,
        ModelRegistry.DEXHEADER_BROADCAST_FUSION.domain);
    assertTrue(
        ModelRegistry.DEXHEADER_BROADCAST_FUSION.assetsPrefix.contains(
            "dexheader_broadcast_fusion"));
  }

  @Test
  public void mldpDexheaderCascade_assetsMatchExportManifest() {
    assertEquals(
        "mldp_dexheader_cascade_mode_a", ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_A.modelId);
    assertEquals(
        "mldp_dexheader_cascade_mode_b", ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B.modelId);
    assertEquals(
        MldpDexHeaderModeAOnnxRunner.DOMAIN, ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_A.domain);
    assertTrue(
        ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_A.assetsPrefix.contains("mldp_dexheader_cascade"));
  }

  @Test
  public void allScanStages_includesDexBroadcastFusion() {
    assertEquals(11, ModelRegistry.ALL_SCAN_STAGES.length);
    boolean found = false;
    for (ModelRegistry.Entry entry : ModelRegistry.ALL_SCAN_STAGES) {
      if (ModelRegistry.DEXHEADER_BROADCAST_FUSION.modelId.equals(entry.modelId)) {
        found = true;
        break;
      }
    }
    assertTrue(found);
  }

  @Test
  public void broadcastMldpHybrid_assetsMatchExportManifest() {
    assertEquals("broadcast_mldp_hybrid", ModelRegistry.BROADCAST_MLDP_HYBRID.modelId);
    assertEquals("manifest_mldp_perm_receiver_actions", ModelRegistry.BROADCAST_MLDP_HYBRID.domain);
    assertEquals(
        BroadcastMldpHybridOnnxRunner.MODEL_ID, ModelRegistry.BROADCAST_MLDP_HYBRID.modelId);
    assertEquals(
        BroadcastMldpHybridOnnxRunner.DOMAIN, ModelRegistry.BROADCAST_MLDP_HYBRID.domain);
    assertTrue(
        ModelRegistry.BROADCAST_MLDP_HYBRID.assetsPrefix.contains("broadcast_mldp_hybrid"));
  }
}
