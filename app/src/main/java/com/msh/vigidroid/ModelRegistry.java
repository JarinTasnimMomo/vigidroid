package com.msh.vigidroid;

/**
 * Canonical {@code model_id} → assets path → scan {@code domain} mapping.
 * Asset subdirs under {@code app/src/main/assets/models/{model_id}/} must match
 * {@code model_id} in each bundle's {@code export_manifest.json} (fusion / multistep).
 */
public final class ModelRegistry {

  public static final class Entry {
    public final String modelId;
    public final String domain;
    public final String assetsPrefix;

    Entry(String modelId, String domain, String assetsPrefix) {
      this.modelId = modelId;
      this.domain = domain;
      this.assetsPrefix = assetsPrefix;
    }
  }

  public static final Entry LINREGDROID_PERMISSION =
      new Entry(
          LinRegDroidOnnxRunner.MODEL_ID,
          LinRegDroidOnnxRunner.DOMAIN,
          "models/linregdroid_permission/");

  public static final Entry MLDP_PRUNED_PERMISSION =
      new Entry(
          MldpPrunedOnnxRunner.MODEL_ID,
          MldpPrunedOnnxRunner.DOMAIN,
          "models/mldp_pruned_permission/");

  public static final Entry BROADCAST_MLDP_HYBRID =
      new Entry(
          BroadcastMldpHybridOnnxRunner.MODEL_ID,
          BroadcastMldpHybridOnnxRunner.DOMAIN,
          "models/broadcast_mldp_hybrid/");

  public static final Entry MLP_HEADER =
      new Entry(MlpHeaderOnnxRunner.MODEL_ID, MlpHeaderOnnxRunner.DOMAIN, "models/mlp_header/");

  public static final Entry EARLY_FUSION_DEX_MANIFEST =
      new Entry(
          PatternAOnnxRunner.MODEL_ID,
          PatternAOnnxRunner.DOMAIN,
          "models/early_fusion_dex_manifest/");

  public static final Entry DUAL_BRANCH_DEX_MANIFEST =
      new Entry(
          PatternBOnnxRunner.MODEL_ID,
          PatternBOnnxRunner.DOMAIN,
          "models/dual_branch_dex_manifest/");

  public static final Entry MLDP_DEXHEADER_CASCADE_MODE_A =
      new Entry(
          MldpDexHeaderModeAOnnxRunner.MODEL_ID,
          MldpDexHeaderModeAOnnxRunner.DOMAIN,
          "models/mldp_dexheader_cascade/mode_a/");

  public static final Entry MLDP_DEXHEADER_CASCADE_MODE_B =
      new Entry(
          MldpDexHeaderModeBOnnxRunner.MODEL_ID,
          MldpDexHeaderModeBOnnxRunner.DOMAIN,
          "models/mldp_dexheader_cascade/mode_b/");

  public static final Entry DEXHEADER_BROADCAST_FUSION =
      new Entry(
          DexheaderBroadcastFusionOnnxRunner.MODEL_ID,
          DexheaderBroadcastFusionOnnxRunner.DOMAIN,
          "models/dexheader_broadcast_fusion/");

  /** Legacy root-asset ONNX (not under {@code models/}). */
  public static final Entry MANIFEST_XGB =
      new Entry("manifest_xgb", "manifest_xgb", "mh1m_2500_rp_XGBoost.onnx");

  public static final Entry BYTECNN =
      new Entry("bytecnn", "bytecnn", "bytecnn_basemodel_2020.onnx");

  /** MoMo + thesis ONNX bundles registered in ScanService stages[]. */
  public static final Entry[] REGISTERED_MODELS = {
    LINREGDROID_PERMISSION,
    MLDP_PRUNED_PERMISSION,
    BROADCAST_MLDP_HYBRID,
    MLP_HEADER,
    EARLY_FUSION_DEX_MANIFEST,
    DUAL_BRANCH_DEX_MANIFEST,
    MLDP_DEXHEADER_CASCADE_MODE_A,
    MLDP_DEXHEADER_CASCADE_MODE_B,
    DEXHEADER_BROADCAST_FUSION,
  };

  /** All pipelines written to {@code stages[]}, including legacy XGB + ByteCNN. */
  public static final Entry[] ALL_SCAN_STAGES = {
    MLDP_DEXHEADER_CASCADE_MODE_B,
    MLDP_DEXHEADER_CASCADE_MODE_A,
    MANIFEST_XGB,
    BYTECNN,
    BROADCAST_MLDP_HYBRID,
    MLP_HEADER,
    EARLY_FUSION_DEX_MANIFEST,
    DUAL_BRANCH_DEX_MANIFEST,
    LINREGDROID_PERMISSION,
    MLDP_PRUNED_PERMISSION,
    DEXHEADER_BROADCAST_FUSION,
  };

  public static Entry entryForDomain(String domain) {
    for (Entry entry : ALL_SCAN_STAGES) {
      if (entry.domain.equals(domain)) {
        return entry;
      }
    }
    return null;
  }

  private ModelRegistry() {}
}
