package com.msh.vigidroid.pipeline.legacy;

import com.msh.vigidroid.CascadePolicy;
import com.msh.vigidroid.FeatureContext;
import com.msh.vigidroid.pipeline.LegacyScanRunner;
import com.msh.vigidroid.pipeline.ModelPipeline;
import com.msh.vigidroid.pipeline.ScanPipelineDependencies;
import com.msh.vigidroid.pipeline.StageResult;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link ModelPipeline} adapters for legacy all-models mode. Execution order and partial-timer
 * semantics are owned by {@link LegacyScanRunner}; these adapters expose the same runners for
 * future cascade wiring and ablation hooks.
 */
public final class LegacyModelPipelines {

  private LegacyModelPipelines() {}

  public static List<ModelPipeline> create(ScanPipelineDependencies deps) {
    LegacyScanRunner runner = new LegacyScanRunner(deps, CascadePolicy.disabledDefault());
    List<ModelPipeline> pipelines = new ArrayList<>();
    pipelines.add(new DelegatingPipeline("mldp_dexheader_cascade_mode_b", "manifest_mldp_perm_dex_header", runner, 0));
    pipelines.add(new DelegatingPipeline("mldp_dexheader_cascade_mode_a", "manifest_mldp_perm_dex_header", runner, 1));
    pipelines.add(new DelegatingPipeline(null, "manifest_xgb", runner, 2));
    pipelines.add(new DelegatingPipeline(null, "bytecnn", runner, 3));
    pipelines.add(new DelegatingPipeline("broadcast_mldp_hybrid", "manifest_mldp_perm_receiver_actions", runner, 4));
    pipelines.add(new DelegatingPipeline("mlp_header", "dex_header_d3", runner, 5));
    pipelines.add(new DelegatingPipeline("early_fusion_dex_manifest", "dex_header_manifest", runner, 6));
    pipelines.add(new DelegatingPipeline("dual_branch_dex_manifest", "dex_header_manifest_dual", runner, 7));
    pipelines.add(new DelegatingPipeline("linregdroid_permission", "manifest_permissions", runner, 8));
    pipelines.add(new DelegatingPipeline("mldp_pruned_permission", "manifest_permissions_mldp", runner, 9));
    return pipelines;
  }

  /**
   * Thin registry entry — {@link #run(FeatureContext)} is not used in legacy batch scans today;
   * {@link LegacyScanRunner} invokes the full ordered path instead.
   */
  private static final class DelegatingPipeline implements ModelPipeline {
    private final String modelId;
    private final String domain;

    DelegatingPipeline(String modelId, String domain, LegacyScanRunner runner, int index) {
      this.modelId = modelId;
      this.domain = domain;
    }

    @Override
    public String modelId() {
      return modelId;
    }

    @Override
    public String domain() {
      return domain;
    }

    @Override
    public boolean isLoaded() {
      return true;
    }

    @Override
    public StageResult run(FeatureContext ctx) {
      throw new UnsupportedOperationException(
          "Use LegacyScanRunner for ordered legacy scans; cascade orchestrator will call run() later.");
    }

    @Override
    public void close() {}
  }
}
