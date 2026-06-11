package com.msh.vigidroid.pipeline;

import com.msh.vigidroid.BroadcastMldpHybridExtractor;
import com.msh.vigidroid.BroadcastMldpHybridOnnxRunner;
import com.msh.vigidroid.DexHeaderFeatureExtractor;
import com.msh.vigidroid.DexheaderBroadcastFusionExtractor;
import com.msh.vigidroid.DexheaderBroadcastFusionOnnxRunner;
import com.msh.vigidroid.LinRegDroidOnnxRunner;
import com.msh.vigidroid.LinRegPermissionExtractor;
import com.msh.vigidroid.ManifestBowExtractor;
import com.msh.vigidroid.MldpDexHeaderExtractor;
import com.msh.vigidroid.MldpDexHeaderModeAOnnxRunner;
import com.msh.vigidroid.MldpDexHeaderModeBOnnxRunner;
import com.msh.vigidroid.MldpPrunedOnnxRunner;
import com.msh.vigidroid.MldpPrunedPermissionExtractor;
import com.msh.vigidroid.MlpHeaderOnnxRunner;
import com.msh.vigidroid.PatternAOnnxRunner;
import com.msh.vigidroid.PatternBOnnxRunner;

import java.util.Map;
import java.util.Set;

import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtSession;

/**
 * ONNX runners, extractors, and legacy XGB feature index — shared by legacy scan pipelines.
 */
public final class ScanPipelineDependencies {

  public final OrtEnvironment ortEnvironment;
  public final OrtSession xgbSession;
  public final OrtSession cnnSession;
  public final Map<String, Integer> xgbFeatureIndex;

  public final MlpHeaderOnnxRunner mlpHeaderRunner;
  public final DexHeaderFeatureExtractor mlpHeaderExtractor;

  public final PatternAOnnxRunner patternARunner;
  public final DexHeaderFeatureExtractor patternAHeaderExtractor;
  public final ManifestBowExtractor patternABowExtractor;

  public final PatternBOnnxRunner patternBRunner;
  public final DexHeaderFeatureExtractor patternBHeaderExtractor;
  public final ManifestBowExtractor patternBBowExtractor;

  public final LinRegDroidOnnxRunner linRegRunner;
  public final LinRegPermissionExtractor linRegExtractor;

  public final MldpPrunedOnnxRunner mldpRunner;
  public final MldpPrunedPermissionExtractor mldpExtractor;

  public final BroadcastMldpHybridOnnxRunner broadcastMldpRunner;
  public final BroadcastMldpHybridExtractor broadcastMldpExtractor;

  public final MldpDexHeaderExtractor mldpDexHeaderExtractor;
  public final MldpDexHeaderModeAOnnxRunner mldpDexHeaderModeARunner;
  public final MldpDexHeaderModeBOnnxRunner mldpDexHeaderModeBRunner;

  public final DexheaderBroadcastFusionOnnxRunner dexheaderBroadcastFusionRunner;
  public final DexheaderBroadcastFusionExtractor dexheaderBroadcastFusionExtractor;

  /** When non-null and non-empty, only these {@code model_id}s run (ablation / plan §2.1 #9). */
  public Set<String> enabledModelIds;

  public ScanPipelineDependencies(
      OrtEnvironment ortEnvironment,
      OrtSession xgbSession,
      OrtSession cnnSession,
      Map<String, Integer> xgbFeatureIndex,
      MlpHeaderOnnxRunner mlpHeaderRunner,
      DexHeaderFeatureExtractor mlpHeaderExtractor,
      PatternAOnnxRunner patternARunner,
      DexHeaderFeatureExtractor patternAHeaderExtractor,
      ManifestBowExtractor patternABowExtractor,
      PatternBOnnxRunner patternBRunner,
      DexHeaderFeatureExtractor patternBHeaderExtractor,
      ManifestBowExtractor patternBBowExtractor,
      LinRegDroidOnnxRunner linRegRunner,
      LinRegPermissionExtractor linRegExtractor,
      MldpPrunedOnnxRunner mldpRunner,
      MldpPrunedPermissionExtractor mldpExtractor,
      BroadcastMldpHybridOnnxRunner broadcastMldpRunner,
      BroadcastMldpHybridExtractor broadcastMldpExtractor,
      MldpDexHeaderExtractor mldpDexHeaderExtractor,
      MldpDexHeaderModeAOnnxRunner mldpDexHeaderModeARunner,
      MldpDexHeaderModeBOnnxRunner mldpDexHeaderModeBRunner,
      DexheaderBroadcastFusionOnnxRunner dexheaderBroadcastFusionRunner,
      DexheaderBroadcastFusionExtractor dexheaderBroadcastFusionExtractor) {
    this.ortEnvironment = ortEnvironment;
    this.xgbSession = xgbSession;
    this.cnnSession = cnnSession;
    this.xgbFeatureIndex = xgbFeatureIndex;
    this.mlpHeaderRunner = mlpHeaderRunner;
    this.mlpHeaderExtractor = mlpHeaderExtractor;
    this.patternARunner = patternARunner;
    this.patternAHeaderExtractor = patternAHeaderExtractor;
    this.patternABowExtractor = patternABowExtractor;
    this.patternBRunner = patternBRunner;
    this.patternBHeaderExtractor = patternBHeaderExtractor;
    this.patternBBowExtractor = patternBBowExtractor;
    this.linRegRunner = linRegRunner;
    this.linRegExtractor = linRegExtractor;
    this.mldpRunner = mldpRunner;
    this.mldpExtractor = mldpExtractor;
    this.broadcastMldpRunner = broadcastMldpRunner;
    this.broadcastMldpExtractor = broadcastMldpExtractor;
    this.mldpDexHeaderExtractor = mldpDexHeaderExtractor;
    this.mldpDexHeaderModeARunner = mldpDexHeaderModeARunner;
    this.mldpDexHeaderModeBRunner = mldpDexHeaderModeBRunner;
    this.dexheaderBroadcastFusionRunner = dexheaderBroadcastFusionRunner;
    this.dexheaderBroadcastFusionExtractor = dexheaderBroadcastFusionExtractor;
  }
}
