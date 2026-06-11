package com.msh.vigidroid.pipeline;

import android.os.Debug;
import android.os.SystemClock;

import com.msh.vigidroid.CascadePolicy;
import com.msh.vigidroid.FeatureContext;
import com.msh.vigidroid.ModelRegistry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Tier-by-tier cascade with early exit; falls back to skipped stages for audit trail. */
public final class ScanOrchestrator {

  private final ScanPipelineDependencies deps;
  private final CascadePolicy policy;

  public ScanOrchestrator(ScanPipelineDependencies deps, CascadePolicy policy) {
    this.deps = deps;
    this.policy = policy;
  }

  public ScanApkResult run(FeatureContext ctx, String apkName, StageRunner.LogSink log) {
    long wallStart = SystemClock.elapsedRealtimeNanos();
    long cpuStart = Debug.threadCpuTimeNanos();
    long memStart = Debug.getNativeHeapAllocatedSize();

    StageRunner runner = new StageRunner(deps);
    Map<String, StageResult> byDomain = new LinkedHashMap<>();
    for (ModelRegistry.Entry entry : ModelRegistry.ALL_SCAN_STAGES) {
      byDomain.put(
          entry.domain,
          StageRunner.skipped(entry, CascadeResult.SKIP_NOT_RUN));
    }

    List<String> modelsRun = new ArrayList<>();
    int totalDexFilesFound = 0;
    long structuralParsingTimeMs = 0L;

    // --- Tier 1 ---
    CascadePolicy.Tier tier1 = policy.tier(1);
    StageResult mldpStage = runner.runMldpPruned(ctx, log);
    StageResult broadcastStage = runner.runBroadcast(ctx, log);
    putStage(byDomain, mldpStage, modelsRun);
    putStage(byDomain, broadcastStage, modelsRun);

    TierDecision tier1Decision =
        evaluateTier(
            tier1,
            List.of(
                scoreEntry(ModelRegistry.MLDP_PRUNED_PERMISSION.modelId, mldpStage),
                scoreEntry(ModelRegistry.BROADCAST_MLDP_HYBRID.modelId, broadcastStage)),
            runner,
            policy,
            false);
    if (tier1Decision.exit != TierExit.CONTINUE) {
      return finish(
          ctx,
          byDomain,
          modelsRun,
          tier1Decision,
          totalDexFilesFound,
          structuralParsingTimeMs,
          wallStart,
          cpuStart,
          memStart);
    }

    // --- Tier 2 ---
    CascadePolicy.Tier tier2 = policy.tier(2);
    StageResult modeBAttempt = runner.runModeB(ctx, log);
    StageResult tier2Stage = modeBAttempt;
    String tier2ModelId = ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B.modelId;
    if (!StageResult.STATUS_OK.equals(modeBAttempt.status)
        && tier2 != null
        && tier2.mlpHeaderFallback) {
      byDomain.put(
          ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B.domain,
          StageRunner.skipped(
              ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B, "mlp_header_fallback"));
      tier2Stage = runner.runMlpHeader(ctx, log);
      tier2ModelId = ModelRegistry.MLP_HEADER.modelId;
    }
    putStage(byDomain, tier2Stage, modelsRun);

    TierDecision tier2Decision =
        evaluateTier(
            tier2,
            List.of(scoreEntry(tier2ModelId, tier2Stage)),
            runner,
            policy,
            false);
    if (tier2Decision.exit != TierExit.CONTINUE) {
      return finish(
          ctx,
          byDomain,
          modelsRun,
          tier2Decision,
          totalDexFilesFound,
          structuralParsingTimeMs,
          wallStart,
          cpuStart,
          memStart);
    }

    // --- Tier 3 ---
    CascadePolicy.Tier tier3 = policy.tier(3);
    String patternModelId = policy.getTier3PatternModel();
    StageResult patternStage;
    ModelRegistry.Entry patternEntry;
    if (ModelRegistry.DUAL_BRANCH_DEX_MANIFEST.modelId.equals(patternModelId)) {
      patternStage = runner.runPatternB(ctx, log);
      patternEntry = ModelRegistry.DUAL_BRANCH_DEX_MANIFEST;
    } else {
      patternStage = runner.runPatternA(ctx, log);
      patternEntry = ModelRegistry.EARLY_FUSION_DEX_MANIFEST;
    }
    putStage(byDomain, patternStage, modelsRun);

    StageRunner.XgbRun xgbRun = runner.runXgb(ctx, log);
    putStage(byDomain, xgbRun.stage, modelsRun);
    totalDexFilesFound = xgbRun.dexFilesFound;
    structuralParsingTimeMs = xgbRun.structuralParsingTimeMs;

    TierDecision tier3Decision =
        evaluateTier(
            tier3,
            List.of(
                scoreEntry(patternEntry.modelId, patternStage),
                scoreEntry(ModelRegistry.MANIFEST_XGB.modelId, xgbRun.stage)),
            runner,
            policy,
            false);
    if (tier3Decision.exit != TierExit.CONTINUE) {
      return finish(
          ctx,
          byDomain,
          modelsRun,
          tier3Decision,
          totalDexFilesFound,
          structuralParsingTimeMs,
          wallStart,
          cpuStart,
          memStart);
    }

    // --- Tier 4 (final fusion) ---
    CascadePolicy.Tier tier4 = policy.tier(4);
    StageResult cnnStage = runner.runCnn(ctx, log);
    putStage(byDomain, cnnStage, modelsRun);

    float finalScore =
        fuseTier4(patternStage, patternEntry.modelId, xgbRun.stage, cnnStage);

    TierDecision tier4Decision =
        new TierDecision(
            tier4 != null ? tier4.tier : 4,
            TierExit.FINAL,
            finalScore,
            decisionForFinalTier(tier4, finalScore),
            CascadeResult.REASON_FINAL);

    if (log != null && finalScore >= 0f) {
      log.log(
          String.format(
              Locale.US,
              "Cascade tier-4 fusion: score=%.4f (pattern+xgb pool + bytecnn)",
              finalScore),
          null);
    }

    return finish(
        ctx,
        byDomain,
        modelsRun,
        tier4Decision,
        totalDexFilesFound,
        structuralParsingTimeMs,
        wallStart,
        cpuStart,
        memStart);
  }

  private ScanApkResult finish(
      FeatureContext ctx,
      Map<String, StageResult> byDomain,
      List<String> modelsRun,
      TierDecision decision,
      int totalDexFilesFound,
      long structuralParsingTimeMs,
      long wallStart,
      long cpuStart,
      long memStart) {
    List<StageResult> ordered = new ArrayList<>();
    for (ModelRegistry.Entry entry : ModelRegistry.ALL_SCAN_STAGES) {
      ordered.add(byDomain.get(entry.domain));
    }

    List<String> modelsSkipped = cascadeModelsSkipped(modelsRun);

    long cpuEnd = Debug.threadCpuTimeNanos();
    long memEnd = Debug.getNativeHeapAllocatedSize();
    long wallEnd = SystemClock.elapsedRealtimeNanos();
    long javaHeapUsed = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
    Debug.MemoryInfo memoryInfo = new Debug.MemoryInfo();
    Debug.getMemoryInfo(memoryInfo);

    CascadeResult cascade =
        new CascadeResult(
            policy.getPolicyName(),
            decision.tier,
            decision.exitReason,
            modelsRun,
            modelsSkipped,
            decision.score,
            decision.decision);

    return new ScanApkResult(
        ordered,
        ctx.sha256Hex(),
        (wallEnd - wallStart) / 1_000_000.0,
        (cpuEnd - cpuStart) / 1_000_000.0,
        memEnd - memStart,
        javaHeapUsed,
        memoryInfo.getTotalPss(),
        totalDexFilesFound,
        structuralParsingTimeMs,
        ctx.sharedParseMs(),
        decision.score,
        decision.decision,
        cascade);
  }

  private static void putStage(
      Map<String, StageResult> byDomain, StageResult stage, List<String> modelsRun) {
    byDomain.put(stage.domain, stage);
    if (stage.modelId != null
        && StageResult.STATUS_OK.equals(stage.status)
        && !modelsRun.contains(stage.modelId)) {
      modelsRun.add(stage.modelId);
    }
  }

  private static List<String> cascadeModelsSkipped(List<String> modelsRun) {
    String[] cascadeMembers = {
      ModelRegistry.MLDP_PRUNED_PERMISSION.modelId,
      ModelRegistry.BROADCAST_MLDP_HYBRID.modelId,
      ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B.modelId,
      ModelRegistry.MLP_HEADER.modelId,
      ModelRegistry.EARLY_FUSION_DEX_MANIFEST.modelId,
      ModelRegistry.DUAL_BRANCH_DEX_MANIFEST.modelId,
      ModelRegistry.MANIFEST_XGB.modelId,
      ModelRegistry.BYTECNN.modelId,
    };
    List<String> skipped = new ArrayList<>();
    for (String modelId : cascadeMembers) {
      if (!modelsRun.contains(modelId)) {
        skipped.add(modelId);
      }
    }
    return skipped;
  }

  private static final class ScoreEntry {
    final String modelId;
    final float score;

    ScoreEntry(String modelId, float score) {
      this.modelId = modelId;
      this.score = score;
    }
  }

  private static ScoreEntry scoreEntry(String modelId, StageResult stage) {
    float score = -1f;
    if (StageResult.STATUS_OK.equals(stage.status)) {
      score = stage.score;
    }
    return new ScoreEntry(modelId, score);
  }

  private enum TierExit {
    CONTINUE,
    BENIGN,
    MALWARE,
    FINAL
  }

  private static final class TierDecision {
    final int tier;
    final TierExit exit;
    final float score;
    final String decision;
    final String exitReason;

    TierDecision(int tier, TierExit exit, float score, String decision, String exitReason) {
      this.tier = tier;
      this.exit = exit;
      this.score = score;
      this.decision = decision;
      this.exitReason = exitReason;
    }
  }

  private TierDecision evaluateTier(
      CascadePolicy.Tier tier,
      List<ScoreEntry> scores,
      StageRunner runner,
      CascadePolicy policy,
      boolean finalTier) {
    if (tier == null) {
      return new TierDecision(0, TierExit.CONTINUE, -1f, null, null);
    }
    float aggregated = weightedScore(policy, scores);
    if (aggregated < 0f) {
      return new TierDecision(tier.tier, TierExit.CONTINUE, -1f, null, null);
    }

    if (aggregated <= tier.tLow) {
      return new TierDecision(
          tier.tier,
          TierExit.BENIGN,
          aggregated,
          "benign",
          CascadeResult.REASON_LOW_BENIGN);
    }

    boolean conservativeMalware =
        tier.conservativeMalwareOr && conservativeMalwareExit(scores, runner);
    if (aggregated >= tier.tHigh || conservativeMalware) {
      return new TierDecision(
          tier.tier,
          TierExit.MALWARE,
          aggregated,
          "malware",
          CascadeResult.REASON_HIGH_MALWARE);
    }

    if (finalTier) {
      return new TierDecision(
          tier.tier,
          TierExit.FINAL,
          aggregated,
          decisionForFinalTier(tier, aggregated),
          CascadeResult.REASON_FINAL);
    }
    return new TierDecision(tier.tier, TierExit.CONTINUE, aggregated, null, null);
  }

  private static boolean conservativeMalwareExit(List<ScoreEntry> scores, StageRunner runner) {
    for (ScoreEntry entry : scores) {
      if (entry.score >= 0f && entry.score >= runner.malwareThresholdFor(entry.modelId)) {
        return true;
      }
    }
    return false;
  }

  private static float weightedScore(CascadePolicy policy, List<ScoreEntry> scores) {
    double weighted = 0.0;
    double totalWeight = 0.0;
    for (ScoreEntry entry : scores) {
      if (entry.score < 0f) {
        continue;
      }
      double w = policy.weightFor(entry.modelId);
      weighted += w * entry.score;
      totalWeight += w;
    }
    if (totalWeight <= 0.0) {
      return -1f;
    }
    return (float) (weighted / totalWeight);
  }

  private float fuseTier4(
      StageResult patternStage, String patternModelId, StageResult xgbStage, StageResult cnnStage) {
    List<ScoreEntry> scores = new ArrayList<>();
    if (StageResult.STATUS_OK.equals(patternStage.status) && patternStage.score >= 0f) {
      scores.add(new ScoreEntry(patternModelId, patternStage.score));
    }
    if (StageResult.STATUS_OK.equals(xgbStage.status) && xgbStage.score >= 0f) {
      scores.add(new ScoreEntry(ModelRegistry.MANIFEST_XGB.modelId, xgbStage.score));
    }
    if (StageResult.STATUS_OK.equals(cnnStage.status) && cnnStage.score >= 0f) {
      scores.add(new ScoreEntry(ModelRegistry.BYTECNN.modelId, cnnStage.score));
    }
    if (scores.isEmpty()) {
      return -1f;
    }

    double weighted = 0.0;
    double totalWeight = 0.0;
    for (ScoreEntry entry : scores) {
      double w = policy.fusionWeightFor(entry.modelId);
      weighted += w * entry.score;
      totalWeight += w;
    }
    if (totalWeight <= 0.0) {
      return -1f;
    }
    return (float) (weighted / totalWeight);
  }

  private static String decisionForFinalTier(CascadePolicy.Tier tier, float score) {
    if (tier == null) {
      return score >= 0.5f ? "malware" : "benign";
    }
    if (score <= tier.tLow) {
      return "benign";
    }
    if (score >= tier.tHigh) {
      return "malware";
    }
    if (tier.tLow < tier.tHigh) {
      return "uncertain";
    }
    float tMid = (float) ((tier.tLow + tier.tHigh) / 2.0);
    return score >= tMid ? "malware" : "benign";
  }
}
