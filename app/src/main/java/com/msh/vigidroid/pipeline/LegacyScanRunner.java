package com.msh.vigidroid.pipeline;

import android.os.Debug;
import android.os.SystemClock;

import com.msh.vigidroid.CascadePolicy;
import com.msh.vigidroid.FeatureContext;
import com.msh.vigidroid.FusionScorer;
import com.msh.vigidroid.ModelRegistry;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;

/** Legacy all-models scan: runs every loaded pipeline on each APK (no cascade early-exit). */
public final class LegacyScanRunner {

  private final StageRunner stageRunner;
  private final CascadePolicy policy;

  public LegacyScanRunner(ScanPipelineDependencies deps, CascadePolicy policy) {
    this.stageRunner = new StageRunner(deps);
    this.policy = policy != null ? policy : CascadePolicy.disabledDefault();
  }

  public ScanApkResult run(FeatureContext ctx, String apkName, StageRunner.LogSink log) {
    long wallStart = SystemClock.elapsedRealtimeNanos();
    long cpuStart = Debug.threadCpuTimeNanos();
    long memStart = Debug.getNativeHeapAllocatedSize();

    StageResult modeB = runTimed(ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B, () -> stageRunner.runModeB(ctx, log), log);
    StageResult modeA = runTimed(ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_A, () -> stageRunner.runModeA(ctx, log), log);
    StageRunner.XgbRun xgbRun = runTimedXgb(() -> stageRunner.runXgb(ctx, log), log);
    StageResult xgbStage = xgbRun.stage;
    StageResult cnnStage = runTimed(ModelRegistry.BYTECNN, () -> stageRunner.runCnn(ctx, log), log);
    StageResult broadcast = runTimed(ModelRegistry.BROADCAST_MLDP_HYBRID, () -> stageRunner.runBroadcast(ctx, log), log);
    StageResult mlp = runTimed(ModelRegistry.MLP_HEADER, () -> stageRunner.runMlpHeader(ctx, log), log);
    StageResult patternA =
        runTimed(ModelRegistry.EARLY_FUSION_DEX_MANIFEST, () -> stageRunner.runPatternA(ctx, log), log);
    StageResult patternB =
        runTimed(ModelRegistry.DUAL_BRANCH_DEX_MANIFEST, () -> stageRunner.runPatternB(ctx, log), log);
    StageResult linReg = runTimed(ModelRegistry.LINREGDROID_PERMISSION, () -> stageRunner.runLinReg(ctx, log), log);
    StageResult mldp = runTimed(ModelRegistry.MLDP_PRUNED_PERMISSION, () -> stageRunner.runMldpPruned(ctx, log), log);
    StageResult dexBroadcastFusion =
        runTimed(
            ModelRegistry.DEXHEADER_BROADCAST_FUSION,
            () -> stageRunner.runDexheaderBroadcastFusion(ctx, log),
            log);

    List<StageResult> orderedStages =
        List.of(
            modeB,
            modeA,
            xgbStage,
            cnnStage,
            broadcast,
            mlp,
            patternA,
            patternB,
            linReg,
            mldp,
            dexBroadcastFusion);

    long cpuEnd = Debug.threadCpuTimeNanos();
    long memEnd = Debug.getNativeHeapAllocatedSize();
    long wallEnd = SystemClock.elapsedRealtimeNanos();
    long memDelta = memEnd - memStart;
    long javaHeapUsed = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
    Debug.MemoryInfo memoryInfo = new Debug.MemoryInfo();
    Debug.getMemoryInfo(memoryInfo);
    int peakTotalPssKb = memoryInfo.getTotalPss();

    float ensemble = FusionScorer.legacyXgbCnnScore(policy, xgbStage.score, cnnStage.score);
    String ensembleDecision = FusionScorer.legacyDecision(ensemble);

    if (StageResult.STATUS_OK.equals(xgbStage.status)) {
      log.log(
          String.format(
              Locale.US,
              "XGBoost: score=%.4f parse=%.2fms vec=%.2fms infer=%.2fms mem=%d bytes",
              xgbStage.score,
              xgbStage.parseMs,
              xgbStage.vectorizeMs,
              xgbStage.inferenceMs,
              xgbStage.memDeltaBytes),
          null);
    }
    if (!StageResult.STATUS_SKIPPED.equals(cnnStage.status)) {
      log.log(
          String.format(
              Locale.US,
              "1D-CNN: score=%.4f parse=%.2fms infer=%.2fms mem=%d bytes",
              cnnStage.score,
              cnnStage.parseMs,
              cnnStage.inferenceMs,
              cnnStage.memDeltaBytes),
          null);
    }

    return new ScanApkResult(
        orderedStages,
        ctx.sha256Hex(),
        (wallEnd - wallStart) / 1_000_000.0,
        (cpuEnd - cpuStart) / 1_000_000.0,
        memDelta,
        javaHeapUsed,
        peakTotalPssKb,
        xgbRun.dexFilesFound,
        xgbRun.structuralParsingTimeMs,
        ctx.sharedParseMs(),
        ensemble,
        ensembleDecision,
        null);
  }

  private StageResult runTimed(
      ModelRegistry.Entry entry, Callable<StageResult> work, StageRunner.LogSink log) {
    try {
      return StageTimeouts.run(work, StageTimeouts.DEFAULT_MS);
    } catch (TimeoutException ex) {
      String message =
          StageDiagnostics.formatMessage(
              entry.modelId, "run", "StageTimeout", "exceeded " + StageTimeouts.DEFAULT_MS + "ms");
      if (log != null) {
        log.log(message, "Error");
      }
      return StageRunner.error(entry, message);
    } catch (Exception ex) {
      return StageRunner.error(entry, StageDiagnostics.formatError(entry.modelId, "run", ex));
    }
  }

  private StageRunner.XgbRun runTimedXgb(Callable<StageRunner.XgbRun> work, StageRunner.LogSink log) {
    try {
      return StageTimeouts.run(work, StageTimeouts.DEFAULT_MS);
    } catch (TimeoutException ex) {
      ModelRegistry.Entry entry = ModelRegistry.MANIFEST_XGB;
      String message =
          StageDiagnostics.formatMessage(
              entry.modelId, "run", "StageTimeout", "exceeded " + StageTimeouts.DEFAULT_MS + "ms");
      if (log != null) {
        log.log(message, "Error");
      }
      return new StageRunner.XgbRun(StageRunner.error(entry, message), 0, 0L);
    } catch (Exception ex) {
      ModelRegistry.Entry entry = ModelRegistry.MANIFEST_XGB;
      return new StageRunner.XgbRun(
          StageRunner.error(entry, StageDiagnostics.formatError(entry.modelId, "run", ex)), 0, 0L);
    }
  }
}
