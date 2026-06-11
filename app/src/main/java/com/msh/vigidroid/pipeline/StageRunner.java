package com.msh.vigidroid.pipeline;

import android.os.SystemClock;

import com.msh.vigidroid.BroadcastMldpHybridExtractor;
import com.msh.vigidroid.DexHeaderFeatureExtractor;
import com.msh.vigidroid.DexheaderBroadcastFusionExtractor;
import com.msh.vigidroid.FeatureContext;
import com.msh.vigidroid.LinRegPermissionExtractor;
import com.msh.vigidroid.ManifestBowExtractor;
import com.msh.vigidroid.MldpDexHeaderCascadeThresholds;
import com.msh.vigidroid.MldpDexHeaderExtractor;
import com.msh.vigidroid.MldpDexHeaderModeBOnnxRunner;
import com.msh.vigidroid.MldpPrunedPermissionExtractor;
import com.msh.vigidroid.ModelRegistry;
import com.msh.vigidroid.ModelThresholds;
import com.msh.vigidroid.OnnxLegacyInference;
import com.msh.vigidroid.XgbFeatureBuilder;

import java.util.Locale;

/** Per-model stage execution shared by legacy all-models and cascade orchestrator. */
public final class StageRunner {

  public interface LogSink {
    void log(String message, String status);
  }

  public static final class XgbRun {
    public final StageResult stage;
    public final int dexFilesFound;
    public final long structuralParsingTimeMs;

    XgbRun(StageResult stage, int dexFilesFound, long structuralParsingTimeMs) {
      this.stage = stage;
      this.dexFilesFound = dexFilesFound;
      this.structuralParsingTimeMs = structuralParsingTimeMs;
    }
  }

  private final ScanPipelineDependencies deps;

  public StageRunner(ScanPipelineDependencies deps) {
    this.deps = deps;
  }

  public static StageResult skipped(ModelRegistry.Entry entry) {
    return skipped(entry, null);
  }

  public static StageResult skipped(ModelRegistry.Entry entry, String reason) {
    StageResult.Builder builder =
        StageResult.builder(entry.domain).modelId(entry.modelId).status(StageResult.STATUS_SKIPPED);
    if (reason != null && !reason.isEmpty()) {
      builder.errorMessage(reason);
    }
    return builder.build();
  }

  public static StageResult error(ModelRegistry.Entry entry, String message) {
    return StageResult.builder(entry.domain)
        .modelId(entry.modelId)
        .status(StageResult.STATUS_ERROR)
        .errorMessage(message)
        .build();
  }

  private static StageResult failStage(
      ModelRegistry.Entry entry, String phase, Exception ex, LogSink log) {
    String message = StageDiagnostics.formatError(entry.modelId, phase, ex);
    StageDiagnostics.logToLogcat(entry.modelId, phase, ex);
    if (log != null) {
      log.log(message, "Error");
    }
    return error(entry, message);
  }

  private static StageResult failStageRuntime(
      ModelRegistry.Entry entry, Exception ex, LogSink log) {
    return failStage(entry, "run", ex, log);
  }

  private static String inferenceErrorMessage(ModelRegistry.Entry entry, String detail) {
    return StageDiagnostics.formatMessage(entry.modelId, "infer", "InferenceFailed", detail);
  }

  private boolean isModelEnabled(String modelId) {
    if (deps.enabledModelIds == null || deps.enabledModelIds.isEmpty()) {
      return true;
    }
    return deps.enabledModelIds.contains(modelId);
  }

  private StageResult skippedIfDisabled(ModelRegistry.Entry entry) {
    if (isModelEnabled(entry.modelId)) {
      return null;
    }
    return skipped(entry, "disabled_by_filter");
  }

  public StageResult runModeB(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.mldpDexHeaderModeBRunner == null || deps.mldpDexHeaderExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      MldpDexHeaderExtractor.PermissionBlockResult perm =
          deps.mldpDexHeaderExtractor.extractPermissionBlock(ctx);
      double parseMs = perm.parseMs();
      double dexMs = 0.0;
      float stage1Score;
      float stage2Score;
      float score;
      boolean earlyExit;

      long inferStart = SystemClock.elapsedRealtimeNanos();
      stage1Score = deps.mldpDexHeaderModeBRunner.predictStage1(perm.xS);
      MldpDexHeaderCascadeThresholds thresholds = deps.mldpDexHeaderModeBRunner.getThresholds();

      if (thresholds.isEarlyExitBenign(stage1Score)
          || thresholds.isEarlyExitMalware(stage1Score)) {
        earlyExit = true;
        stage2Score = MldpDexHeaderModeBOnnxRunner.SKIPPED_STAGE2_SCORE;
        score = stage1Score;
      } else {
        MldpDexHeaderExtractor.DexBlockResult dex =
            deps.mldpDexHeaderExtractor.extractDexBlock(ctx);
        dexMs = dex.dexMs();
        stage2Score = deps.mldpDexHeaderModeBRunner.predictStage2(dex.h);
        score = stage2Score;
        earlyExit = false;
      }
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
      long memDelta = probe.memDeltaBytes();
      double cpuMs = probe.cpuMs();

      if (score >= 0f && log != null) {
        log.log(
            String.format(
                Locale.US,
                "MLDP+Dex cascade Mode B: score=%.4f s1=%.4f s2=%.4f early_exit=%s "
                    + "parse=%.2fms dex=%.2fms infer=%.2fms mem=%d bytes",
                score,
                stage1Score,
                stage2Score,
                earlyExit,
                parseMs,
                dexMs,
                inferMs,
                memDelta),
            null);
      }

      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(parseMs)
          .vectorizeMs(0.0)
          .inferenceMs(inferMs)
          .cpuMs(cpuMs)
          .score(score)
          .memDeltaBytes(memDelta)
          .cascade("B", dexMs, stage1Score, stage2Score, earlyExit)
          .build();
    } catch (Exception ex) {
      return failStageRuntime(entry, ex, log);
    }
  }

  public StageResult runModeA(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_A;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.mldpDexHeaderModeARunner == null || deps.mldpDexHeaderExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    MldpDexHeaderExtractor.ExtractionResult extraction;
    try {
      if (log != null) {
        log.log("Mode A: extract start", null);
      }
      extraction = deps.mldpDexHeaderExtractor.extract(ctx);
      if (log != null) {
        log.log(
            String.format(Locale.US, "Mode A: extract ok x_dim=%d", extraction.x.length),
            null);
      }
    } catch (Exception ex) {
      return failStage(entry, "extract", ex, log);
    }

    float score;
    long inferStart = SystemClock.elapsedRealtimeNanos();
    try {
      if (log != null) {
        log.log("Mode A: infer start", null);
      }
      score = deps.mldpDexHeaderModeARunner.predict(extraction.x);
    } catch (Exception ex) {
      return failStage(entry, "infer", ex, log);
    }
    double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
    long memDelta = probe.memDeltaBytes();

    if (score >= 0f && log != null) {
      log.log(
          String.format(
              Locale.US,
              "MLDP+Dex cascade Mode A: score=%.4f parse=%.2fms dex=%.2fms "
                  + "vec=%.2fms infer=%.2fms mem=%d bytes",
              score,
              (double) extraction.parseMs(),
              (double) extraction.dexMs(),
              (double) extraction.vectorizeMs(),
              inferMs,
              memDelta),
          null);
    }

    return StageResult.builder(entry.domain)
        .modelId(entry.modelId)
        .parseMs(extraction.parseMs())
        .vectorizeMs(extraction.vectorizeMs())
        .inferenceMs(inferMs)
        .cpuMs(probe.cpuMs())
        .score(score)
        .memDeltaBytes(memDelta)
        .cascade("A", extraction.dexMs(), -1f, -1f, false)
        .build();
  }

  public XgbRun runXgb(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.MANIFEST_XGB;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return new XgbRun(disabled, 0, 0L);
    }
    if (deps.xgbSession == null || deps.xgbFeatureIndex.isEmpty()) {
      if (log != null) {
        log.log("XGBoost pipeline skipped (model or features missing)", null);
      }
      return new XgbRun(skipped(entry), 0, 0L);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      XgbFeatureBuilder.Result extraction = XgbFeatureBuilder.build(ctx, deps.xgbFeatureIndex);
      long inferStart = SystemClock.elapsedRealtimeNanos();
      float score =
          OnnxLegacyInference.runXgb(
              deps.ortEnvironment, deps.xgbSession, extraction.aggregatedVector);
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;

      if (score < 0f) {
        return new XgbRun(
            StageResult.builder(entry.domain)
                .modelId(entry.modelId)
                .parseMs(extraction.parseTimeNanos / 1_000_000.0)
                .vectorizeMs(extraction.vectorizeTimeNanos / 1_000_000.0)
                .inferenceMs(inferMs)
                .cpuMs(probe.cpuMs())
                .status(StageResult.STATUS_ERROR)
                .errorMessage(inferenceErrorMessage(entry, "XGB inference failed"))
                .memDeltaBytes(probe.memDeltaBytes())
                .build(),
            extraction.dexFilesFound,
            extraction.structuralParsingTimeMs);
      }

      StageResult stage =
          StageResult.builder(entry.domain)
              .modelId(entry.modelId)
              .parseMs(extraction.parseTimeNanos / 1_000_000.0)
              .vectorizeMs(extraction.vectorizeTimeNanos / 1_000_000.0)
              .inferenceMs(inferMs)
              .cpuMs(probe.cpuMs())
              .score(score)
              .memDeltaBytes(probe.memDeltaBytes())
              .build();
      return new XgbRun(stage, extraction.dexFilesFound, extraction.structuralParsingTimeMs);
    } catch (Exception ex) {
      return new XgbRun(failStageRuntime(entry, ex, log), 0, 0L);
    }
  }

  public StageResult runCnn(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.BYTECNN;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.cnnSession == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    long parseStart = SystemClock.elapsedRealtimeNanos();
    long[] tail = ctx.tailBytes1024();
    double parseMs = (SystemClock.elapsedRealtimeNanos() - parseStart) / 1_000_000.0;

    long inferStart = SystemClock.elapsedRealtimeNanos();
    float score = OnnxLegacyInference.runCnn(deps.ortEnvironment, deps.cnnSession, tail);
    double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;

    if (score < 0f) {
      if (log != null) {
        log.log("ONNX CNN model not initialized", "Error");
      }
      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(parseMs)
          .inferenceMs(inferMs)
          .cpuMs(probe.cpuMs())
          .status(StageResult.STATUS_ERROR)
          .errorMessage(inferenceErrorMessage(entry, "CNN inference failed"))
          .memDeltaBytes(probe.memDeltaBytes())
          .build();
    }
    return StageResult.builder(entry.domain)
        .modelId(entry.modelId)
        .parseMs(parseMs)
        .inferenceMs(inferMs)
        .cpuMs(probe.cpuMs())
        .score(score)
        .memDeltaBytes(probe.memDeltaBytes())
        .build();
  }

  public StageResult runBroadcast(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.BROADCAST_MLDP_HYBRID;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.broadcastMldpRunner == null || deps.broadcastMldpExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    BroadcastMldpHybridExtractor.ExtractionResult extraction;
    try {
      if (log != null) {
        log.log("Broadcast+MLDP: extract start", null);
      }
      extraction = deps.broadcastMldpExtractor.extract(ctx);
      if (log != null) {
        log.log(
            String.format(Locale.US, "Broadcast+MLDP: extract ok vec_dim=%d", extraction.vector.length),
            null);
      }
    } catch (Exception ex) {
      return failStage(entry, "extract", ex, log);
    }

    float score;
    long inferStart = SystemClock.elapsedRealtimeNanos();
    try {
      if (log != null) {
        log.log("Broadcast+MLDP: infer start", null);
      }
      score = deps.broadcastMldpRunner.predict(extraction.vector);
    } catch (Exception ex) {
      return failStage(entry, "infer", ex, log);
    }
    double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
    long memDelta = probe.memDeltaBytes();

    if (score >= 0f && log != null) {
      log.log(
          String.format(
              Locale.US,
              "Broadcast+MLDP: score=%.4f parse=%.2fms vec=%.2fms infer=%.2fms mem=%d bytes",
              score,
              (double) extraction.parseMs(),
              (double) extraction.vectorizeMs(),
              inferMs,
              memDelta),
          null);
    }

    return StageResult.builder(entry.domain)
        .modelId(entry.modelId)
        .parseMs(extraction.parseMs())
        .vectorizeMs(extraction.vectorizeMs())
        .inferenceMs(inferMs)
        .cpuMs(probe.cpuMs())
        .score(score)
        .memDeltaBytes(memDelta)
        .build();
  }

  public StageResult runMlpHeader(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.MLP_HEADER;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.mlpHeaderRunner == null || deps.mlpHeaderExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      DexHeaderFeatureExtractor.ExtractionResult extraction =
          deps.mlpHeaderExtractor.extractFromDexByteArrays(ctx.dexByteArrays());
      long inferStart = SystemClock.elapsedRealtimeNanos();
      float score = deps.mlpHeaderRunner.predict(extraction.features);
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
      long memDelta = probe.memDeltaBytes();

      if (score >= 0f && log != null) {
        log.log(
            String.format(
                Locale.US,
                "BM1 mlp_header: score=%.4f parse=%.2fms norm=%.2fms infer=%.2fms mem=%d bytes",
                score,
                extraction.extractNanos / 1_000_000.0,
                extraction.normalizeNanos / 1_000_000.0,
                inferMs,
                memDelta),
            null);
      }

      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(extraction.extractNanos / 1_000_000.0)
          .vectorizeMs(extraction.normalizeNanos / 1_000_000.0)
          .inferenceMs(inferMs)
          .cpuMs(probe.cpuMs())
          .score(score)
          .memDeltaBytes(memDelta)
          .build();
    } catch (Exception ex) {
      return failStageRuntime(entry, ex, log);
    }
  }

  public StageResult runPatternA(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.EARLY_FUSION_DEX_MANIFEST;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.patternARunner == null
        || deps.patternAHeaderExtractor == null
        || deps.patternABowExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      DexHeaderFeatureExtractor.ExtractionResult header =
          deps.patternAHeaderExtractor.extractFromDexByteArrays(ctx.dexByteArrays());
      ManifestBowExtractor.ExtractionResult bow = deps.patternABowExtractor.extract(ctx);
      long inferStart = SystemClock.elapsedRealtimeNanos();
      float score = deps.patternARunner.predict(header.features, bow.bow);
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
      long memDelta = probe.memDeltaBytes();

      if (score >= 0f && log != null) {
        log.log(
            String.format(
                Locale.US,
                "Early-fusion Dex+manifest: score=%.4f header=%.2fms bow=%.2fms infer=%.2fms mem=%d bytes",
                score,
                header.extractNanos / 1_000_000.0,
                (bow.extractNanos + bow.vectorizeNanos) / 1_000_000.0,
                inferMs,
                memDelta),
            null);
      }

      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(header.extractNanos / 1_000_000.0)
          .vectorizeMs((bow.extractNanos + bow.vectorizeNanos) / 1_000_000.0)
          .inferenceMs(inferMs)
          .cpuMs(probe.cpuMs())
          .score(score)
          .memDeltaBytes(memDelta)
          .build();
    } catch (Exception ex) {
      return failStageRuntime(entry, ex, log);
    }
  }

  public StageResult runPatternB(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.DUAL_BRANCH_DEX_MANIFEST;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.patternBRunner == null
        || deps.patternBHeaderExtractor == null
        || deps.patternBBowExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      DexHeaderFeatureExtractor.ExtractionResult header =
          deps.patternBHeaderExtractor.extractFromDexByteArrays(ctx.dexByteArrays());
      ManifestBowExtractor.ExtractionResult bow = deps.patternBBowExtractor.extract(ctx);
      long inferStart = SystemClock.elapsedRealtimeNanos();
      float score = deps.patternBRunner.predict(header.features, bow.bow);
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
      long memDelta = probe.memDeltaBytes();

      if (score >= 0f && log != null) {
        log.log(
            String.format(
                Locale.US,
                "Dual-branch Dex+manifest: score=%.4f header=%.2fms bow=%.2fms infer=%.2fms mem=%d bytes",
                score,
                header.extractNanos / 1_000_000.0,
                (bow.extractNanos + bow.vectorizeNanos) / 1_000_000.0,
                inferMs,
                memDelta),
            null);
      }

      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(header.extractNanos / 1_000_000.0)
          .vectorizeMs((bow.extractNanos + bow.vectorizeNanos) / 1_000_000.0)
          .inferenceMs(inferMs)
          .cpuMs(probe.cpuMs())
          .score(score)
          .memDeltaBytes(memDelta)
          .build();
    } catch (Exception ex) {
      return failStageRuntime(entry, ex, log);
    }
  }

  public StageResult runLinReg(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.LINREGDROID_PERMISSION;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.linRegRunner == null || deps.linRegExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      LinRegPermissionExtractor.ExtractionResult extraction = deps.linRegExtractor.extract(ctx);
      long inferStart = SystemClock.elapsedRealtimeNanos();
      float score = deps.linRegRunner.predict(extraction.vector);
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
      long memDelta = probe.memDeltaBytes();

      if (score >= 0f && log != null) {
        log.log(
            String.format(
                Locale.US,
                "LinRegDroid: score=%.4f parse=%.2fms vec=%.2fms infer=%.2fms mem=%d bytes",
                score,
                extraction.extractNanos / 1_000_000.0,
                extraction.vectorizeNanos / 1_000_000.0,
                inferMs,
                memDelta),
            null);
      }

      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(extraction.extractNanos / 1_000_000.0)
          .vectorizeMs(extraction.vectorizeNanos / 1_000_000.0)
          .inferenceMs(inferMs)
          .cpuMs(probe.cpuMs())
          .score(score)
          .memDeltaBytes(memDelta)
          .build();
    } catch (Exception ex) {
      return failStageRuntime(entry, ex, log);
    }
  }

  public StageResult runMldpPruned(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.MLDP_PRUNED_PERMISSION;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.mldpRunner == null || deps.mldpExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    try {
      MldpPrunedPermissionExtractor.ExtractionResult extraction = deps.mldpExtractor.extract(ctx);
      long inferStart = SystemClock.elapsedRealtimeNanos();
      float score = deps.mldpRunner.predict(extraction.vector);
      double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
      long memDelta = probe.memDeltaBytes();

      if (score >= 0f && log != null) {
        log.log(
            String.format(
                Locale.US,
                "MLDP pruned: score=%.4f parse=%.2fms vec=%.2fms infer=%.2fms mem=%d bytes",
                score,
                extraction.extractNanos / 1_000_000.0,
                extraction.vectorizeNanos / 1_000_000.0,
                inferMs,
                memDelta),
            null);
      }

      return StageResult.builder(entry.domain)
          .modelId(entry.modelId)
          .parseMs(extraction.extractNanos / 1_000_000.0)
          .vectorizeMs(extraction.vectorizeNanos / 1_000_000.0)
          .inferenceMs(inferMs)
          .cpuMs(probe.cpuMs())
          .score(score)
          .memDeltaBytes(memDelta)
          .build();
    } catch (Exception ex) {
      return failStageRuntime(entry, ex, log);
    }
  }

  public StageResult runDexheaderBroadcastFusion(FeatureContext ctx, LogSink log) {
    ModelRegistry.Entry entry = ModelRegistry.DEXHEADER_BROADCAST_FUSION;
    StageResult disabled = skippedIfDisabled(entry);
    if (disabled != null) {
      return disabled;
    }
    if (deps.dexheaderBroadcastFusionRunner == null || deps.dexheaderBroadcastFusionExtractor == null) {
      return skipped(entry);
    }
    StageResourceProbe probe = new StageResourceProbe();
    DexheaderBroadcastFusionExtractor.ExtractionResult extraction;
    try {
      if (log != null) {
        log.log("Dex+Broadcast fusion: extract start", null);
      }
      extraction = deps.dexheaderBroadcastFusionExtractor.extract(ctx);
      if (log != null) {
        log.log(
            String.format(
                Locale.US,
                "Dex+Broadcast fusion: extract ok header_dim=%d receiver_dim=%d",
                extraction.header.length,
                extraction.receiver.length),
            null);
      }
    } catch (Exception ex) {
      return failStage(entry, "extract", ex, log);
    }

    float score;
    long inferStart = SystemClock.elapsedRealtimeNanos();
    try {
      if (log != null) {
        log.log("Dex+Broadcast fusion: infer start", null);
      }
      score = deps.dexheaderBroadcastFusionRunner.predict(extraction.header, extraction.receiver);
    } catch (Exception ex) {
      return failStage(entry, "infer", ex, log);
    }
    double inferMs = (SystemClock.elapsedRealtimeNanos() - inferStart) / 1_000_000.0;
    long memDelta = probe.memDeltaBytes();

    if (score >= 0f && log != null) {
      log.log(
          String.format(
              Locale.US,
              "Dex+Broadcast fusion: score=%.4f parse=%.2fms dex=%.2fms vec=%.2fms infer=%.2fms mem=%d bytes",
              score,
              (double) extraction.parseMs,
              (double) extraction.dexMs,
              (double) extraction.vectorizeMs,
              inferMs,
              memDelta),
          null);
    }

    return StageResult.builder(entry.domain)
        .modelId(entry.modelId)
        .parseMs(extraction.parseMs + extraction.dexMs)
        .vectorizeMs(extraction.vectorizeMs)
        .inferenceMs(inferMs)
        .cpuMs(probe.cpuMs())
        .score(score)
        .memDeltaBytes(memDelta)
        .build();
  }

  public float malwareThresholdFor(String modelId) {
    try {
      if (ModelRegistry.MLDP_PRUNED_PERMISSION.modelId.equals(modelId) && deps.mldpRunner != null) {
        return deps.mldpRunner.getThresholds().getMalwareThreshold();
      }
      if (ModelRegistry.BROADCAST_MLDP_HYBRID.modelId.equals(modelId) && deps.broadcastMldpRunner != null) {
        return deps.broadcastMldpRunner.getThresholds().getMalwareThreshold();
      }
    } catch (Exception ignored) {
    }
    return ModelThresholds.DEFAULT_MALWARE_THRESHOLD;
  }
}
