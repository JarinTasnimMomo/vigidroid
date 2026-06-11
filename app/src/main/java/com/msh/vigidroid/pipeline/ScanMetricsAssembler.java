package com.msh.vigidroid.pipeline;

import com.msh.vigidroid.BatterySampler;
import com.msh.vigidroid.CascadePolicy;
import com.msh.vigidroid.EvalLabelParser;
import com.msh.vigidroid.MetricsWriter;
import com.msh.vigidroid.ModelRegistry;

import java.io.File;

/** Build {@link MetricsWriter.ScanMetrics} from a legacy {@link ScanApkResult}. */
public final class ScanMetricsAssembler {

  private ScanMetricsAssembler() {}

  public static MetricsWriter.ScanMetrics toScanMetrics(
      String trigger,
      File apk,
      ScanApkResult result,
      CascadePolicy policy,
      boolean cascadeEnabled,
      BatterySampler.Snapshot batteryStart,
      BatterySampler.Snapshot batteryEnd) {
    MetricsWriter.ScanMetrics scan = new MetricsWriter.ScanMetrics();
    scan.trigger = trigger;
    scan.groundTruth = EvalLabelParser.groundTruthFromApkName(apk.getName());
    scan.apkName = apk.getName();
    scan.apkPath = apk.getAbsolutePath();
    scan.apkSizeBytes = apk.length();
    scan.apkSha256 = result.apkSha256;
    scan.wallMs = result.wallMs;
    scan.cpuMs = result.cpuMs;
    scan.memDeltaBytes = result.memDeltaBytes;
    scan.javaHeapUsedBytes = result.javaHeapUsedBytes;
    scan.peakTotalPssKb = result.peakTotalPssKb;
    scan.totalDexFilesFound = result.totalDexFilesFound;
    scan.structuralParsingTimeMs = result.structuralParsingTimeMs;
    scan.sharedParseMs = result.sharedParseMs;

    for (StageResult stage : result.stages) {
      scan.stages.add(toStageMetrics(stage));
    }

    if (result.ensembleScore >= 0f) {
      scan.ensembleScore = result.ensembleScore;
      scan.ensembleDecision = result.ensembleDecision;
      if (result.cascade != null) {
        scan.ensemblePolicy = result.cascade.policyName;
        scan.cascadePolicy = result.cascade.policyName;
        scan.cascadeExitTier = result.cascade.exitTier;
        scan.cascadeExitReason = result.cascade.exitReason;
        scan.cascadeFinalScore = result.cascade.finalScore;
        scan.cascadeDecision = result.cascade.decision;
        scan.cascadeModelsRun = result.cascade.modelsRun;
        scan.cascadeModelsSkipped = result.cascade.modelsSkipped;
      } else if (policy != null) {
        scan.ensemblePolicy = policy.getLegacyEnsemblePolicy();
      } else {
        scan.ensemblePolicy = "legacy_xgb_cnn";
      }
    }

    scan.cascadeEnabled = cascadeEnabled;
    scan.batteryPctDelta = MetricsWriter.capacityPctDelta(batteryStart, batteryEnd);
    return scan;
  }

  public static MetricsWriter.ScanMetrics dedupSkipped(
      String trigger, File apk, String sha256, String sessionId, boolean cascadeEnabled) {
    MetricsWriter.ScanMetrics scan = new MetricsWriter.ScanMetrics();
    scan.dedupSkipped = true;
    scan.trigger = trigger;
    scan.sessionId = sessionId;
    scan.cascadeEnabled = cascadeEnabled;
    scan.groundTruth = EvalLabelParser.groundTruthFromApkName(apk.getName());
    scan.apkName = apk.getName();
    scan.apkPath = apk.getAbsolutePath();
    scan.apkSizeBytes = apk.length();
    scan.apkSha256 = sha256;
    return scan;
  }

  private static MetricsWriter.StageMetrics toStageMetrics(StageResult stage) {
    String modelId = stage.modelId;
    if (modelId == null || modelId.isEmpty()) {
      ModelRegistry.Entry entry = ModelRegistry.entryForDomain(stage.domain);
      if (entry != null) {
        modelId = entry.modelId;
      }
    }

    if (stage.cascade) {
      return MetricsWriter.StageMetrics.cascade(
          stage.domain,
          modelId,
          stage.cascadeMode,
          stage.parseMs,
          stage.dexMs,
          stage.vectorizeMs,
          stage.inferenceMs,
          stage.cpuMs,
          stage.stage1Score,
          stage.stage2Score,
          stage.earlyExit,
          stage.status,
          stage.errorMessage,
          stage.score,
          stage.memDeltaBytes);
    }

    return new MetricsWriter.StageMetrics(
        stage.domain,
        modelId,
        stage.parseMs,
        stage.vectorizeMs,
        stage.inferenceMs,
        stage.cpuMs,
        stage.status,
        stage.errorMessage,
        stage.score,
        stage.memDeltaBytes);
  }
}
