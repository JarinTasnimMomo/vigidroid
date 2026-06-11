package com.msh.vigidroid.pipeline;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Aggregated legacy scan output for one APK. */
public final class ScanApkResult {

  /** Fixed-order stage list ({@link ModelRegistry#ALL_SCAN_STAGES}), always length 10. */
  public final List<StageResult> stages;

  public final String apkSha256;
  public final double wallMs;
  public final double cpuMs;
  public final long memDeltaBytes;
  public final long javaHeapUsedBytes;
  public final int peakTotalPssKb;

  public final int totalDexFilesFound;
  public final long structuralParsingTimeMs;
  public final double sharedParseMs;

  public final float ensembleScore;
  public final String ensembleDecision;

  /** Non-null when scan used the cascade orchestrator. */
  public final CascadeResult cascade;

  public ScanApkResult(
      List<StageResult> stages,
      String apkSha256,
      double wallMs,
      double cpuMs,
      long memDeltaBytes,
      long javaHeapUsedBytes,
      int peakTotalPssKb,
      int totalDexFilesFound,
      long structuralParsingTimeMs,
      double sharedParseMs,
      float ensembleScore,
      String ensembleDecision) {
    this(
        stages,
        apkSha256,
        wallMs,
        cpuMs,
        memDeltaBytes,
        javaHeapUsedBytes,
        peakTotalPssKb,
        totalDexFilesFound,
        structuralParsingTimeMs,
        sharedParseMs,
        ensembleScore,
        ensembleDecision,
        null);
  }

  public ScanApkResult(
      List<StageResult> stages,
      String apkSha256,
      double wallMs,
      double cpuMs,
      long memDeltaBytes,
      long javaHeapUsedBytes,
      int peakTotalPssKb,
      int totalDexFilesFound,
      long structuralParsingTimeMs,
      double sharedParseMs,
      float ensembleScore,
      String ensembleDecision,
      CascadeResult cascade) {
    this.stages = Collections.unmodifiableList(new ArrayList<>(stages));
    this.apkSha256 = apkSha256;
    this.wallMs = wallMs;
    this.cpuMs = cpuMs;
    this.memDeltaBytes = memDeltaBytes;
    this.javaHeapUsedBytes = javaHeapUsedBytes;
    this.peakTotalPssKb = peakTotalPssKb;
    this.totalDexFilesFound = totalDexFilesFound;
    this.structuralParsingTimeMs = structuralParsingTimeMs;
    this.sharedParseMs = sharedParseMs;
    this.ensembleScore = ensembleScore;
    this.ensembleDecision = ensembleDecision;
    this.cascade = cascade;
  }

  public StageResult stageForDomain(String domain) {
    for (StageResult stage : stages) {
      if (stage.domain.equals(domain)) {
        return stage;
      }
    }
    return null;
  }
}
