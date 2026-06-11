package com.msh.vigidroid;

import android.os.SystemClock;

import java.io.ByteArrayInputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Build the 2500-d aggregated XGB manifest+DEX vector from a shared {@link FeatureContext}.
 */
public final class XgbFeatureBuilder {

  public static final int FEATURE_DIM = 2500;

  public static final class Result {
    public final float[] aggregatedVector;
    public final int dexFilesFound;
    public final long structuralParsingTimeMs;
    public final long parseTimeNanos;
    public final long vectorizeTimeNanos;

    Result(
        float[] aggregatedVector,
        int dexFilesFound,
        long structuralParsingTimeMs,
        long parseTimeNanos,
        long vectorizeTimeNanos) {
      this.aggregatedVector = aggregatedVector;
      this.dexFilesFound = dexFilesFound;
      this.structuralParsingTimeMs = structuralParsingTimeMs;
      this.parseTimeNanos = parseTimeNanos;
      this.vectorizeTimeNanos = vectorizeTimeNanos;
    }
  }

  private XgbFeatureBuilder() {}

  public static Result build(FeatureContext ctx, Map<String, Integer> featureIndex) {
    float[] aggregatedVector = new float[FEATURE_DIM];
    long parseTimeNanos = 0L;
    long vectorizeTimeNanos = 0L;
    long structuralParsingStart = SystemClock.elapsedRealtimeNanos();

    long manifestVectorStart = SystemClock.elapsedRealtimeNanos();
    float[] manifestVector = vectorize(ctx.xgbManifestTokens(), featureIndex);
    vectorizeTimeNanos += SystemClock.elapsedRealtimeNanos() - manifestVectorStart;
    orPoolInto(aggregatedVector, manifestVector);

    int dexFilesFound = ctx.dexFilesFound();
    for (byte[] dexBytes : ctx.dexByteArrays()) {
      long dexParseStart = SystemClock.elapsedRealtimeNanos();
      Set<String> dexFeatures = new HashSet<>();
      try {
        MinimalDexParser.parse(new ByteArrayInputStream(dexBytes), dexFeatures::add);
      } catch (Exception ignored) {
        continue;
      }
      parseTimeNanos += SystemClock.elapsedRealtimeNanos() - dexParseStart;

      long dexVectorStart = SystemClock.elapsedRealtimeNanos();
      float[] dexVector = vectorize(dexFeatures, featureIndex);
      orPoolInto(aggregatedVector, dexVector);
      vectorizeTimeNanos += SystemClock.elapsedRealtimeNanos() - dexVectorStart;
    }

    long structuralParsingTimeMs =
        (SystemClock.elapsedRealtimeNanos() - structuralParsingStart) / 1_000_000L;
    return new Result(
        aggregatedVector,
        dexFilesFound,
        structuralParsingTimeMs,
        parseTimeNanos,
        vectorizeTimeNanos);
  }

  private static float[] vectorize(Collection<String> tokens, Map<String, Integer> featureIndex) {
    float[] vec = new float[FEATURE_DIM];
    for (String t : tokens) {
      Integer idx = featureIndex.get(t);
      if (idx != null && idx >= 0 && idx < FEATURE_DIM) {
        vec[idx] = 1.0f;
      }
    }
    return vec;
  }

  private static void orPoolInto(float[] master, float[] candidate) {
    int n = Math.min(master.length, candidate.length);
    for (int i = 0; i < n; i++) {
      if (candidate[i] > 0.0f) {
        master[i] = 1.0f;
      }
    }
  }
}
