package com.msh.vigidroid.pipeline;

/**
 * Per-model pipeline output: timings, score, memory delta, and audit status.
 * Cascade stages use optional fields.
 */
public final class StageResult {

  public static final String STATUS_OK = "ok";
  public static final String STATUS_SKIPPED = "skipped";
  public static final String STATUS_ERROR = "error";

  public final String domain;
  public final String modelId;
  public final String status;
  public final String errorMessage;
  public final double parseMs;
  public final double vectorizeMs;
  public final double inferenceMs;
  public final double cpuMs;
  public final float score;
  public final long memDeltaBytes;

  public final boolean cascade;
  public final String cascadeMode;
  public final double dexMs;
  public final float stage1Score;
  public final float stage2Score;
  public final boolean earlyExit;

  private StageResult(Builder builder) {
    this.domain = builder.domain;
    this.modelId = builder.modelId;
    this.status = builder.status;
    this.errorMessage = builder.errorMessage;
    this.parseMs = builder.parseMs;
    this.vectorizeMs = builder.vectorizeMs;
    this.inferenceMs = builder.inferenceMs;
    this.cpuMs = builder.cpuMs;
    this.score = builder.score;
    this.memDeltaBytes = builder.memDeltaBytes;
    this.cascade = builder.cascade;
    this.cascadeMode = builder.cascadeMode;
    this.dexMs = builder.dexMs;
    this.stage1Score = builder.stage1Score;
    this.stage2Score = builder.stage2Score;
    this.earlyExit = builder.earlyExit;
  }

  public static Builder builder(String domain) {
    return new Builder(domain);
  }

  public static final class Builder {
    private final String domain;
    private String modelId;
    private String status = STATUS_OK;
    private String errorMessage;
    private double parseMs;
    private double vectorizeMs;
    private double inferenceMs;
    private double cpuMs;
    private float score = -1f;
    private long memDeltaBytes;
    private boolean cascade;
    private String cascadeMode;
    private double dexMs;
    private float stage1Score = -1f;
    private float stage2Score = -1f;
    private boolean earlyExit;

    Builder(String domain) {
      this.domain = domain;
    }

    public Builder modelId(String modelId) {
      this.modelId = modelId;
      return this;
    }

    public Builder status(String status) {
      this.status = status;
      return this;
    }

    public Builder errorMessage(String errorMessage) {
      this.errorMessage = errorMessage;
      return this;
    }

    public Builder parseMs(double parseMs) {
      this.parseMs = parseMs;
      return this;
    }

    public Builder vectorizeMs(double vectorizeMs) {
      this.vectorizeMs = vectorizeMs;
      return this;
    }

    public Builder inferenceMs(double inferenceMs) {
      this.inferenceMs = inferenceMs;
      return this;
    }

    public Builder cpuMs(double cpuMs) {
      this.cpuMs = cpuMs;
      return this;
    }

    public Builder score(float score) {
      this.score = score;
      return this;
    }

    public Builder memDeltaBytes(long memDeltaBytes) {
      this.memDeltaBytes = memDeltaBytes;
      return this;
    }

    public Builder cascade(
        String mode,
        double dexMs,
        float stage1Score,
        float stage2Score,
        boolean earlyExit) {
      this.cascade = true;
      this.cascadeMode = mode;
      this.dexMs = dexMs;
      this.stage1Score = stage1Score;
      this.stage2Score = stage2Score;
      this.earlyExit = earlyExit;
      return this;
    }

    public StageResult build() {
      return new StageResult(this);
    }
  }
}
