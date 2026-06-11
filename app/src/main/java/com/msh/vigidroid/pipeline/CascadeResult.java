package com.msh.vigidroid.pipeline;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Audit trail for a cascade scan verdict path. */
public final class CascadeResult {

  public static final String REASON_LOW_BENIGN = "low_confident_benign";
  public static final String REASON_HIGH_MALWARE = "high_confident_malware";
  public static final String REASON_FINAL = "final_verdict";

  public static final String SKIP_NOT_RUN = "cascade_not_run";

  public final String policyName;
  public final int exitTier;
  public final String exitReason;
  public final List<String> modelsRun;
  public final List<String> modelsSkipped;
  public final float finalScore;
  public final String decision;

  public CascadeResult(
      String policyName,
      int exitTier,
      String exitReason,
      List<String> modelsRun,
      List<String> modelsSkipped,
      float finalScore,
      String decision) {
    this.policyName = policyName;
    this.exitTier = exitTier;
    this.exitReason = exitReason;
    this.modelsRun = Collections.unmodifiableList(new ArrayList<>(modelsRun));
    this.modelsSkipped = Collections.unmodifiableList(new ArrayList<>(modelsSkipped));
    this.finalScore = finalScore;
    this.decision = decision;
  }
}
