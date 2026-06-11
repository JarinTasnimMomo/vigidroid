package com.msh.vigidroid;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class FusionScorerTest {

  @Test
  public void legacyXgbCnnScore_usesPolicyFusionWeights() throws Exception {
    String json =
        "{"
            + "\"policy_name\":\"test\","
            + "\"tiers\":[],"
            + "\"fusion_weights\":{\"manifest_xgb\":0.8,\"bytecnn\":0.2}"
            + "}";
    CascadePolicy policy = CascadePolicy.fromJson(new JSONObject(json));
    float score = FusionScorer.legacyXgbCnnScore(policy, 1.0f, -1f);
    assertEquals(1.0f, score, 1e-6f);
    float blend = FusionScorer.legacyXgbCnnScore(policy, 1.0f, 0.5f);
    assertEquals(0.9f, blend, 1e-6f);
  }
}
