package com.msh.vigidroid;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CascadePolicyTest {

  @Test
  public void fromJson_parsesTiersAndWeights() throws Exception {
    String json =
        "{"
            + "\"policy_name\":\"test_cascade\","
            + "\"enabled\":false,"
            + "\"tier3_pattern_model\":\"early_fusion_dex_manifest\","
            + "\"tiers\":["
            + "  {\"tier\":1,\"models\":[\"mldp_pruned_permission\"],\"t_low\":0.1,\"t_high\":0.9,"
            + "   \"conservative_malware_or\":true},"
            + "  {\"tier\":4,\"models\":[\"bytecnn\"],\"t_low\":0.5,\"t_high\":0.5,\"final\":true}"
            + "],"
            + "\"model_weights\":{\"manifest_xgb\":0.97},"
            + "\"fusion_weights\":{\"bytecnn\":0.96}"
            + "}";

    CascadePolicy policy = CascadePolicy.fromJson(new JSONObject(json));
    assertEquals("test_cascade", policy.getPolicyName());
    assertFalse(policy.isEnabled());
    assertEquals(2, policy.getTiers().size());
    assertEquals(1, policy.tier(1).tier);
    assertTrue(policy.tier(1).conservativeMalwareOr);
    assertTrue(policy.tier(4).finalTier);
    assertEquals(0.97, policy.weightFor("manifest_xgb"), 1e-9);
    assertEquals(0.96, policy.fusionWeightFor("bytecnn"), 1e-9);
    assertEquals(1.0, policy.weightFor("missing_model"), 1e-9);
  }

  @Test
  public void withEnabled_overridesWithoutReloadingAssets() throws Exception {
    CascadePolicy disabled = CascadePolicy.disabledDefault();
    CascadePolicy enabled = disabled.withEnabled(true);
    assertFalse(disabled.isEnabled());
    assertTrue(enabled.isEnabled());
    assertEquals(disabled.getPolicyName(), enabled.getPolicyName());
    assertEquals(disabled, disabled.withEnabled(false));
  }
}
