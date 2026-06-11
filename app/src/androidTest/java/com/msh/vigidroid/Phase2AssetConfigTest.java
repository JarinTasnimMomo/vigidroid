package com.msh.vigidroid;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Phase 2 — asset/config verification (steps 2.2–2.4).
 *
 * <p>Run: {@code Android_Works/run_phase2_extraction.sh}
 */
@RunWith(AndroidJUnit4.class)
public class Phase2AssetConfigTest {

  private static final String BROADCAST_FEATURES =
      "models/broadcast_mldp_hybrid/features/";
  private static final String FUSION_FEATURES =
      "models/dexheader_broadcast_fusion/features/";
  private static final String MLDP_FEATURES =
      "models/mldp_dexheader_cascade/features/";
  private static final String MLP_HEADER_NORM =
      "models/mlp_header/features/normalization_header.json";

  @Test
  public void broadcastMldpHybrid_featureLayoutAndVocabs_matchPcSpec() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject layout =
        new JSONObject(
            ModelAssetHelper.readAssetText(context, BROADCAST_FEATURES + "feature_layout.json"));
    assertEquals(22, layout.getInt("S"));
    assertEquals(70, layout.getInt("R"));
    assertEquals(92, layout.getInt("total"));

    JSONArray mldpTokens =
        new JSONObject(
                ModelAssetHelper.readAssetText(
                    context, BROADCAST_FEATURES + "mldp_permission_vocab.json"))
            .getJSONArray("tokens");
    JSONArray receiverTokens =
        new JSONObject(
                ModelAssetHelper.readAssetText(
                    context, BROADCAST_FEATURES + "receiver_action_vocab.json"))
            .getJSONArray("tokens");
    assertEquals("S vocab", layout.getInt("S"), mldpTokens.length());
    assertEquals("R vocab", layout.getInt("R"), receiverTokens.length());

    JSONObject systemActions =
        new JSONObject(
            ModelAssetHelper.readAssetText(context, BROADCAST_FEATURES + "system_actions.json"));
    JSONArray actions = systemActions.getJSONArray("actions");
    assertTrue("system_actions should be non-empty", actions.length() > 0);

    assertEquals(BroadcastMldpHybridExtractor.S_DIM, layout.getInt("S"));
    assertEquals(BroadcastMldpHybridExtractor.R_DIM, layout.getInt("R"));
    assertEquals(BroadcastMldpHybridExtractor.FEATURE_DIM, layout.getInt("total"));
  }

  @Test
  public void mldpDexheader_normalizationHeader_matchesDeployedMlpHeader() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject mlp =
        new JSONObject(ModelAssetHelper.readAssetText(context, MLP_HEADER_NORM));
    JSONObject cascade =
        new JSONObject(
            ModelAssetHelper.readAssetText(context, MLDP_FEATURES + "normalization_header.json"));

    assertEquals(mlp.getInt("feature_dim"), cascade.getInt("feature_dim"));
    assertJsonFloatArrayEquals("mins", mlp.getJSONArray("mins"), cascade.getJSONArray("mins"));
    assertJsonFloatArrayEquals("maxs", mlp.getJSONArray("maxs"), cascade.getJSONArray("maxs"));
    assertEquals("deployed_mlp_header", cascade.optString("source"));
  }

  @Test
  public void dexheaderBroadcastFusion_receiverDim_matchesLayoutAndRunner() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject layout =
        new JSONObject(
            ModelAssetHelper.readAssetText(context, FUSION_FEATURES + "feature_layout.json"));
    assertEquals(70, layout.getInt("receiver"));
    assertEquals(DexHeaderFeatureExtractor.FEATURE_DIM, layout.getInt("dex_header"));

    JSONArray receiverTokens =
        new JSONObject(
                ModelAssetHelper.readAssetText(
                    context, FUSION_FEATURES + "receiver_action_vocab.json"))
            .getJSONArray("tokens");
    assertEquals(layout.getInt("receiver"), receiverTokens.length());

    DexheaderBroadcastFusionExtractor extractor =
        DexheaderBroadcastFusionExtractor.fromAssets(context);
    assertEquals(70, extractor.getReceiverDim());
    assertEquals(DexheaderBroadcastFusionExtractor.H_DIM, layout.getInt("dex_header"));
  }

  private static void assertJsonFloatArrayEquals(String label, JSONArray a, JSONArray b)
      throws Exception {
    assertEquals(label + " length", a.length(), b.length());
    for (int i = 0; i < a.length(); i++) {
      assertEquals(label + "[" + i + "]", a.getDouble(i), b.getDouble(i), 0.0);
    }
  }
}
