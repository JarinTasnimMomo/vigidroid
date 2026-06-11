package com.msh.vigidroid.pipeline;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class ScanDetailFormatterTest {

  @Test
  public void format_includesTotalAndEnsembleInLegacyMode() throws Exception {
    JSONObject root = new JSONObject();
    root.put("wall_ms", 35.0);
    root.put("shared_parse_ms", 210.0);
    root.put("total_ms", 245.0);
    root.put("ensemble_score", 0.898);
    root.put("ensemble_decision", "malware");
    root.put("stages", new org.json.JSONArray());

    String text = ScanDetailFormatter.format(root.toString());
    assertTrue(text.contains("stage_wall=35.0 ms"));
    assertTrue(text.contains("shared_parse=210.0 ms"));
    assertTrue(text.contains("total=245.0 ms"));
    assertTrue(text.contains("Ensemble (list badge): malware"));
    assertTrue(text.contains("legacy mode"));
  }

  @Test
  public void format_showsStageErrorMessage() throws Exception {
    JSONObject stage = new JSONObject();
    stage.put("model_id", "broadcast_mldp_hybrid");
    stage.put("status", "error");
    stage.put("error_message", "broadcast_mldp_hybrid@infer: OrtException: test");
    org.json.JSONArray stages = new org.json.JSONArray();
    stages.put(stage);
    JSONObject root = new JSONObject();
    root.put("wall_ms", 1.0);
    root.put("stages", stages);

    String text = ScanDetailFormatter.format(root.toString());
    assertTrue(text.contains("broadcast_mldp_hybrid@infer"));
  }
}
