package com.msh.vigidroid;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class OnnxManifestIoTest {

  @Test
  public void malwareOutputName_prefersManifestOutputs() throws Exception {
    JSONObject manifest =
        new JSONObject(
            "{\"outputs\":[{\"name\":\"malware_prob\",\"shape\":[1,1]}]}");
    assertEquals("malware_prob", OnnxManifestIo.malwareOutputName(manifest));
  }

  @Test
  public void malwareOutputName_acceptsMalwareProbability() throws Exception {
    JSONObject manifest =
        new JSONObject(
            "{\"outputs\":[{\"name\":\"malware_probability\",\"shape\":[1,1]}]}");
    assertEquals("malware_probability", OnnxManifestIo.malwareOutputName(manifest));
  }

  @Test
  public void malwareOutputName_fallsBackToOnnxRuntimeCheck() throws Exception {
    JSONObject manifest =
        new JSONObject("{\"onnx_runtime_check\":{\"output_name\":\"malware_prob\"}}");
    assertEquals("malware_prob", OnnxManifestIo.malwareOutputName(manifest));
  }
}
