package com.msh.vigidroid;

import org.json.JSONArray;
import org.json.JSONObject;

/** Resolve ONNX input/output tensor names from export_manifest.json. */
final class OnnxManifestIo {

  private static final String[] MALWARE_OUTPUT_ALIASES = {
    "malware_prob", "malware_probability"
  };

  private OnnxManifestIo() {}

  static String inputName(JSONObject manifest, String fallback) throws Exception {
    JSONArray inputs = manifest.optJSONArray("inputs");
    if (inputs != null && inputs.length() > 0) {
      return inputs.getJSONObject(0).optString("name", fallback);
    }
    JSONObject onnxCheck = manifest.optJSONObject("onnx_runtime_check");
    if (onnxCheck != null) {
      JSONArray inputNames = onnxCheck.optJSONArray("input_names");
      if (inputNames != null && inputNames.length() > 0) {
        return inputNames.optString(0, fallback);
      }
      return onnxCheck.optString("input_name", fallback);
    }
    return fallback;
  }

  static String namedInput(JSONObject manifest, String logicalName) throws Exception {
    JSONArray inputs = manifest.optJSONArray("inputs");
    if (inputs != null) {
      for (int i = 0; i < inputs.length(); i++) {
        JSONObject inp = inputs.getJSONObject(i);
        if (logicalName.equals(inp.optString("name"))) {
          return inp.getString("name");
        }
      }
    }
    return logicalName;
  }

  static String outputName(JSONObject manifest, String fallback) throws Exception {
    JSONArray outputs = manifest.optJSONArray("outputs");
    if (outputs != null && outputs.length() > 0) {
      return outputs.getJSONObject(0).optString("name", fallback);
    }
    JSONObject onnxCheck = manifest.optJSONObject("onnx_runtime_check");
    if (onnxCheck != null) {
      return onnxCheck.optString("output_name", fallback);
    }
    return fallback;
  }

  /** Canonical malware score output name (handles prob vs probability across bundles). */
  static String malwareOutputName(JSONObject manifest) throws Exception {
    JSONArray outputs = manifest.optJSONArray("outputs");
    if (outputs != null) {
      for (int i = 0; i < outputs.length(); i++) {
        String name = outputs.getJSONObject(i).optString("name", "");
        for (String alias : MALWARE_OUTPUT_ALIASES) {
          if (alias.equals(name)) {
            return name;
          }
        }
      }
      if (outputs.length() > 0) {
        return outputs.getJSONObject(0).getString("name");
      }
    }
    JSONObject onnxCheck = manifest.optJSONObject("onnx_runtime_check");
    if (onnxCheck != null) {
      String fromCheck = onnxCheck.optString("output_name", "");
      if (!fromCheck.isEmpty()) {
        return fromCheck;
      }
    }
    return "malware_probability";
  }
}
