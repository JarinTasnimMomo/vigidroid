package com.msh.vigidroid;

import android.util.Log;

import java.util.Set;

import ai.onnxruntime.OrtSession;

/** Log and validate ONNX session IO names at load time. */
public final class OnnxSessionDiagnostics {

  private OnnxSessionDiagnostics() {}

  public static void logSingleIo(
      String tag, String modelId, OrtSession session, String manifestInput, String manifestOutput) {
    try {
      Set<String> sessionInputs = session.getInputNames();
      Set<String> sessionOutputs = session.getOutputNames();
      Log.i(
          tag,
          modelId
              + " manifest_in="
              + manifestInput
              + " manifest_out="
              + manifestOutput
              + " session_in="
              + sessionInputs
              + " session_out="
              + sessionOutputs);
      validateSingleIo(modelId, sessionInputs, sessionOutputs, manifestInput, manifestOutput);
    } catch (Exception ex) {
      Log.w(tag, modelId + ": failed to read session IO names", ex);
    }
  }

  public static void logDualInput(
      String tag,
      String modelId,
      OrtSession session,
      String manifestInputA,
      String manifestInputB,
      String manifestOutput) {
    try {
      Set<String> sessionInputs = session.getInputNames();
      Set<String> sessionOutputs = session.getOutputNames();
      Log.i(
          tag,
          modelId
              + " manifest_in=["
              + manifestInputA
              + ", "
              + manifestInputB
              + "] manifest_out="
              + manifestOutput
              + " session_in="
              + sessionInputs
              + " session_out="
              + sessionOutputs);
      validateDualInput(
          modelId, sessionInputs, sessionOutputs, manifestInputA, manifestInputB, manifestOutput);
    } catch (Exception ex) {
      Log.w(tag, modelId + ": failed to read session IO names", ex);
    }
  }

  static void validateSingleIo(
      String modelId,
      Set<String> sessionInputs,
      Set<String> sessionOutputs,
      String manifestInput,
      String manifestOutput) {
    if (!sessionInputs.contains(manifestInput)) {
      throw new IllegalStateException(
          modelId
              + ": manifest input '"
              + manifestInput
              + "' missing from session inputs "
              + sessionInputs);
    }
    if (manifestOutput != null
        && !manifestOutput.isEmpty()
        && !sessionOutputs.contains(manifestOutput)) {
      throw new IllegalStateException(
          modelId
              + ": manifest output '"
              + manifestOutput
              + "' missing from session outputs "
              + sessionOutputs);
    }
  }

  static void validateDualInput(
      String modelId,
      Set<String> sessionInputs,
      Set<String> sessionOutputs,
      String manifestInputA,
      String manifestInputB,
      String manifestOutput) {
    if (!sessionInputs.contains(manifestInputA)) {
      throw new IllegalStateException(
          modelId
              + ": manifest input '"
              + manifestInputA
              + "' missing from session inputs "
              + sessionInputs);
    }
    if (!sessionInputs.contains(manifestInputB)) {
      throw new IllegalStateException(
          modelId
              + ": manifest input '"
              + manifestInputB
              + "' missing from session inputs "
              + sessionInputs);
    }
    if (manifestOutput != null
        && !manifestOutput.isEmpty()
        && !sessionOutputs.contains(manifestOutput)) {
      throw new IllegalStateException(
          modelId
              + ": manifest output '"
              + manifestOutput
              + "' missing from session outputs "
              + sessionOutputs);
    }
  }
}
