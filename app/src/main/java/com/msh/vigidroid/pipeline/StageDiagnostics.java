package com.msh.vigidroid.pipeline;

import android.util.Log;

/** Phase-0 RCA helpers: rich stage errors for UI + Logcat stack traces. */
public final class StageDiagnostics {

  private static final String TAG = "StageDiagnostics";

  private StageDiagnostics() {}

  public static String formatError(String modelId, String phase, Throwable ex) {
    if (ex == null) {
      return modelId + "@" + phase + ": unknown error";
    }
    StringBuilder sb = new StringBuilder();
    sb.append(modelId).append('@').append(phase).append(": ");
    sb.append(ex.getClass().getSimpleName()).append(": ");
    String message = ex.getMessage();
    sb.append(message != null ? message : "(no message)");

    StackTraceElement[] stack = ex.getStackTrace();
    if (stack.length > 0) {
      StackTraceElement frame = stack[0];
      sb.append(" at ")
          .append(shortClassName(frame.getClassName()))
          .append('.')
          .append(frame.getMethodName())
          .append(':')
          .append(frame.getLineNumber());
    }

    Throwable cause = ex.getCause();
    if (cause != null && cause != ex) {
      sb.append(" | cause=")
          .append(cause.getClass().getSimpleName())
          .append(": ")
          .append(cause.getMessage());
    }
    return sb.toString();
  }

  public static String formatMessage(
      String modelId, String phase, String simpleName, String message) {
    return modelId
        + "@"
        + phase
        + ": "
        + simpleName
        + ": "
        + (message != null ? message : "(no message)");
  }

  public static void logToLogcat(String modelId, String phase, Throwable ex) {
    Log.e(TAG, formatError(modelId, phase, ex), ex);
  }

  private static String shortClassName(String fqcn) {
    int dot = fqcn.lastIndexOf('.');
    return dot >= 0 ? fqcn.substring(dot + 1) : fqcn;
  }
}
