package com.msh.vigidroid.pipeline;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class StageDiagnosticsTest {

  @Test
  public void formatError_includesModelPhaseAndFrame() {
    Exception ex = new IllegalStateException("f != java.lang.Long");
    String msg = StageDiagnostics.formatError("broadcast_mldp_hybrid", "infer", ex);
    assertTrue(msg.contains("broadcast_mldp_hybrid@infer"));
    assertTrue(msg.contains("IllegalStateException"));
    assertTrue(msg.contains("f != java.lang.Long"));
    assertTrue(msg.contains(" at "));
  }
}
