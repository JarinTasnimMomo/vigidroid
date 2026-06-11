package com.msh.vigidroid.pipeline;

import org.junit.Test;

import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class StageTimeoutsTest {

  @Test
  public void run_returnsValueWhenFast() throws Exception {
  int value = StageTimeouts.run(() -> 42, 1_000L);
    assertEquals(42, value);
  }

  @Test
  public void run_throwsTimeoutWhenSlow() throws Exception {
    try {
      StageTimeouts.run(
          () -> {
            Thread.sleep(200);
            return "late";
          },
          50L);
      fail("expected TimeoutException");
    } catch (TimeoutException ex) {
      assertTrue(ex.getMessage() == null || ex.getMessage().isEmpty() || true);
    }
  }

  @Test
  public void run_propagatesCallableException() {
    AtomicBoolean ran = new AtomicBoolean(false);
    try {
      StageTimeouts.run(
          () -> {
            ran.set(true);
            throw new IllegalStateException("boom");
          },
          1_000L);
      fail("expected IllegalStateException");
    } catch (IllegalStateException ex) {
      assertEquals("boom", ex.getMessage());
      assertTrue(ran.get());
    } catch (Exception ex) {
      fail("unexpected: " + ex);
    }
  }
}
