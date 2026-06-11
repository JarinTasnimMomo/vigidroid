package com.msh.vigidroid.pipeline;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Per-stage wall-clock guard for batch device eval (Phase 6). */
public final class StageTimeouts {

  public static final long DEFAULT_MS = 120_000L;

  private StageTimeouts() {}

  public static <T> T run(Callable<T> work, long timeoutMs)
      throws TimeoutException, Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    Future<T> future = executor.submit(work);
    try {
      return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException ex) {
      future.cancel(true);
      throw ex;
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof Exception) {
        throw (Exception) cause;
      }
      if (cause instanceof Error) {
        throw (Error) cause;
      }
      throw ex;
    } finally {
      executor.shutdownNow();
    }
  }
}
