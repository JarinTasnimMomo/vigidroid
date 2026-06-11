package com.msh.vigidroid.pipeline;

import android.os.Debug;

/** Per-stage native-heap delta and scan-thread CPU time (wraps one pipeline). */
final class StageResourceProbe {

  private final long memBefore;
  private final long cpuBefore;

  StageResourceProbe() {
    memBefore = Debug.getNativeHeapAllocatedSize();
    cpuBefore = Debug.threadCpuTimeNanos();
  }

  long memDeltaBytes() {
    return Debug.getNativeHeapAllocatedSize() - memBefore;
  }

  double cpuMs() {
    return (Debug.threadCpuTimeNanos() - cpuBefore) / 1_000_000.0;
  }
}
