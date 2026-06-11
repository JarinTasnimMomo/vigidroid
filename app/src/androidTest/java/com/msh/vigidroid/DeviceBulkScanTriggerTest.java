package com.msh.vigidroid;

import android.content.Intent;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Enqueues {@link ScanService} bulk scans via adb (no UI). Does not wait for completion.
 *
 * <pre>
 * # Scan A — ablation, all models
 * adb shell am instrument -w -e class com.msh.vigidroid.DeviceBulkScanTriggerTest#enqueueScanA \
 *   com.msh.vigidroid.test/androidx.test.runner.AndroidJUnitRunner
 *
 * # Scan B — cascade
 * adb shell am instrument -w -e class com.msh.vigidroid.DeviceBulkScanTriggerTest#enqueueScanB \
 *   com.msh.vigidroid.test/androidx.test.runner.AndroidJUnitRunner
 * </pre>
 */
@RunWith(AndroidJUnit4.class)
public class DeviceBulkScanTriggerTest {

  @Test
  public void enqueueScanA() {
    enqueue(false, "adb-scan-a");
  }

  @Test
  public void enqueueScanB() {
    enqueue(true, "adb-scan-b");
  }

  private static void enqueue(boolean cascadeEnabled, String sessionId) {
    Intent intent = new Intent();
    intent.putExtra("manual_trigger", true);
    intent.putExtra(ScanService.EXTRA_RESCAN_ALL, true);
    intent.putExtra(ScanService.EXTRA_CASCADE_ENABLED, cascadeEnabled);
    intent.putExtra(ScanService.EXTRA_SESSION_ID, sessionId);
    ScanService.enqueueWork(InstrumentationRegistry.getInstrumentation().getTargetContext(), intent);
  }
}
