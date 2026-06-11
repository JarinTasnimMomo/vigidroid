package com.msh.vigidroid;

import android.content.Context;

import java.io.File;

/** Resolve thesis eval APK paths pushed by {@code Android_Works/run_p1_exit_scan.sh}. */
public final class EvalApkPaths {

  public static final String SCAN_1514_NAME = "scan_1514_malware.apk";
  public static final String SCAN_1514_TMP = "/data/local/tmp/" + SCAN_1514_NAME;
  public static final String SCAN_1514_DOWNLOAD =
      "/sdcard/Download/Scanable/" + SCAN_1514_NAME;

  private EvalApkPaths() {}

  public static File resolveScan1514(Context context) {
    File tmp = new File(SCAN_1514_TMP);
    if (tmp.isFile()) {
      return tmp;
    }
    File appFiles = new File(context.getExternalFilesDir(null), SCAN_1514_NAME);
    if (appFiles.isFile()) {
      return appFiles;
    }
    return new File(SCAN_1514_DOWNLOAD);
  }
}
