package com.msh.vigidroid;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parse eval APK ground truth from filename (A5). */
public final class EvalLabelParser {

  private static final Pattern EVAL_PATTERN =
      Pattern.compile("(?i)^eval_\\d+_(benign|malware)\\.apk$");

  private EvalLabelParser() {}

  public static String groundTruthFromApkName(String apkName) {
    if (apkName == null || apkName.isEmpty()) {
      return "unknown";
    }
    Matcher matcher = EVAL_PATTERN.matcher(apkName.trim());
    if (matcher.matches()) {
      return matcher.group(1).toLowerCase(Locale.US);
    }
    return "unknown";
  }
}
