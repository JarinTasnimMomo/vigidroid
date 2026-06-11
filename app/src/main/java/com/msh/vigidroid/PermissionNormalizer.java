package com.msh.vigidroid;

import org.json.JSONArray;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * VigiDroid permission token normalization and binary vectorization.
 * Matches Python linear/permission_extractor src/features/permission_vector.py
 * and legacy ScanService.normalizePermission semantics.
 */
public final class PermissionNormalizer {

  private static final String ANDROID_PERMISSION_PREFIX = "android.permission.";

  private PermissionNormalizer() {}

  /**
   * android.permission.SEND_SMS -> permissions::send_sms
   */
  public static String normalize(String raw) {
    String p = raw.trim().toLowerCase(Locale.US);
    if (p.startsWith(ANDROID_PERMISSION_PREFIX)) {
      p = p.substring(ANDROID_PERMISSION_PREFIX.length());
    }
    return "permissions::" + p.replace('.', '_');
  }

  public static Map<String, Integer> buildTokenToIndex(JSONArray permissions) throws Exception {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    for (int i = 0; i < permissions.length(); i++) {
      tokenToIndex.put(permissions.getString(i), i);
    }
    return tokenToIndex;
  }

  public static List<String> normalizePermissions(List<String> rawPermissions) {
    List<String> out = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    for (String raw : rawPermissions) {
      if (raw == null || raw.trim().isEmpty()) {
        continue;
      }
      String token = normalize(raw);
      if (seen.add(token)) {
        out.add(token);
      }
    }
    return out;
  }

  public static List<String> readNormalizedPermissions(File apkFile) throws Exception {
    try (ZipFile zip = new ZipFile(apkFile)) {
      ZipEntry entry = zip.getEntry("AndroidManifest.xml");
      if (entry == null) {
        throw new IllegalStateException("AndroidManifest.xml not found in APK");
      }
      try (InputStream is = zip.getInputStream(entry)) {
        return normalizePermissions(ManifestAxmlParser.extractManifestPermissions(is));
      }
    }
  }

  /** Unknown tokens are silently ignored (no UNK bucket). */
  public static float[] buildBinaryVector(
      List<String> normalizedTokens, Map<String, Integer> tokenToIndex, int vectorSize) {
    float[] vec = new float[vectorSize];
    for (String token : normalizedTokens) {
      Integer idx = tokenToIndex.get(token);
      if (idx != null && idx >= 0 && idx < vectorSize) {
        vec[idx] = 1.0f;
      }
    }
    return vec;
  }
}
