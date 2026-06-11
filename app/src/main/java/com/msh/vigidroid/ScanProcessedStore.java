package com.msh.vigidroid;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** Persist scanned APK SHA-256 digests for incremental scan / dedup (A3). */
public final class ScanProcessedStore {

  private static final String PREFS = "scan_processed_store";
  private static final String KEY_DIGESTS = "sha256_digests";
  private static final int MAX_ENTRIES = 5000;

  private ScanProcessedStore() {}

  public static boolean contains(Context context, String sha256Hex) {
    if (sha256Hex == null || sha256Hex.isEmpty()) {
      return false;
    }
    return load(context).contains(sha256Hex.toLowerCase());
  }

  public static void mark(Context context, String sha256Hex) {
    if (sha256Hex == null || sha256Hex.isEmpty()) {
      return;
    }
    Set<String> digests = load(context);
    digests.add(sha256Hex.toLowerCase());
    trimIfNeeded(digests);
    save(context, digests);
  }

  public static void clear(Context context) {
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_DIGESTS).apply();
  }

  private static Set<String> load(Context context) {
    SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    String raw = prefs.getString(KEY_DIGESTS, "[]");
    Set<String> out = new HashSet<>();
    try {
      JSONArray arr = new JSONArray(raw);
      for (int i = 0; i < arr.length(); i++) {
        out.add(arr.getString(i));
      }
    } catch (Exception ignored) {
    }
    return out;
  }

  private static void save(Context context, Set<String> digests) {
    JSONArray arr = new JSONArray();
    for (String digest : digests) {
      arr.put(digest);
    }
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .edit()
        .putString(KEY_DIGESTS, arr.toString())
        .apply();
  }

  private static void trimIfNeeded(Set<String> digests) {
    if (digests.size() <= MAX_ENTRIES) {
      return;
    }
    Set<String> trimmed = new HashSet<>();
    int skip = digests.size() - MAX_ENTRIES;
    int index = 0;
    for (String digest : digests) {
      if (index++ < skip) {
        continue;
      }
      trimmed.add(digest);
    }
    digests.clear();
    digests.addAll(trimmed);
  }

  public static int count(Context context) {
    return load(context).size();
  }

  public static Set<String> snapshot(Context context) {
    return Collections.unmodifiableSet(load(context));
  }
}
