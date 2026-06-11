package com.msh.vigidroid;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Parse-once APK context: single {@link ZipFile} open, shared manifest/dex bytes, tail bytes, SHA-256.
 * Per-model pipelines read cached data instead of re-opening the APK.
 */
public final class FeatureContext implements AutoCloseable {

  private final File apkFile;
  private final ZipFile zip;
  private final long sharedParseNanos;

  private final List<String> normalizedPermissions;
  private final ManifestAxmlParser.HybridManifestFeatures hybridManifest;
  private final List<String> manifestBowTokens;
  private final Set<String> xgbManifestTokens;
  private final List<byte[]> dexByteArrays;
  private final long[] tailBytes1024;
  private final String sha256Hex;

  private FeatureContext(
      File apkFile,
      ZipFile zip,
      long sharedParseNanos,
      List<String> normalizedPermissions,
      ManifestAxmlParser.HybridManifestFeatures hybridManifest,
      List<String> manifestBowTokens,
      Set<String> xgbManifestTokens,
      List<byte[]> dexByteArrays,
      long[] tailBytes1024,
      String sha256Hex) {
    this.apkFile = apkFile;
    this.zip = zip;
    this.sharedParseNanos = sharedParseNanos;
    this.normalizedPermissions = normalizedPermissions;
    this.hybridManifest = hybridManifest;
    this.manifestBowTokens = manifestBowTokens;
    this.xgbManifestTokens = xgbManifestTokens;
    this.dexByteArrays = dexByteArrays;
    this.tailBytes1024 = tailBytes1024;
    this.sha256Hex = sha256Hex;
  }

  public static FeatureContext open(File apkFile) throws Exception {
    long t0 = System.nanoTime();

    String sha256Hex = computeFileSha256(apkFile);
    long[] tailBytes1024 = readTailBytes(apkFile, 1024);

    ZipFile zip = new ZipFile(apkFile);
    byte[] manifestBytes = readManifestBytes(zip);

    List<String> rawPermissions =
        ManifestAxmlParser.extractManifestPermissions(new ByteArrayInputStream(manifestBytes));
    List<String> normalizedPermissions = PermissionNormalizer.normalizePermissions(rawPermissions);

    ManifestAxmlParser.HybridManifestFeatures hybridManifest =
        ManifestAxmlParser.parseHybridManifest(new ByteArrayInputStream(manifestBytes));

    List<String> manifestBowTokens =
        ManifestAxmlParser.extractManifestTokens(new ByteArrayInputStream(manifestBytes));

    Set<String> xgbManifestTokens = parseXgbManifestTokens(manifestBytes);

    List<String> dexEntryNames = DexHeaderFeatureExtractor.listDexEntries(zip);
    List<byte[]> dexByteArrays = new ArrayList<>(dexEntryNames.size());
    for (String entryName : dexEntryNames) {
      ZipEntry entry = zip.getEntry(entryName);
      if (entry != null) {
        dexByteArrays.add(DexHeaderFeatureExtractor.readEntryBytes(zip, entry));
      }
    }

    long sharedParseNanos = System.nanoTime() - t0;
    return new FeatureContext(
        apkFile,
        zip,
        sharedParseNanos,
        normalizedPermissions,
        hybridManifest,
        manifestBowTokens,
        xgbManifestTokens,
        dexByteArrays,
        tailBytes1024,
        sha256Hex);
  }

  public File apkFile() {
    return apkFile;
  }

  public double sharedParseMs() {
    return sharedParseNanos / 1_000_000.0;
  }

  public List<String> normalizedPermissions() {
    return normalizedPermissions;
  }

  public ManifestAxmlParser.HybridManifestFeatures hybridManifest() {
    return hybridManifest;
  }

  public List<String> manifestBowTokens() {
    return manifestBowTokens;
  }

  public Set<String> xgbManifestTokens() {
    return xgbManifestTokens;
  }

  public List<byte[]> dexByteArrays() {
    return dexByteArrays;
  }

  public int dexFilesFound() {
    return dexByteArrays.size();
  }

  public long[] tailBytes1024() {
    return tailBytes1024;
  }

  public String sha256Hex() {
    return sha256Hex;
  }

  @Override
  public void close() {
    try {
      zip.close();
    } catch (Exception ignored) {
    }
  }

  private static byte[] readManifestBytes(ZipFile zip) throws Exception {
    ZipEntry entry = zip.getEntry("AndroidManifest.xml");
    if (entry == null) {
      throw new IllegalStateException("AndroidManifest.xml not found in APK");
    }
    return DexHeaderFeatureExtractor.readEntryBytes(zip, entry);
  }

  private static Set<String> parseXgbManifestTokens(byte[] manifestBytes) throws Exception {
    Set<String> tokens = new HashSet<>();
    try (InputStream is = new ByteArrayInputStream(manifestBytes)) {
      AxmlReader reader = new AxmlReader(is);
      Set<String> rawFeatures = reader.parse();
      for (String rawFeature : rawFeatures) {
        if (rawFeature == null) {
          continue;
        }
        if (rawFeature.startsWith("android.permission.")) {
          tokens.add(PermissionNormalizer.normalize(rawFeature));
        }
        if (rawFeature.startsWith("android.intent.action.")) {
          tokens.add(normalizeXgbIntent(rawFeature));
        }
      }
    }
    return tokens;
  }

  private static String normalizeXgbIntent(String intent) {
    String i = intent.toLowerCase(Locale.US);
    if (i.startsWith("android.intent.action.")) {
      i = i.substring("android.intent.action.".length());
    }
    return "intents::" + i.replace('.', '_');
  }

  private static long[] readTailBytes(File apkFile, int byteLength) throws Exception {
    long[] result = new long[byteLength];
    try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
      long fileLength = raf.length();
      long startPos = Math.max(0, fileLength - byteLength);
      raf.seek(startPos);

      byte[] buffer = new byte[(int) (fileLength - startPos)];
      raf.readFully(buffer);

      int padLength = byteLength - buffer.length;
      for (int i = 0; i < padLength; i++) {
        result[i] = 0;
      }
      for (int i = 0; i < buffer.length; i++) {
        result[padLength + i] = buffer[i] & 0xFF;
      }
    }
    return result;
  }

  private static String computeFileSha256(File apkFile) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] buf = new byte[8192];
    try (FileInputStream fis = new FileInputStream(apkFile)) {
      int read;
      while ((read = fis.read(buf)) != -1) {
        md.update(buf, 0, read);
      }
    }
    byte[] digest = md.digest();
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) {
      sb.append(String.format(Locale.US, "%02x", b));
    }
    return sb.toString();
  }
}
