package com.msh.vigidroid;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extract manifest permission and intent action/category tokens from binary AXML.
 * Matches Python pattern_a manifest_bow.extract_manifest_tokens (pyaxmlparser).
 */
public final class ManifestAxmlParser {

  private static final int RES_XML_TYPE = 0x0003;
  private static final int RES_STRING_POOL_TYPE = 0x0001;
  private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
  private static final int RES_XML_END_ELEMENT_TYPE = 0x0103;
  private static final int TYPE_STRING = 0x03;

  /** Permissions plus static {@code <receiver>} intent actions (matches Python P2). */
  public static final class HybridManifestFeatures {
    public final List<String> permissions;
    public final List<String> receiverActions;

    HybridManifestFeatures(List<String> permissions, List<String> receiverActions) {
      this.permissions = permissions;
      this.receiverActions = receiverActions;
    }
  }

  private ManifestAxmlParser() {}

  public static List<String> extractManifestTokens(InputStream is) throws Exception {
    return extractManifestStrings(is, false);
  }

  /** Permission tags only (uses-permission*, permission); no intent actions/categories. */
  public static List<String> extractManifestPermissions(InputStream is) throws Exception {
    return extractManifestStrings(is, true);
  }

  /**
   * Static {@code <receiver>} descendant {@code <action android:name>} values only (M3 raw stage;
   * caller filters against system_actions.json).
   */
  public static List<String> extractReceiverActions(InputStream is) throws Exception {
    return parseHybridManifest(is).receiverActions;
  }

  /** Permissions and receiver-scoped actions in one AXML pass. */
  public static HybridManifestFeatures parseHybridManifest(InputStream is) throws Exception {
    byte[] buf = readAll(is);
    if (readU16(buf, 0) != RES_XML_TYPE) {
      throw new IllegalStateException("Expected RES_XML_TYPE chunk");
    }
    int xmlHeaderSize = readU16(buf, 2);
    int xmlChunkSize = readInt(buf, 4);

    StringPool pool = null;
    List<String> permissions = new ArrayList<>();
    List<String> receiverActions = new ArrayList<>();
    Set<String> seenPermissions = new HashSet<>();
    Set<String> seenActions = new HashSet<>();
    int receiverDepth = 0;

    int offset = xmlHeaderSize;
    while (offset + 8 <= xmlChunkSize) {
      int chunkType = readU16(buf, offset);
      int headerSize = readU16(buf, offset + 2);
      int chunkSize = readInt(buf, offset + 4);
      if (chunkSize < 8 || offset + chunkSize > xmlChunkSize) {
        break;
      }

      if (chunkType == RES_STRING_POOL_TYPE && pool == null) {
        pool = parseStringPool(buf, offset);
      } else if (pool != null && chunkType == RES_XML_START_ELEMENT_TYPE) {
        String tagName = elementTagName(buf, offset, headerSize, chunkSize, pool);
        if ("receiver".equals(tagName)) {
          receiverDepth++;
        }
        collectHybridStartElement(
            buf,
            offset,
            headerSize,
            chunkSize,
            pool,
            tagName,
            receiverDepth,
            permissions,
            seenPermissions,
            receiverActions,
            seenActions);
      } else if (pool != null && chunkType == RES_XML_END_ELEMENT_TYPE) {
        String tagName = elementTagName(buf, offset, headerSize, chunkSize, pool);
        if ("receiver".equals(tagName) && receiverDepth > 0) {
          receiverDepth--;
        }
      }
      offset += chunkSize;
    }

    if (permissions.isEmpty() && receiverActions.isEmpty()) {
      throw new IllegalStateException("No manifest tokens found");
    }
    return new HybridManifestFeatures(permissions, receiverActions);
  }

  private static List<String> extractManifestStrings(InputStream is, boolean permissionsOnly)
      throws Exception {
    byte[] buf = readAll(is);
    if (readU16(buf, 0) != RES_XML_TYPE) {
      throw new IllegalStateException("Expected RES_XML_TYPE chunk");
    }
    int xmlHeaderSize = readU16(buf, 2);
    int xmlChunkSize = readInt(buf, 4);

    StringPool pool = null;
    List<String> tokens = new ArrayList<>();
    Set<String> seen = new HashSet<>();

    int offset = xmlHeaderSize;
    while (offset + 8 <= xmlChunkSize) {
      int chunkType = readU16(buf, offset);
      int headerSize = readU16(buf, offset + 2);
      int chunkSize = readInt(buf, offset + 4);
      if (chunkSize < 8 || offset + chunkSize > xmlChunkSize) {
        break;
      }

      if (chunkType == RES_STRING_POOL_TYPE && pool == null) {
        pool = parseStringPool(buf, offset);
      } else if (chunkType == RES_XML_START_ELEMENT_TYPE && pool != null) {
        parseStartElement(
            buf, offset, headerSize, chunkSize, pool, tokens, seen, permissionsOnly);
      }
      offset += chunkSize;
    }

    if (tokens.isEmpty()) {
      throw new IllegalStateException("No manifest tokens found");
    }
    return tokens;
  }

  private static String elementTagName(
      byte[] buf, int offset, int headerSize, int chunkSize, StringPool pool) {
    if (offset + 28 > offset + chunkSize) {
      return "";
    }
    return pool.getString(readInt(buf, offset + 20));
  }

  private static void collectHybridStartElement(
      byte[] buf,
      int offset,
      int headerSize,
      int chunkSize,
      StringPool pool,
      String tagName,
      int receiverDepth,
      List<String> permissions,
      Set<String> seenPermissions,
      List<String> receiverActions,
      Set<String> seenActions) {
    int attributeStart = readU16(buf, offset + 24);
    int attributeSize = readU16(buf, offset + 26);
    int attributeCount = readU16(buf, offset + 28);
    if (attributeSize == 0) {
      attributeSize = 20;
    }
    int attrBase = offset + headerSize + attributeStart;
    for (int i = 0; i < attributeCount; i++) {
      int attrOff = attrBase + i * attributeSize;
      if (attrOff + attributeSize > offset + chunkSize) {
        break;
      }
      String attrName = pool.getString(readInt(buf, attrOff + 4));
      if (!"name".equals(attrName)) {
        continue;
      }
      int rawValueIdx = readInt(buf, attrOff + 8);
      int dataType = buf[attrOff + 15] & 0xFF;
      int data = readInt(buf, attrOff + 16);
      String value = resolveAttributeValue(pool, dataType, data, rawValueIdx);
      if (value == null || value.isEmpty()) {
        continue;
      }
      if (isPermissionTag(tagName)) {
        addToken(permissions, seenPermissions, value);
      } else if ("action".equals(tagName) && receiverDepth > 0) {
        addToken(receiverActions, seenActions, value);
      }
    }
  }

  private static void parseStartElement(
      byte[] buf,
      int offset,
      int headerSize,
      int chunkSize,
      StringPool pool,
      List<String> tokens,
      Set<String> seen,
      boolean permissionsOnly) {
    if (offset + 28 > offset + chunkSize) {
      return;
    }
    String tagName = pool.getString(readInt(buf, offset + 20));
    int attributeStart = readU16(buf, offset + 24);
    int attributeSize = readU16(buf, offset + 26);
    int attributeCount = readU16(buf, offset + 28);
    if (attributeSize == 0) {
      attributeSize = 20;
    }
    int attrBase = offset + headerSize + attributeStart;
    for (int i = 0; i < attributeCount; i++) {
      int attrOff = attrBase + i * attributeSize;
      if (attrOff + attributeSize > offset + chunkSize) {
        break;
      }
      String attrName = pool.getString(readInt(buf, attrOff + 4));
      if (!"name".equals(attrName)) {
        continue;
      }
      int rawValueIdx = readInt(buf, attrOff + 8);
      int dataType = buf[attrOff + 15] & 0xFF;
      int data = readInt(buf, attrOff + 16);
      String value = resolveAttributeValue(pool, dataType, data, rawValueIdx);
      if (value == null || value.isEmpty()) {
        continue;
      }
      boolean include =
          permissionsOnly
              ? isPermissionTag(tagName)
              : isPermissionTag(tagName) || "action".equals(tagName) || "category".equals(tagName);
      if (include) {
        addToken(tokens, seen, value);
      }
    }
  }

  private static boolean isPermissionTag(String tagName) {
    return "permission".equals(tagName) || tagName.startsWith("uses-permission");
  }

  private static String resolveAttributeValue(
      StringPool pool, int dataType, int data, int rawValueIdx) {
    if (dataType == TYPE_STRING) {
      return pool.getString(data);
    }
    if (rawValueIdx >= 0) {
      return pool.getString(rawValueIdx);
    }
    return null;
  }

  private static void addToken(List<String> tokens, Set<String> seen, String value) {
    String trimmed = value.trim();
    if (!trimmed.isEmpty() && seen.add(trimmed)) {
      tokens.add(trimmed);
    }
  }

  private static byte[] readAll(InputStream is) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int read;
    while ((read = is.read(buffer)) != -1) {
      baos.write(buffer, 0, read);
    }
    return baos.toByteArray();
  }

  private static int readInt(byte[] data, int offset) {
    return (data[offset] & 0xFF)
        | ((data[offset + 1] & 0xFF) << 8)
        | ((data[offset + 2] & 0xFF) << 16)
        | ((data[offset + 3] & 0xFF) << 24);
  }

  private static int readU16(byte[] data, int offset) {
    return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
  }

  private static StringPool parseStringPool(byte[] buf, int offset) {
    int headerSize = readU16(buf, offset + 2);
    int stringCount = readInt(buf, offset + 8);
    int stringsStart = readInt(buf, offset + 20);
    String[] strings = new String[stringCount];
    int offsetsBase = offset + headerSize;
    int stringsBase = offset + stringsStart;
    for (int i = 0; i < stringCount; i++) {
      int stringOff = readInt(buf, offsetsBase + i * 4);
      strings[i] = readUtf16String(buf, stringsBase + stringOff);
    }
    return new StringPool(strings);
  }

  private static String readUtf16String(byte[] data, int offset) {
    if (offset < 0 || offset + 2 > data.length) {
      return "";
    }
    int len = readU16(data, offset);
    int byteLen = len * 2;
    if (offset + 2 + byteLen > data.length) {
      return "";
    }
    return new String(data, offset + 2, byteLen, StandardCharsets.UTF_16LE);
  }

  private static final class StringPool {
    private final String[] strings;

    StringPool(String[] strings) {
      this.strings = strings;
    }

    String getString(int index) {
      if (index < 0 || index >= strings.length) {
        return "";
      }
      String s = strings[index];
      return s != null ? s : "";
    }
  }
}
