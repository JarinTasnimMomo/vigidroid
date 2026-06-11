package com.msh.vigidroid;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A1 JVM tests — Java hybrid vector vs Python parity dump on 3 golden manifests.
 */
public class BroadcastMldpHybridExtractorTest {

  private static final String FIXTURES_RESOURCE = "broadcast_mldp_hybrid_parity_fixtures.json";

  @Test
  public void featureDim_matchesExportBundle() {
    assertEquals(22, BroadcastMldpHybridExtractor.S_DIM);
    assertEquals(70, BroadcastMldpHybridExtractor.R_DIM);
    assertEquals(92, BroadcastMldpHybridExtractor.FEATURE_DIM);
  }

  @Test
  public void buildHybridVector_fromFixtureTokens_matchesPythonDump() throws Exception {
    JSONObject root = loadFixtures();
    BroadcastMldpHybridExtractor extractor = extractorFromRepoAssets(root);

    JSONArray fixtures = root.getJSONArray("fixtures");
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      JSONArray perms = fixture.getJSONArray("permissions");
      JSONArray actions = fixture.getJSONArray("receiver_actions");
      float[] expected = jsonToFloats(fixture.getJSONArray("expected_vector"));

      float[] actual =
          extractor.buildHybridVector(jsonToStringList(perms), jsonToStringList(actions));
      assertArrayEquals(
          "Token vector mismatch for " + fixture.getString("sample_id"),
          expected,
          actual,
          0f);
    }
  }

  @Test
  public void parseManifest_matchesPythonDump_forThreeGoldenManifests() throws Exception {
    JSONObject root = loadFixtures();
    BroadcastMldpHybridExtractor extractor = extractorFromRepoAssets(root);
    JSONArray fixtures = root.getJSONArray("fixtures");

    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String basename = fixture.getString("apk_basename").replace(".apk", ".xml");
      String resourcePath = "broadcast_mldp_hybrid/manifests/" + basename;
      try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
        if (is == null) {
          throw new AssertionError("Missing test manifest resource: " + resourcePath);
        }
        BroadcastMldpHybridExtractor.ExtractionResult result = extractor.extractManifest(is);
        float[] expected = jsonToFloats(fixture.getJSONArray("expected_vector"));
        assertEquals(
            BroadcastMldpHybridExtractor.FEATURE_DIM,
            result.vector.length);
        assertArrayEquals(
            "Manifest parse mismatch for " + fixture.getString("sample_id"),
            expected,
            result.vector,
            0f);
      }
    }
  }

  @Test
  public void filterReceiverSystemActions_dropsNonSystemActions() throws Exception {
    JSONObject root = loadFixtures();
    BroadcastMldpHybridExtractor extractor = extractorFromRepoAssets(root);
    assertTrue(
        extractor
            .filterReceiverSystemActions(
                Arrays.asList(
                    "android.intent.action.BOOT_COMPLETED",
                    "com.vendor.custom.ACTION",
                    "android.intent.action.BOOT_COMPLETED"))
            .equals(Arrays.asList("android.intent.action.BOOT_COMPLETED")));
  }

  private static JSONObject loadFixtures() throws Exception {
    try (InputStream is = BroadcastMldpHybridExtractorTest.class.getClassLoader()
        .getResourceAsStream(FIXTURES_RESOURCE)) {
      if (is == null) {
        throw new AssertionError("Missing fixtures: " + FIXTURES_RESOURCE);
      }
      byte[] bytes = is.readAllBytes();
      return new JSONObject(new String(bytes, StandardCharsets.UTF_8));
    }
  }

  private static BroadcastMldpHybridExtractor extractorFromRepoAssets(JSONObject fixturesRoot)
      throws Exception {
    Path featuresDir = resolveFeaturesDir();
    return BroadcastMldpHybridExtractor.fromAssetStrings(
        readUtf8(featuresDir.resolve("mldp_permission_vocab.json")),
        readUtf8(featuresDir.resolve("receiver_action_vocab.json")),
        readUtf8(featuresDir.resolve("system_actions.json")),
        readUtf8(featuresDir.resolve("feature_layout.json")));
  }

  private static Path resolveFeaturesDir() {
    Path cwd = Paths.get(System.getProperty("user.dir"));
    Path[] candidates =
        new Path[] {
          cwd.resolve("src/main/assets/models/broadcast_mldp_hybrid/features"),
          cwd.resolve("app/src/main/assets/models/broadcast_mldp_hybrid/features"),
          cwd.getParent().resolve("app/src/main/assets/models/broadcast_mldp_hybrid/features"),
          Paths.get("src/main/assets/models/broadcast_mldp_hybrid/features"),
        };
    for (Path candidate : candidates) {
      if (Files.isDirectory(candidate)) {
        return candidate;
      }
    }
    throw new AssertionError("Could not locate broadcast_mldp_hybrid feature assets from " + cwd);
  }

  private static float[] jsonToFloats(JSONArray row) throws Exception {
    float[] values = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      values[i] = (float) row.getDouble(i);
    }
    return values;
  }

  private static String readUtf8(Path path) throws Exception {
    return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
  }

  private static java.util.List<String> jsonToStringList(JSONArray row) throws Exception {
    java.util.List<String> out = new java.util.ArrayList<>();
    for (int i = 0; i < row.length(); i++) {
      out.add(row.getString(i));
    }
    return out;
  }
}
