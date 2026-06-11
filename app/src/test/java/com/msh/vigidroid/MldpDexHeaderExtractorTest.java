package com.msh.vigidroid;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * A1 JVM tests — Java cascade vectors vs Python dumps on 3 golden manifests / fixtures.
 */
public class MldpDexHeaderExtractorTest {

  private static final String FIXTURES_RESOURCE = "mldp_dexheader_cascade_a1_fixtures.json";

  @Test
  public void featureDims_matchExportBundle() {
    assertEquals(22, MldpDexHeaderExtractor.S_DIM);
    assertEquals(104, MldpDexHeaderExtractor.H_DIM);
    assertEquals(126, MldpDexHeaderExtractor.D_DIM);
  }

  @Test
  public void buildXS_andFuse_fromFixtureTokens_matchesPythonDump() throws Exception {
    JSONObject root = loadFixtures();
    MldpDexHeaderExtractor extractor = extractorFromRepoAssets(root);

    JSONArray fixtures = root.getJSONArray("fixtures");
    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      JSONArray perms = fixture.getJSONArray("permissions");
      float[] expectedXS = jsonToFloats(fixture.getJSONArray("expected_x_s"));
      float[] expectedH = jsonToFloats(fixture.getJSONArray("expected_h"));
      float[] expectedX = jsonToFloats(fixture.getJSONArray("expected_x"));

      float[] xS = extractor.buildXS(jsonToStringList(perms));
      float[] x = extractor.fuse(xS, expectedH);
      assertArrayEquals(
          "x_S mismatch for " + fixture.getString("sample_id"), expectedXS, xS, 0f);
      assertArrayEquals(
          "x mismatch for " + fixture.getString("sample_id"), expectedX, x, 0f);
    }
  }

  @Test
  public void parseManifest_matchesPythonXS_forThreeGoldenManifests() throws Exception {
    JSONObject root = loadFixtures();
    MldpDexHeaderExtractor extractor = extractorFromRepoAssets(root);
    JSONArray fixtures = root.getJSONArray("fixtures");

    for (int i = 0; i < fixtures.length(); i++) {
      JSONObject fixture = fixtures.getJSONObject(i);
      String sampleId = fixture.getString("sample_id");
      float[] expectedXS = jsonToFloats(fixture.getJSONArray("expected_x_s"));
      String resourcePath = "mldp_dexheader_cascade/manifests/" + sampleId + ".xml";
      try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
        if (is == null) {
          throw new AssertionError("Missing test manifest resource: " + resourcePath);
        }
        MldpDexHeaderExtractor.ExtractionResult result = extractor.extractManifest(is);
        assertEquals(MldpDexHeaderExtractor.S_DIM, result.xS.length);
        assertArrayEquals(
            "Manifest x_S mismatch for " + sampleId, expectedXS, result.xS, 0f);
      }
    }
  }

  private static JSONObject loadFixtures() throws Exception {
    try (InputStream is =
        MldpDexHeaderExtractorTest.class.getClassLoader().getResourceAsStream(FIXTURES_RESOURCE)) {
      if (is == null) {
        throw new AssertionError("Missing fixtures: " + FIXTURES_RESOURCE);
      }
      return new JSONObject(new String(is.readAllBytes(), StandardCharsets.UTF_8));
    }
  }

  private static MldpDexHeaderExtractor extractorFromRepoAssets(JSONObject fixturesRoot)
      throws Exception {
    Path featuresDir = resolveFeaturesDir();
    return MldpDexHeaderExtractor.fromAssetStrings(
        readUtf8(featuresDir.resolve("mldp_permission_vocab.json")),
        readUtf8(featuresDir.resolve("normalization_header.json")),
        readUtf8(featuresDir.resolve("feature_layout.json")));
  }

  private static Path resolveFeaturesDir() {
    Path cwd = Paths.get(System.getProperty("user.dir"));
    Path[] candidates =
        new Path[] {
          cwd.resolve("src/main/assets/models/mldp_dexheader_cascade/features"),
          cwd.resolve("app/src/main/assets/models/mldp_dexheader_cascade/features"),
          cwd.getParent().resolve("app/src/main/assets/models/mldp_dexheader_cascade/features"),
          Paths.get("src/main/assets/models/mldp_dexheader_cascade/features"),
        };
    for (Path candidate : candidates) {
      if (Files.isDirectory(candidate)) {
        return candidate;
      }
    }
    throw new AssertionError(
        "Could not locate mldp_dexheader_cascade feature assets from " + cwd);
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
