package com.msh.vigidroid;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class ManifestBowExtractorTest {

  @Test
  public void buildMultihot_matchesPythonLexiconRules() {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    tokenToIndex.put("android.permission.INTERNET", 0);
    tokenToIndex.put("android.permission.CAMERA", 1);
    tokenToIndex.put("android.intent.action.MAIN", 2);
    int unkIndex = 3;
    int vectorSize = 4;
    ManifestBowExtractor extractor = new ManifestBowExtractor(tokenToIndex, unkIndex, vectorSize);

    float[] vec =
        extractor.buildMultihot(
            Arrays.asList("android.permission.INTERNET", "unknown.token"));

    assertEquals(vectorSize, vec.length);
    assertEquals(1.0f, vec[0], 0f);
    assertEquals(0.0f, vec[1], 0f);
    assertEquals(0.0f, vec[2], 0f);
    assertEquals(1.0f, vec[unkIndex], 0f);
    assertEquals(2.0f, sum(vec), 0f);
  }

  @Test
  public void buildMultihot_multipleUnknownTokensSetUnkOnce() {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    tokenToIndex.put("android.permission.INTERNET", 0);
    int unkIndex = 1;
    ManifestBowExtractor extractor = new ManifestBowExtractor(tokenToIndex, unkIndex, 2);

    float[] vec =
        extractor.buildMultihot(Arrays.asList("missing.one", "missing.two", "android.permission.INTERNET"));

    assertEquals(1.0f, vec[0], 0f);
    assertEquals(1.0f, vec[1], 0f);
    assertEquals(2.0f, sum(vec), 0f);
  }

  private static float sum(float[] values) {
    float total = 0f;
    for (float v : values) {
      total += v;
    }
    return total;
  }
}
