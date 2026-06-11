package com.msh.vigidroid;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class MldpPrunedPermissionExtractorTest {

  @Test
  public void buildBinaryVector_prunedSetOnly() {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    tokenToIndex.put("permissions::send_sms", 0);
    tokenToIndex.put("permissions::read_sms", 1);
    tokenToIndex.put("permissions::camera", 2);
    MldpPrunedPermissionExtractor extractor = new MldpPrunedPermissionExtractor(tokenToIndex, 3);

    float[] vec =
        extractor.buildBinaryVector(
            Arrays.asList(
                "permissions::send_sms",
                "permissions::internet",
                "permissions::read_sms"));

    assertArrayEquals(new float[] {1f, 1f, 0f}, vec, 0f);
  }

  @Test
  public void featureDim_matchesFrozenSetS() {
    assertEquals(40, MldpPrunedPermissionExtractor.FEATURE_DIM);
  }
}
