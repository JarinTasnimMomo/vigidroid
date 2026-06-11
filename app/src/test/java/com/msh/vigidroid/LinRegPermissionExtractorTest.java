package com.msh.vigidroid;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class LinRegPermissionExtractorTest {

  @Test
  public void buildBinaryVector_matchesPythonVocabRules() {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    tokenToIndex.put("permissions::internet", 0);
    tokenToIndex.put("permissions::send_sms", 1);
    tokenToIndex.put("permissions::camera", 2);
    LinRegPermissionExtractor extractor = new LinRegPermissionExtractor(tokenToIndex, 3);

    float[] vec =
        extractor.buildBinaryVector(
            Arrays.asList("permissions::send_sms", "permissions::unknown", "permissions::camera"));

    assertArrayEquals(new float[] {0f, 1f, 1f}, vec, 0f);
  }

  @Test
  public void featureDim_matchesVectorSize() {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    tokenToIndex.put("permissions::internet", 0);
    LinRegPermissionExtractor extractor = new LinRegPermissionExtractor(tokenToIndex, 1);
    assertEquals(1, extractor.featureDim());
  }
}
