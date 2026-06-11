package com.msh.vigidroid;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class PermissionNormalizerTest {

  @Test
  public void normalize_androidPermissionPrefix() {
    assertEquals(
        "permissions::send_sms",
        PermissionNormalizer.normalize("android.permission.SEND_SMS"));
  }

  @Test
  public void normalize_dotsBecomeUnderscores() {
    assertEquals(
        "permissions::read_phone_state",
        PermissionNormalizer.normalize("android.permission.READ_PHONE_STATE"));
  }

  @Test
  public void normalize_customPermissionWithoutAndroidPrefix() {
    assertEquals(
        "permissions::com_example_custom_perm",
        PermissionNormalizer.normalize("com.example.custom.perm"));
  }

  @Test
  public void buildBinaryVector_unknownTokensIgnored() {
    Map<String, Integer> tokenToIndex = new HashMap<>();
    tokenToIndex.put("permissions::internet", 0);
    tokenToIndex.put("permissions::send_sms", 1);
    tokenToIndex.put("permissions::camera", 2);

    float[] vec =
        PermissionNormalizer.buildBinaryVector(
            Arrays.asList(
                "permissions::send_sms", "permissions::unknown", "permissions::camera"),
            tokenToIndex,
            3);

    assertEquals(3, vec.length);
    assertEquals(0.0f, vec[0], 0f);
    assertEquals(1.0f, vec[1], 0f);
    assertEquals(1.0f, vec[2], 0f);
  }

  @Test
  public void normalizePermissions_deduplicatesAfterNormalization() {
    List<String> tokens =
        PermissionNormalizer.normalizePermissions(
            Arrays.asList(
                "android.permission.INTERNET",
                "android.permission.internet",
                "  android.permission.INTERNET  "));
    assertEquals(1, tokens.size());
    assertEquals("permissions::internet", tokens.get(0));
  }
}
