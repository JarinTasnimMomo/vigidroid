package com.msh.vigidroid;

import android.content.Context;

import androidx.test.platform.app.InstrumentationRegistry;

import java.io.InputStream;

/** Read files bundled under androidTest/assets (not shipped in the release APK). */
public final class TestAssetHelper {

  private TestAssetHelper() {}

  public static Context appContext() {
    return InstrumentationRegistry.getInstrumentation().getTargetContext();
  }

  public static Context testContext() {
    return InstrumentationRegistry.getInstrumentation().getContext();
  }

  public static String readTestAssetText(String assetPath) throws Exception {
    return ModelAssetHelper.readAssetText(testContext(), assetPath);
  }

  public static InputStream openTestAsset(String assetPath) throws Exception {
    return testContext().getAssets().open(assetPath);
  }

  public static boolean testAssetExists(String assetPath) {
    try (InputStream ignored = openTestAsset(assetPath)) {
      return true;
    } catch (Exception e) {
      return false;
    }
  }
}
