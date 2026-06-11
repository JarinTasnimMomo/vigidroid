package com.msh.vigidroid;

import org.junit.Test;

import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ManifestAxmlParserTest {

  @Test
  public void extractManifestTokens_matchesPythonTokenSet() throws Exception {
    try (InputStream is =
        getClass().getClassLoader().getResourceAsStream("sample_AndroidManifest.xml")) {
      if (is == null) {
        return;
      }
      List<String> tokens = ManifestAxmlParser.extractManifestTokens(is);
      Set<String> found = new HashSet<>(tokens);
      Set<String> expected = new HashSet<>();
      expected.add("android.permission.WRITE_EXTERNAL_STORAGE");
      expected.add("android.permission.READ_EXTERNAL_STORAGE");
      expected.add("com.msh.vigidroid.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION");
      expected.add("android.permission.MANAGE_EXTERNAL_STORAGE");
      expected.add("android.intent.action.MAIN");
      expected.add("android.intent.action.DOWNLOAD_COMPLETE");
      expected.add("android.intent.category.LAUNCHER");
      expected.add("androidx.profileinstaller.action.INSTALL_PROFILE");
      expected.add("androidx.profileinstaller.action.SKIP_FILE");
      expected.add("androidx.profileinstaller.action.SAVE_PROFILE");
      expected.add("androidx.profileinstaller.action.BENCHMARK_OPERATION");
      assertEquals(expected, found);
      assertEquals(11, tokens.size());
    }
  }

  @Test
  public void extractManifestPermissions_omitsIntentTokens() throws Exception {
    try (InputStream is =
        getClass().getClassLoader().getResourceAsStream("sample_AndroidManifest.xml")) {
      if (is == null) {
        return;
      }
      List<String> permissions = ManifestAxmlParser.extractManifestPermissions(is);
      Set<String> found = new HashSet<>(permissions);
      assertTrue(found.contains("android.permission.WRITE_EXTERNAL_STORAGE"));
      assertTrue(found.contains("com.msh.vigidroid.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"));
      assertEquals(4, permissions.size());
      for (String token : permissions) {
        assertTrue(!token.startsWith("android.intent."));
      }
    }
  }
}
