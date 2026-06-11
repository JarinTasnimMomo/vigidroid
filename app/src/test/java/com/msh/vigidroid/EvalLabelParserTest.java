package com.msh.vigidroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class EvalLabelParserTest {

  @Test
  public void parsesEvalFilenameLabels() {
    assertEquals("benign", EvalLabelParser.groundTruthFromApkName("eval_0001_benign.apk"));
    assertEquals("malware", EvalLabelParser.groundTruthFromApkName("eval_0400_malware.apk"));
    assertEquals("unknown", EvalLabelParser.groundTruthFromApkName("random_app.apk"));
  }
}
