package com.msh.vigidroid.pipeline;

import com.msh.vigidroid.FeatureContext;

/**
 * One ONNX detection pipeline: feature work from a shared {@link FeatureContext} plus inference.
 */
public interface ModelPipeline {

  String modelId();

  String domain();

  boolean isLoaded();

  StageResult run(FeatureContext ctx);

  void close();
}
