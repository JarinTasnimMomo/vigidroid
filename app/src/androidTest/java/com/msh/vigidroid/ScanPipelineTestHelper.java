package com.msh.vigidroid;

import android.content.Context;

import com.msh.vigidroid.pipeline.ScanPipelineDependencies;

import org.json.JSONArray;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtSession;

/** Builds a full {@link ScanPipelineDependencies} for instrumented legacy-scan tests. */
final class ScanPipelineTestHelper implements AutoCloseable {

  final ScanPipelineDependencies deps;

  private final OrtSession xgbSession;
  private final OrtSession cnnSession;
  private final MlpHeaderOnnxRunner mlpHeaderRunner;
  private final PatternAOnnxRunner patternARunner;
  private final PatternBOnnxRunner patternBRunner;
  private final LinRegDroidOnnxRunner linRegRunner;
  private final MldpPrunedOnnxRunner mldpRunner;
  private final BroadcastMldpHybridOnnxRunner broadcastRunner;
  private final MldpDexHeaderModeAOnnxRunner modeARunner;
  private final MldpDexHeaderModeBOnnxRunner modeBRunner;
  private final DexheaderBroadcastFusionOnnxRunner fusionRunner;

  private ScanPipelineTestHelper(
      ScanPipelineDependencies deps,
      OrtSession xgbSession,
      OrtSession cnnSession,
      MlpHeaderOnnxRunner mlpHeaderRunner,
      PatternAOnnxRunner patternARunner,
      PatternBOnnxRunner patternBRunner,
      LinRegDroidOnnxRunner linRegRunner,
      MldpPrunedOnnxRunner mldpRunner,
      BroadcastMldpHybridOnnxRunner broadcastRunner,
      MldpDexHeaderModeAOnnxRunner modeARunner,
      MldpDexHeaderModeBOnnxRunner modeBRunner,
      DexheaderBroadcastFusionOnnxRunner fusionRunner) {
    this.deps = deps;
    this.xgbSession = xgbSession;
    this.cnnSession = cnnSession;
    this.mlpHeaderRunner = mlpHeaderRunner;
    this.patternARunner = patternARunner;
    this.patternBRunner = patternBRunner;
    this.linRegRunner = linRegRunner;
    this.mldpRunner = mldpRunner;
    this.broadcastRunner = broadcastRunner;
    this.modeARunner = modeARunner;
    this.modeBRunner = modeBRunner;
    this.fusionRunner = fusionRunner;
  }

  static ScanPipelineTestHelper create(Context context) throws Exception {
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    OrtSession.SessionOptions options = OnnxSessionFactory.createOptions(context);
    Map<String, Integer> featureIndex = loadXgbFeatureIndex(context);

    OrtSession xgbSession = openCachedAssetSession(context, env, options, "mh1m_2500_rp_XGBoost.onnx");
    OrtSession cnnSession =
        openCachedAssetSession(context, env, options, "bytecnn_basemodel_2020.onnx");

    MlpHeaderOnnxRunner mlpHeaderRunner = MlpHeaderOnnxRunner.create(context, env);
    PatternAOnnxRunner patternARunner = PatternAOnnxRunner.create(context, env);
    PatternBOnnxRunner patternBRunner = PatternBOnnxRunner.create(context, env);
    LinRegDroidOnnxRunner linRegRunner = LinRegDroidOnnxRunner.create(context, env);
    MldpPrunedOnnxRunner mldpRunner = MldpPrunedOnnxRunner.create(context, env);
    BroadcastMldpHybridOnnxRunner broadcastRunner =
        BroadcastMldpHybridOnnxRunner.create(context, env);
    MldpDexHeaderModeAOnnxRunner modeARunner =
        MldpDexHeaderModeAOnnxRunner.create(context, env);
    MldpDexHeaderModeBOnnxRunner modeBRunner =
        MldpDexHeaderModeBOnnxRunner.create(context, env);
    DexheaderBroadcastFusionOnnxRunner fusionRunner =
        DexheaderBroadcastFusionOnnxRunner.create(context, env);

    ScanPipelineDependencies deps =
        new ScanPipelineDependencies(
            env,
            xgbSession,
            cnnSession,
            featureIndex,
            mlpHeaderRunner,
            DexHeaderFeatureExtractor.fromAssets(context),
            patternARunner,
            DexHeaderFeatureExtractor.fromAssets(
                context, DexHeaderFeatureExtractor.EARLY_FUSION_DEX_MANIFEST_NORMALIZATION_ASSET),
            ManifestBowExtractor.fromAssets(
                context, ManifestBowExtractor.EARLY_FUSION_DEX_MANIFEST_VOCAB_ASSET),
            patternBRunner,
            DexHeaderFeatureExtractor.fromAssets(
                context, DexHeaderFeatureExtractor.DUAL_BRANCH_DEX_MANIFEST_NORMALIZATION_ASSET),
            ManifestBowExtractor.fromAssets(
                context, ManifestBowExtractor.DUAL_BRANCH_DEX_MANIFEST_VOCAB_ASSET),
            linRegRunner,
            LinRegPermissionExtractor.fromAssets(context),
            mldpRunner,
            MldpPrunedPermissionExtractor.fromAssets(context),
            broadcastRunner,
            BroadcastMldpHybridExtractor.fromAssets(context),
            MldpDexHeaderExtractor.fromAssets(context),
            modeARunner,
            modeBRunner,
            fusionRunner,
            DexheaderBroadcastFusionExtractor.fromAssets(context));

    return new ScanPipelineTestHelper(
        deps,
        xgbSession,
        cnnSession,
        mlpHeaderRunner,
        patternARunner,
        patternBRunner,
        linRegRunner,
        mldpRunner,
        broadcastRunner,
        modeARunner,
        modeBRunner,
        fusionRunner);
  }

  @Override
  public void close() {
    closeQuietly(fusionRunner);
    closeQuietly(modeBRunner);
    closeQuietly(modeARunner);
    closeQuietly(broadcastRunner);
    closeQuietly(mldpRunner);
    closeQuietly(linRegRunner);
    closeQuietly(patternBRunner);
    closeQuietly(patternARunner);
    closeQuietly(mlpHeaderRunner);
    closeQuietly(cnnSession);
    closeQuietly(xgbSession);
  }

  private static void closeQuietly(AutoCloseable closeable) {
    if (closeable == null) {
      return;
    }
    try {
      closeable.close();
    } catch (Exception ignored) {
    }
  }

  private static OrtSession openCachedAssetSession(
      Context context, OrtEnvironment env, OrtSession.SessionOptions options, String assetName)
      throws Exception {
    File modelFile = new File(context.getCacheDir(), assetName);
    if (!modelFile.exists()) {
      try (InputStream is = context.getAssets().open(assetName);
          FileOutputStream fos = new FileOutputStream(modelFile)) {
        byte[] buf = new byte[8192];
        int r;
        while ((r = is.read(buf)) != -1) {
          fos.write(buf, 0, r);
        }
      }
    }
    return env.createSession(modelFile.getAbsolutePath(), options);
  }

  private static Map<String, Integer> loadXgbFeatureIndex(Context context) throws Exception {
    Map<String, Integer> featureIndex = new HashMap<>();
    try (InputStream is = context.getAssets().open("mh1m_2500_rp_features.json.gzip");
        GZIPInputStream gzis = new GZIPInputStream(new BufferedInputStream(is))) {
      StringBuilder sb = new StringBuilder();
      byte[] buf = new byte[8192];
      int r;
      while ((r = gzis.read(buf)) != -1) {
        sb.append(new String(buf, 0, r));
      }
      JSONArray arr = new JSONArray(sb.toString());
      for (int i = 0; i < arr.length(); i++) {
        featureIndex.put(arr.getString(i), i);
      }
    }
    return featureIndex;
  }
}
