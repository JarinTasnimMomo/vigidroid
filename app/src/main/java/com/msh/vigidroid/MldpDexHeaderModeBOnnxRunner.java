package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.Closeable;

import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

/**
 * A2 — Mode B cascade ONNX: Stage-1 MLDP on x_S; uncertain band invokes Stage-2 on H.
 */
public final class MldpDexHeaderModeBOnnxRunner implements Closeable {

  private static final String TAG = "MldpDexHeaderModeBOnnx";
  public static final String MODEL_ID = "mldp_dexheader_cascade_mode_b";
  public static final String DOMAIN = "manifest_mldp_perm_dex_header";
  private static final String ASSET_PREFIX = "models/mldp_dexheader_cascade/mode_b/";
  private static final String STAGE1_MODEL_ASSET = ASSET_PREFIX + "stage1_mldp.onnx";
  private static final String STAGE2_MODEL_ASSET = ASSET_PREFIX + "stage2_mlp_header.onnx";
  private static final String MANIFEST_ASSET = ASSET_PREFIX + "export_manifest.json";
  private static final String THRESHOLDS_ASSET = "models/mldp_dexheader_cascade/thresholds.json";
  private static final String STAGE1_CACHE = "mldp_dexheader_cascade_stage1.onnx";
  private static final String STAGE2_CACHE = "mldp_dexheader_cascade_stage2.onnx";
  public static final float SKIPPED_STAGE2_SCORE = -1f;

  public enum EarlyExitKind {
    NONE,
    BENIGN,
    MALWARE
  }

  public static final class CascadeResult {
    public final float stage1Score;
    public final float stage2Score;
    public final float finalScore;
    public final EarlyExitKind earlyExitKind;
    public final boolean skippedDex;
    public final boolean malware;

    CascadeResult(
        float stage1Score,
        float stage2Score,
        float finalScore,
        EarlyExitKind earlyExitKind,
        boolean skippedDex,
        boolean malware) {
      this.stage1Score = stage1Score;
      this.stage2Score = stage2Score;
      this.finalScore = finalScore;
      this.earlyExitKind = earlyExitKind;
      this.skippedDex = skippedDex;
      this.malware = malware;
    }

    public boolean isEarlyExit() {
      return earlyExitKind != EarlyExitKind.NONE;
    }
  }

  private final OrtEnvironment environment;
  private final OrtSession stage1Session;
  private final OrtSession stage2Session;
  private final String stage1InputName;
  private final String stage1OutputName;
  private final String stage2InputName;
  private final String stage2OutputName;
  private final MldpDexHeaderCascadeThresholds thresholds;

  private MldpDexHeaderModeBOnnxRunner(
      OrtEnvironment environment,
      OrtSession stage1Session,
      OrtSession stage2Session,
      String stage1InputName,
      String stage1OutputName,
      String stage2InputName,
      String stage2OutputName,
      MldpDexHeaderCascadeThresholds thresholds) {
    this.environment = environment;
    this.stage1Session = stage1Session;
    this.stage2Session = stage2Session;
    this.stage1InputName = stage1InputName;
    this.stage1OutputName = stage1OutputName;
    this.stage2InputName = stage2InputName;
    this.stage2OutputName = stage2OutputName;
    this.thresholds = thresholds;
  }

  public static MldpDexHeaderModeBOnnxRunner create(Context context, OrtEnvironment sharedEnv)
      throws Exception {
    JSONObject manifest = new JSONObject(ModelAssetHelper.readAssetText(context, MANIFEST_ASSET));
    JSONObject stage1 = manifest.getJSONObject("stage1");
    JSONObject stage2 = manifest.getJSONObject("stage2");
    String stage1Input = OnnxManifestIo.inputName(stage1, "features");
    String stage1Output = OnnxManifestIo.outputName(stage1, "stage1_prob");
    String stage2Input = OnnxManifestIo.inputName(stage2, "features");
    String stage2Output = OnnxManifestIo.malwareOutputName(stage2);

    MldpDexHeaderCascadeThresholds thresholds =
        MldpDexHeaderCascadeThresholds.fromAsset(context, THRESHOLDS_ASSET);
    java.io.File stage1File =
        ModelAssetHelper.copyAssetToCache(context, STAGE1_MODEL_ASSET, STAGE1_CACHE);
    java.io.File stage2File =
        ModelAssetHelper.copyAssetToCache(context, STAGE2_MODEL_ASSET, STAGE2_CACHE);
    OrtSession stage1Session =
        sharedEnv.createSession(
            stage1File.getAbsolutePath(), OnnxSessionFactory.createOptions(context));
    OrtSession stage2Session =
        sharedEnv.createSession(
            stage2File.getAbsolutePath(), OnnxSessionFactory.createOptions(context));
    OnnxSessionDiagnostics.logSingleIo(
        TAG, MODEL_ID + "_stage1", stage1Session, stage1Input, stage1Output);
    OnnxSessionDiagnostics.logSingleIo(
        TAG, MODEL_ID + "_stage2", stage2Session, stage2Input, stage2Output);
    Log.i(
        TAG,
        "Loaded Mode B cascade ONNX (t_low="
            + thresholds.getStage1TLow()
            + ", t_high="
            + thresholds.getStage1THigh()
            + ")");
    return new MldpDexHeaderModeBOnnxRunner(
        sharedEnv,
        stage1Session,
        stage2Session,
        stage1Input,
        stage1Output,
        stage2Input,
        stage2Output,
        thresholds);
  }

  public MldpDexHeaderCascadeThresholds getThresholds() {
    return thresholds;
  }

  public float predictStage1(float[] xS) throws OrtException {
    if (xS.length != MldpDexHeaderExtractor.S_DIM) {
      throw new IllegalArgumentException(
          "Expected " + MldpDexHeaderExtractor.S_DIM + " x_S features, got " + xS.length);
    }
    return MldpDexHeaderModeAOnnxRunner.runSession(
        stage1Session, stage1InputName, stage1OutputName, environment, xS);
  }

  public float predictStage2(float[] h) throws OrtException {
    if (h.length != MldpDexHeaderExtractor.H_DIM) {
      throw new IllegalArgumentException(
          "Expected " + MldpDexHeaderExtractor.H_DIM + " H features, got " + h.length);
    }
    return MldpDexHeaderModeAOnnxRunner.runSession(
        stage2Session, stage2InputName, stage2OutputName, environment, h);
  }

  /**
   * Evaluate cascade after optional feature extraction. When {@code h} is null and Stage-1 is
   * uncertain, throws — caller must extract dex header first (A3 orchestration).
   */
  public CascadeResult predictCascade(float[] xS, float[] h) throws OrtException {
    float s1 = predictStage1(xS);
    if (thresholds.isEarlyExitBenign(s1)) {
      return new CascadeResult(
          s1, SKIPPED_STAGE2_SCORE, s1, EarlyExitKind.BENIGN, true, false);
    }
    if (thresholds.isEarlyExitMalware(s1)) {
      return new CascadeResult(
          s1, SKIPPED_STAGE2_SCORE, s1, EarlyExitKind.MALWARE, true, true);
    }
    if (h == null) {
      throw new IllegalStateException("Stage-2 requires H when Stage-1 score is in uncertain band");
    }
    float s2 = predictStage2(h);
    boolean malware = thresholds.isMalwareStage2(s2);
    return new CascadeResult(s1, s2, s2, EarlyExitKind.NONE, false, malware);
  }

  /** Stage-1 only — reports whether dex read can be skipped (early exit). */
  public CascadeResult predictStage1Gate(float[] xS) throws OrtException {
    float s1 = predictStage1(xS);
    if (thresholds.isEarlyExitBenign(s1)) {
      return new CascadeResult(
          s1, SKIPPED_STAGE2_SCORE, s1, EarlyExitKind.BENIGN, true, false);
    }
    if (thresholds.isEarlyExitMalware(s1)) {
      return new CascadeResult(
          s1, SKIPPED_STAGE2_SCORE, s1, EarlyExitKind.MALWARE, true, true);
    }
    return new CascadeResult(s1, SKIPPED_STAGE2_SCORE, s1, EarlyExitKind.NONE, false, false);
  }

  @Override
  public void close() {
    if (stage1Session != null) {
      try {
        stage1Session.close();
      } catch (Exception ignored) {
      }
    }
    if (stage2Session != null) {
      try {
        stage2Session.close();
      } catch (Exception ignored) {
      }
    }
  }
}
