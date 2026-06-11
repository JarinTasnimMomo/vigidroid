package com.msh.vigidroid;

import android.content.Context;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.InputStream;

import ai.onnxruntime.OrtEnvironment;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Phase 0 — isolate extract vs infer for the three models that failed on device with
 * {@code f != java.lang.Long}. ONNX-only tests use bundled parity vectors (no APK extract).
 *
 * <p>Run: {@code Android_Works/run_phase0_isolation.sh}
 */
@RunWith(AndroidJUnit4.class)
public class Phase0FailingModelsIsolationTest {

  private static final String TAG = "Phase0Isolation";

  @Test
  public void modeA_onnxOnly_firstParityVector() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root =
        new JSONObject(
            ModelAssetHelper.readAssetText(
                context, "models/mldp_dexheader_cascade/parity_samples/parity_onnx_vectors.json"));
    JSONArray vectors = root.getJSONArray("vectors");
    float[] features = jsonRowToFloats(vectors.getJSONArray(0));
    assertEquals(MldpDexHeaderExtractor.D_DIM, features.length);

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    MldpDexHeaderModeAOnnxRunner runner = MldpDexHeaderModeAOnnxRunner.create(context, env);
    try {
      float score = runner.predict(features);
      Log.i(TAG, "mode_a onnx_only score=" + score);
      assertNotNull(score);
    } catch (Exception ex) {
      fail("mode_a@infer(onnx_only): " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
    } finally {
      runner.close();
    }
  }

  @Test
  public void broadcast_onnxOnly_firstParityVector() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    JSONObject root =
        new JSONObject(
            ModelAssetHelper.readAssetText(
                context, "models/broadcast_mldp_hybrid/parity_samples/parity_vectors.json"));
    float[] features = jsonRowToFloats(root.getJSONArray("vectors").getJSONArray(0));
    assertEquals(BroadcastMldpHybridExtractor.FEATURE_DIM, features.length);

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    BroadcastMldpHybridOnnxRunner runner = BroadcastMldpHybridOnnxRunner.create(context, env);
    try {
      float score = runner.predict(features);
      Log.i(TAG, "broadcast_mldp_hybrid onnx_only score=" + score);
      assertNotNull(score);
    } catch (Exception ex) {
      fail(
          "broadcast_mldp_hybrid@infer(onnx_only): "
              + ex.getClass().getSimpleName()
              + ": "
              + ex.getMessage());
    } finally {
      runner.close();
    }
  }

  @Test
  public void broadcast_extractOnly_sample000_manifest() throws Exception {
    Context context = TestAssetHelper.appContext();
    BroadcastMldpHybridExtractor extractor = BroadcastMldpHybridExtractor.fromAssets(context);
    String manifestAsset =
        "models/broadcast_mldp_hybrid/parity_samples/manifests/sample_000.xml";
    try (InputStream is = TestAssetHelper.openTestAsset(manifestAsset)) {
      BroadcastMldpHybridExtractor.ExtractionResult result = extractor.extractManifest(is);
      Log.i(
          TAG,
          "broadcast extract_only vec_dim="
              + result.vector.length
              + " perms="
              + result.permissionCount);
      assertEquals(BroadcastMldpHybridExtractor.FEATURE_DIM, result.vector.length);
      assertTrue(result.permissionCount >= 0);
    } catch (Exception ex) {
      fail(
          "broadcast_mldp_hybrid@extract(manifest_only): "
              + ex.getClass().getSimpleName()
              + ": "
              + ex.getMessage());
    }
  }

  @Test
  public void broadcast_e2e_singleSample_extractThenInfer() throws Exception {
    Context context = TestAssetHelper.appContext();
    BroadcastMldpHybridExtractor extractor = BroadcastMldpHybridExtractor.fromAssets(context);
    OrtEnvironment env = OrtEnvironment.getEnvironment();
    BroadcastMldpHybridOnnxRunner runner = BroadcastMldpHybridOnnxRunner.create(context, env);
    String manifestAsset =
        "models/broadcast_mldp_hybrid/parity_samples/manifests/sample_000.xml";
    try (InputStream is = TestAssetHelper.openTestAsset(manifestAsset)) {
      BroadcastMldpHybridExtractor.ExtractionResult extraction = extractor.extractManifest(is);
      float score = runner.predict(extraction.vector);
      Log.i(TAG, "broadcast e2e sample_000 score=" + score);
      assertTrue(score >= 0f && score <= 1f);
    } catch (Exception ex) {
      fail(
          "broadcast_mldp_hybrid@e2e(sample_000): "
              + ex.getClass().getSimpleName()
              + ": "
              + ex.getMessage());
    } finally {
      runner.close();
    }
  }

  @Test
  public void modeA_extractManifestOnly_sample000() throws Exception {
    Context context = TestAssetHelper.appContext();
    MldpDexHeaderExtractor extractor = MldpDexHeaderExtractor.fromAssets(context);
    String manifestAsset =
        "models/mldp_dexheader_cascade/parity_samples/manifests/sample_000.xml";
    try (InputStream is = TestAssetHelper.openTestAsset(manifestAsset)) {
      MldpDexHeaderExtractor.ExtractionResult result = extractor.extractManifest(is);
      Log.i(TAG, "mode_a manifest_only x_dim=" + result.x.length);
      assertEquals(MldpDexHeaderExtractor.D_DIM, result.x.length);
    } catch (Exception ex) {
      fail(
          "mldp_dexheader_cascade_mode_a@extract(manifest_only): "
              + ex.getClass().getSimpleName()
              + ": "
              + ex.getMessage());
    }
  }

  @Test
  public void dexFusion_onnxOnly_zeroVectors() throws Exception {
    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    float[] header = new float[DexHeaderFeatureExtractor.FEATURE_DIM];
    float[] receiver = new float[70];

    OrtEnvironment env = OrtEnvironment.getEnvironment();
    DexheaderBroadcastFusionOnnxRunner runner =
        DexheaderBroadcastFusionOnnxRunner.create(context, env);
    try {
      float score = runner.predict(header, receiver);
      Log.i(TAG, "dexheader_broadcast_fusion onnx_only score=" + score);
      assertNotNull(score);
    } catch (Exception ex) {
      fail(
          "dexheader_broadcast_fusion@infer(onnx_only): "
              + ex.getClass().getSimpleName()
              + ": "
              + ex.getMessage());
    } finally {
      runner.close();
    }
  }

  private static float[] jsonRowToFloats(JSONArray row) throws Exception {
    float[] values = new float[row.length()];
    for (int i = 0; i < row.length(); i++) {
      values[i] = (float) row.getDouble(i);
    }
    return values;
  }

}
