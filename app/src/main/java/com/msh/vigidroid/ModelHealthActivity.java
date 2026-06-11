package com.msh.vigidroid;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;

import java.util.List;
import java.util.Locale;

import ai.onnxruntime.BuildConfig;
import ai.onnxruntime.OrtEnvironment;

/** Debug-only one-tap ONNX parity health check (Phase 6). */
public class ModelHealthActivity extends AppCompatActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (!BuildConfig.DEBUG) {
      finish();
      return;
    }
    setContentView(R.layout.activity_model_health);
    TextView body = findViewById(R.id.txtModelHealth);
    MaterialButton rerun = findViewById(R.id.btnModelHealthRerun);
    rerun.setOnClickListener(v -> runChecks(body));
    runChecks(body);
  }

  private void runChecks(TextView body) {
    body.setText(getString(R.string.model_health_running));
    new Thread(
            () -> {
              OrtEnvironment env = OrtEnvironment.getEnvironment();
              MldpDexHeaderModeAOnnxRunner modeA = null;
              BroadcastMldpHybridOnnxRunner broadcast = null;
              DexheaderBroadcastFusionOnnxRunner fusion = null;
              try {
                modeA = MldpDexHeaderModeAOnnxRunner.create(this, env);
                broadcast = BroadcastMldpHybridOnnxRunner.create(this, env);
                fusion = DexheaderBroadcastFusionOnnxRunner.create(this, env);
                List<ModelHealthChecker.Result> results =
                    ModelHealthChecker.runAll(this, modeA, broadcast, fusion);
                final String text = formatResults(results);
                boolean allOk = true;
                for (ModelHealthChecker.Result r : results) {
                  if (!r.ok) {
                    allOk = false;
                    break;
                  }
                }
                final boolean finalAllOk = allOk;
                runOnUiThread(
                    () -> {
                      body.setText(text);
                      Toast.makeText(
                              this,
                              finalAllOk
                                  ? getString(R.string.model_health_all_ok)
                                  : getString(R.string.model_health_some_failed),
                              Toast.LENGTH_SHORT)
                          .show();
                    });
              } catch (Exception ex) {
                final String errText = "Init failed: " + ex.getMessage();
                runOnUiThread(() -> body.setText(errText));
              } finally {
                closeQuietly(modeA);
                closeQuietly(broadcast);
                closeQuietly(fusion);
              }
            })
        .start();
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

  private static String formatResults(List<ModelHealthChecker.Result> results) {
    StringBuilder sb = new StringBuilder();
    int ok = 0;
    for (ModelHealthChecker.Result result : results) {
      sb.append(result.ok ? "[OK] " : "[FAIL] ")
          .append(result.modelId)
          .append('\n')
          .append("  ")
          .append(result.detail)
          .append("\n\n");
      if (result.ok) {
        ok++;
      }
    }
    sb.insert(
        0,
        String.format(
                Locale.US,
                "Parity tolerance ±%.0e\n%d/%d passed\n\n",
                ModelHealthChecker.TOLERANCE,
                ok,
                results.size()));
    return sb.toString();
  }
}
