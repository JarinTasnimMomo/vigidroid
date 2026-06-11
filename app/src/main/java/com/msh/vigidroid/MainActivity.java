package com.msh.vigidroid;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.widget.SwitchCompat;

import com.google.android.material.button.MaterialButton;
import com.msh.vigidroid.pipeline.ScanDetailFormatter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Locale;
import java.util.UUID;

public class MainActivity extends AppCompatActivity {

    public static final String ACTION_SCAN_LOG = "SCAN_LOG";
    public static final String ACTION_SCAN_RESULT = "SCAN_RESULT";
    /** adb: am start … --ez auto_rescan_all true --ez cascade_enabled false|true */
    public static final String EXTRA_AUTO_RESCAN_ALL = "auto_rescan_all";

    private static final int COL_APK_DP = 168;
    private static final int COL_VERDICT_DP = 132;
    private static final int COL_TIME_DP = 84;
    private static final int COL_MEM_DP = 96;

    private TextView txtStatus, txtLog, txtMetricsPath, txtEmptyResults;
    private TableLayout tableResults;
    private HorizontalScrollView scrollResults;
    private MaterialButton btnStartScan, btnRescanAll, btnStopScan, btnOpenMetrics, btnViewFullLog,
            btnClearScanHistory;
    private SwitchCompat switchCascadeMode;
    private boolean scanRunning;

    private static final String PREFS_SCAN_UI = "scan_ui_prefs";
    private static final String PREF_CASCADE_ENABLED = "cascade_enabled";
    private View contentMetrics, contentLog;
    private ImageView iconMetricsExpand, iconLogExpand;

    private boolean tableHeaderAdded;
    private int resultRowCount;
    private File metricsDir;

    private final BroadcastReceiver scanReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (ACTION_SCAN_RESULT.equals(intent.getAction())) {
                appendResultRow(intent);
                return;
            }
            if (ACTION_SCAN_LOG.equals(intent.getAction())) {
                String log = intent.getStringExtra("log");
                if (log != null) {
                    appendLog(log);
                }
                String status = intent.getStringExtra("status");
                if (status != null) {
                    if (status.startsWith(ScanService.EXTRA_PROGRESS + ":")) {
                        String[] parts = status.substring(ScanService.EXTRA_PROGRESS.length() + 1).split("/");
                        if (parts.length == 2) {
                            try {
                                int current = Integer.parseInt(parts[0]);
                                int total = Integer.parseInt(parts[1]);
                                txtStatus.setText(getString(R.string.scan_progress, current, total));
                                txtStatus.setTextColor(
                                        ContextCompat.getColor(MainActivity.this, R.color.text_primary));
                            } catch (NumberFormatException ignored) {
                            }
                        }
                    } else {
                        setStatus(status);
                    }
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bindViews();
        setupCollapsibles();
        setupMetricsPath();
        requestAllFileAccess();

        switchCascadeMode = findViewById(R.id.switchCascadeMode);
        switchCascadeMode.setShowText(false);
        btnClearScanHistory = findViewById(R.id.btnClearScanHistory);
        boolean cascadeDefault =
                getSharedPreferences(PREFS_SCAN_UI, MODE_PRIVATE).getBoolean(PREF_CASCADE_ENABLED, true);
        switchCascadeMode.setChecked(cascadeDefault);
        updateScanModeStatus();
        switchCascadeMode.setOnCheckedChangeListener((buttonView, isChecked) -> {
            getSharedPreferences(PREFS_SCAN_UI, MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREF_CASCADE_ENABLED, isChecked)
                    .apply();
            updateScanModeStatus();
        });
        MaterialButton btnModelHealth = findViewById(R.id.btnModelHealth);
        if (BuildConfig.DEBUG) {
            btnModelHealth.setVisibility(View.VISIBLE);
            btnModelHealth.setOnClickListener(
                    v -> startActivity(new Intent(this, ModelHealthActivity.class)));
        } else {
            btnModelHealth.setVisibility(View.GONE);
        }

        btnClearScanHistory.setOnClickListener(v -> {
            int count = ScanProcessedStore.count(this);
            ScanProcessedStore.clear(this);
            Toast.makeText(
                            this,
                            getString(R.string.clear_scan_history_done, count),
                            Toast.LENGTH_SHORT)
                    .show();
            appendLog("Cleared scan history (" + count + " digests)");
        });

        btnStartScan.setOnClickListener(v -> startScan(false));
        btnRescanAll.setOnClickListener(v -> startScan(true));
        btnStopScan.setOnClickListener(v -> {
            ScanService.requestCancel();
            appendLog("Stop requested");
        });

        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_SCAN_LOG);
        filter.addAction(ACTION_SCAN_RESULT);
        LocalBroadcastManager.getInstance(this).registerReceiver(scanReceiver, filter);
        handleAutoScanIntent(getIntent());
    }

  @Override
  protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);
    handleAutoScanIntent(intent);
  }

  private void handleAutoScanIntent(Intent intent) {
    if (intent == null || !intent.getBooleanExtra(EXTRA_AUTO_RESCAN_ALL, false)) {
      return;
    }
    if (intent.hasExtra(ScanService.EXTRA_CASCADE_ENABLED)) {
      boolean cascade = intent.getBooleanExtra(ScanService.EXTRA_CASCADE_ENABLED, true);
      switchCascadeMode.setChecked(cascade);
      getSharedPreferences(PREFS_SCAN_UI, MODE_PRIVATE)
          .edit()
          .putBoolean(PREF_CASCADE_ENABLED, cascade)
          .apply();
      updateScanModeStatus();
    }
    appendLog("Auto rescan triggered via adb intent");
    startScan(true);
  }

    private void bindViews() {
        txtStatus = findViewById(R.id.txtStatus);
        txtLog = findViewById(R.id.txtLog);
        txtMetricsPath = findViewById(R.id.txtMetricsPath);
        txtEmptyResults = findViewById(R.id.txtEmptyResults);
        tableResults = findViewById(R.id.tableResults);
        scrollResults = findViewById(R.id.scrollResults);
        btnStartScan = findViewById(R.id.btnStartScan);
        btnRescanAll = findViewById(R.id.btnRescanAll);
        btnStopScan = findViewById(R.id.btnStopScan);
        btnOpenMetrics = findViewById(R.id.btnOpenMetrics);
        btnViewFullLog = findViewById(R.id.btnViewFullLog);
        contentMetrics = findViewById(R.id.contentMetrics);
        contentLog = findViewById(R.id.contentLog);
        iconMetricsExpand = findViewById(R.id.iconMetricsExpand);
        iconLogExpand = findViewById(R.id.iconLogExpand);
    }

    private void setupCollapsibles() {
        findViewById(R.id.headerMetrics).setOnClickListener(v ->
                toggleSection(contentMetrics, iconMetricsExpand));
        findViewById(R.id.headerLog).setOnClickListener(v ->
                toggleSection(contentLog, iconLogExpand));

        btnOpenMetrics.setOnClickListener(v -> downloadMetrics());
        btnViewFullLog.setOnClickListener(v -> showFullLogDialog());
    }

    private void setupMetricsPath() {
        metricsDir = MetricsWriter.getMetricsDir(this);
        String pkg = getPackageName();
        txtMetricsPath.setText(
                metricsDir.getAbsolutePath()
                        + "\nAblation: "
                        + MetricsWriter.SCAN_A_JSONL_FILENAME
                        + "\nCascade: "
                        + MetricsWriter.SCAN_B_JSONL_FILENAME
                        + "\n\nDevice File Explorer:\n"
                        + "sdcard/Android/data/"
                        + pkg
                        + "/files/metrics/");
    }

    private void startScan(boolean rescanAll) {
        tableResults.removeAllViews();
        tableHeaderAdded = false;
        resultRowCount = 0;
        txtEmptyResults.setVisibility(View.VISIBLE);
        scrollResults.setVisibility(View.GONE);
        txtLog.setText("");
        appendLog(rescanAll ? "Rescan all requested" : "Incremental scan requested");
        setScanRunning(true);

        Intent i = new Intent(MainActivity.this, ScanService.class);
        i.putExtra("manual_trigger", true);
        i.putExtra(ScanService.EXTRA_RESCAN_ALL, rescanAll);
        i.putExtra(ScanService.EXTRA_SESSION_ID, UUID.randomUUID().toString());
        i.putExtra(ScanService.EXTRA_CASCADE_ENABLED, switchCascadeMode.isChecked());
        ScanService.enqueueWork(MainActivity.this, i);
    }

    private void updateScanModeStatus() {
        if (switchCascadeMode == null || txtStatus == null || scanRunning) {
            return;
        }
        String mode =
                switchCascadeMode.isChecked()
                        ? getString(R.string.scan_mode_cascade)
                        : getString(R.string.scan_mode_ablation);
        txtStatus.setText(getString(R.string.status_scan_mode, mode));
        txtStatus.setTextColor(ContextCompat.getColor(this, R.color.text_secondary));
    }

    private void setScanRunning(boolean running) {
        scanRunning = running;
        btnStartScan.setEnabled(!running);
        btnRescanAll.setEnabled(!running);
        btnStopScan.setVisibility(running ? View.VISIBLE : View.GONE);
        if (running) {
            setStatus(getString(R.string.status_scanning));
        }
    }

    private void toggleSection(View content, ImageView icon) {
        boolean show = content.getVisibility() != View.VISIBLE;
        content.setVisibility(show ? View.VISIBLE : View.GONE);
        icon.setImageResource(show ? R.drawable.ic_expand_less : R.drawable.ic_expand_more);
    }

    private void setStatus(String status) {
        if ("Idle".equalsIgnoreCase(status) || "Running".equalsIgnoreCase(status)) {
            txtStatus.setText(getString(R.string.status_idle));
        } else if (status.toLowerCase(Locale.US).contains("scan")
                || "Parsing".equalsIgnoreCase(status)) {
            txtStatus.setText(getString(R.string.status_scanning));
        } else if ("Error".equalsIgnoreCase(status)) {
            txtStatus.setText(status);
            txtStatus.setTextColor(ContextCompat.getColor(this, R.color.verdict_malware));
        } else {
            txtStatus.setText(status);
            txtStatus.setTextColor(ContextCompat.getColor(this, R.color.text_primary));
        }
        if (!"Error".equalsIgnoreCase(status)) {
            txtStatus.setTextColor(ContextCompat.getColor(this, R.color.text_primary));
        }
    }

    private void appendLog(String line) {
        CharSequence current = txtLog.getText();
        if (getString(R.string.log_empty).contentEquals(current)) {
            txtLog.setText(line + "\n");
        } else {
            txtLog.append(line + "\n");
        }
    }

    private void downloadMetrics() {
        if (metricsDir == null) {
            Toast.makeText(this, R.string.metrics_missing, Toast.LENGTH_SHORT).show();
            return;
        }
        File source = new File(metricsDir, MetricsWriter.AGGREGATE_FILENAME);
        if (!source.exists()) {
            Toast.makeText(this, R.string.metrics_missing, Toast.LENGTH_SHORT).show();
            return;
        }

        File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File target = new File(downloads, MetricsWriter.AGGREGATE_FILENAME);
        try (FileInputStream fis = new FileInputStream(source);
             FileOutputStream fos = new FileOutputStream(target)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = fis.read(buf)) != -1) {
                fos.write(buf, 0, read);
            }
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText("metrics_path", target.getAbsolutePath()));
            }
            Toast.makeText(this, getString(R.string.metrics_downloaded, target.getAbsolutePath()), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.metrics_download_failed, e.getMessage()), Toast.LENGTH_LONG).show();
        }
        toggleSection(contentMetrics, iconMetricsExpand);
    }

    private void showFullLogDialog() {
        TextView body = new TextView(this);
        body.setText(txtLog.getText());
        body.setPadding(dp(16), dp(12), dp(16), dp(12));
        body.setTextIsSelectable(true);
        body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        body.setTypeface(Typeface.MONOSPACE);
        body.setTextColor(ContextCompat.getColor(this, R.color.text_secondary));

        new AlertDialog.Builder(this)
                .setTitle(R.string.system_log_title)
                .setView(body)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    private void ensureTableHeader() {
        if (tableHeaderAdded) {
            return;
        }
        String[] headers = {
                getString(R.string.col_apk),
                getString(R.string.col_verdict),
                getString(R.string.col_time),
                getString(R.string.col_memory)
        };
        int[] widths = {COL_APK_DP, COL_VERDICT_DP, COL_TIME_DP, COL_MEM_DP};
        String timeHint = getString(R.string.col_time_hint);

        TableRow row = new TableRow(this);
        row.setBackgroundColor(ContextCompat.getColor(this, R.color.table_header_bg));
        for (int i = 0; i < headers.length; i++) {
            TextView header = headerCell(headers[i], widths[i]);
            if (i == 2) {
                header.setContentDescription(timeHint);
            }
            row.addView(header);
        }
        tableResults.addView(row);
        tableHeaderAdded = true;
    }

    private void appendResultRow(Intent intent) {
        ensureTableHeader();
        txtEmptyResults.setVisibility(View.GONE);
        scrollResults.setVisibility(View.VISIBLE);

        String apkName = intent.getStringExtra("apk_name");
        float ensemble = intent.getFloatExtra("ensemble_score", -1f);
        String decision = intent.getStringExtra("ensemble_decision");
        double totalMs = intent.getDoubleExtra("total_ms", 0);
        double totalMemMb = intent.getDoubleExtra("total_mem_mb", 0);
        String metricsFile = intent.getStringExtra("metrics_file");

        TableRow row = new TableRow(this);
        int bg = (resultRowCount % 2 == 0)
                ? R.color.table_row_odd
                : R.color.table_row_even;
        row.setBackgroundColor(ContextCompat.getColor(this, bg));
        resultRowCount++;

        row.addView(apkCell(apkName != null ? apkName : "?", COL_APK_DP));
        row.addView(verdictBadgeCell(decision, ensemble, COL_VERDICT_DP));
        row.addView(dataCell(String.format(Locale.US, "%.0f ms", totalMs), COL_TIME_DP, Gravity.END));
        row.addView(dataCell(String.format(Locale.US, "%.2f MB", totalMemMb), COL_MEM_DP, Gravity.END));

        ImageView chevron = new ImageView(this);
        chevron.setImageResource(R.drawable.ic_expand_more);
        chevron.setContentDescription(getString(R.string.scan_detail_title));
        TableRow.LayoutParams chevronLp =
                new TableRow.LayoutParams(dp(28), ViewGroup.LayoutParams.WRAP_CONTENT);
        chevronLp.gravity = Gravity.CENTER_VERTICAL;
        chevron.setLayoutParams(chevronLp);
        row.addView(chevron);

        String detailJson = intent.getStringExtra("scan_detail_json");
        row.setClickable(true);
        row.setFocusable(true);
        row.setOnClickListener(v -> showScanDetailDialog(apkName, detailJson));

        tableResults.addView(row);

        if (metricsFile != null) {
            appendLog("Saved: " + metricsFile);
        }
        setScanRunning(false);
        setStatus(getString(R.string.status_idle));
    }

    private void showScanDetailDialog(String apkName, String detailJson) {
        TextView body = new TextView(this);
        body.setPadding(dp(16), dp(12), dp(16), dp(12));
        body.setTextIsSelectable(true);
        body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f);
        body.setTypeface(Typeface.MONOSPACE);
        body.setTextColor(ContextCompat.getColor(this, R.color.text_secondary));
        body.setText(ScanDetailFormatter.format(detailJson));

        new AlertDialog.Builder(this)
                .setTitle(getString(R.string.scan_detail_title) + ": " + apkName)
                .setView(body)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    private TextView headerCell(String text, int widthDp) {
        TextView tv = dataCell(text, widthDp, Gravity.CENTER);
        tv.setTypeface(null, Typeface.BOLD);
        tv.setTextColor(ContextCompat.getColor(this, R.color.text_primary));
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f);
        return tv;
    }

    private TextView apkCell(String apkName, int widthDp) {
        TextView tv = dataCell(apkName, widthDp, Gravity.START | Gravity.CENTER_VERTICAL);
        tv.setSingleLine(true);
        tv.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
        tv.setTextColor(ContextCompat.getColor(this, R.color.text_primary));
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f);
        return tv;
    }

    private TextView dataCell(String text, int widthDp, int gravity) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setGravity(gravity);
        tv.setPadding(dp(10), dp(12), dp(10), dp(12));
        TableRow.LayoutParams lp = new TableRow.LayoutParams(dp(widthDp), ViewGroup.LayoutParams.WRAP_CONTENT);
        tv.setLayoutParams(lp);
        return tv;
    }

    private LinearLayout verdictBadgeCell(String decision, float ensemble, int widthDp) {
        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.HORIZONTAL);
        wrap.setGravity(Gravity.CENTER);
        wrap.setPadding(dp(6), dp(8), dp(6), dp(8));
        TableRow.LayoutParams lp = new TableRow.LayoutParams(dp(widthDp), ViewGroup.LayoutParams.WRAP_CONTENT);
        wrap.setLayoutParams(lp);

        if (decision == null || ensemble < 0f) {
            TextView dash = new TextView(this);
            dash.setText("—");
            dash.setGravity(Gravity.CENTER);
            wrap.addView(dash);
            return wrap;
        }

        int bgRes;
        int textColorRes;
        int iconRes;
        String label;

        switch (decision) {
            case "malware":
                bgRes = R.drawable.bg_badge_malware;
                textColorRes = R.color.verdict_malware;
                iconRes = R.drawable.ic_verdict_malware;
                label = getString(R.string.verdict_malware);
                break;
            case "uncertain":
                bgRes = R.drawable.bg_badge_uncertain;
                textColorRes = R.color.verdict_uncertain;
                iconRes = R.drawable.ic_verdict_uncertain;
                label = getString(R.string.verdict_uncertain);
                break;
            default:
                bgRes = R.drawable.bg_badge_benign;
                textColorRes = R.color.verdict_benign;
                iconRes = R.drawable.ic_verdict_benign;
                label = getString(R.string.verdict_benign);
                break;
        }

        LinearLayout badge = new LinearLayout(this);
        badge.setOrientation(LinearLayout.HORIZONTAL);
        badge.setGravity(Gravity.CENTER_VERTICAL);
        badge.setBackgroundResource(bgRes);
        badge.setPadding(dp(10), dp(6), dp(12), dp(6));

        ImageView icon = new ImageView(this);
        icon.setImageResource(iconRes);
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(16), dp(16));
        iconLp.setMarginEnd(dp(6));
        icon.setLayoutParams(iconLp);
        badge.addView(icon);

        TextView tv = new TextView(this);
        tv.setText(label);
        tv.setTextColor(ContextCompat.getColor(this, textColorRes));
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        tv.setTypeface(null, Typeface.BOLD);
        badge.addView(tv);

        wrap.addView(badge);
        if ("uncertain".equals(decision)) {
            TextView hint = new TextView(this);
            hint.setText(getString(R.string.verdict_uncertain_hint));
            hint.setTextColor(ContextCompat.getColor(this, R.color.text_secondary));
            hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f);
            hint.setPadding(dp(4), 0, 0, 0);
            wrap.addView(hint);
        }
        return wrap;
    }

    private int dp(int value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }

    @Override
    protected void onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(scanReceiver);
        super.onDestroy();
    }

    private void requestAllFileAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            }
        }
    }
}
