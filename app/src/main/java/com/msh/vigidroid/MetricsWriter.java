package com.msh.vigidroid;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Append-only scan logs: one JSON object per line, split by scan mode.
 * Ablation (all models) → {@link #SCAN_A_JSONL_FILENAME}; cascade → {@link #SCAN_B_JSONL_FILENAME}.
 * Merge to legacy JSON on PC via {@code jsonl_to_json.py}.
 */
public final class MetricsWriter {

    private static final String TAG = "MetricsWriter";
    public static final String METRICS_SUBDIR = "metrics";
    /** Scan A — ablation, all models on every APK ({@code cascade_enabled=false}). */
    public static final String SCAN_A_JSONL_FILENAME = "scan_a_all_models.jsonl";
    /** Scan B — deployed cascade ({@code cascade_enabled=true}). */
    public static final String SCAN_B_JSONL_FILENAME = "scan_b_cascade.jsonl";
    /** Legacy PC merge target for Scan A pulls. */
    public static final String SCAN_A_LEGACY_AGGREGATE_FILENAME = "scan_a_all_models.json";
    /** Legacy PC merge target for Scan B pulls. */
    public static final String SCAN_B_LEGACY_AGGREGATE_FILENAME = "scan_b_cascade.json";
    /**
     * @deprecated Pre-split builds used one combined log; kept for migration reads on PC only.
     */
    @Deprecated public static final String JSONL_FILENAME = "all_scan_metrics.jsonl";
    /** @deprecated Use mode-specific legacy filenames. */
    @Deprecated public static final String LEGACY_AGGREGATE_FILENAME = "all_scan_metrics.json";
    /** @deprecated Use {@link #SCAN_A_JSONL_FILENAME} or {@link #SCAN_B_JSONL_FILENAME}. */
    @Deprecated public static final String AGGREGATE_FILENAME = JSONL_FILENAME;

    public static final String STATUS_OK = "ok";
    public static final String STATUS_SKIPPED = "skipped";
    public static final String STATUS_ERROR = "error";

    public static final String RECORD_TYPE_SCAN = "scan";
    public static final String RECORD_TYPE_SESSION = "session";

    private MetricsWriter() {}

    public static File getMetricsDir(Context context) {
        File base = context.getExternalFilesDir(null);
        if (base == null) {
            base = context.getFilesDir();
        }
        File dir = new File(base, METRICS_SUBDIR);
        if (!dir.exists() && !dir.mkdirs()) {
            Log.w(TAG, "Could not create metrics dir: " + dir.getAbsolutePath());
        }
        return dir;
    }

    /** First 8 hex chars of a full lowercase SHA-256 digest. */
    public static String shortSha256Prefix(String fullSha256) {
        if (fullSha256 == null || fullSha256.length() < 8) {
            return "00000000";
        }
        return fullSha256.substring(0, 8).toLowerCase(Locale.US);
    }

    public static final class StageMetrics {
        public final String domain;
        public final String modelId;
        public final String status;
        public final String errorMessage;
        public final double parseMs;
        public final double vectorizeMs;
        public final double inferenceMs;
        public final double cpuMs;
        public final float score;
        public final long memDeltaBytes;
        public final boolean cascade;
        public final String mode;
        public final double dexMs;
        public final float stage1Score;
        public final float stage2Score;
        public final boolean earlyExit;

        public StageMetrics(String domain, double parseMs, double vectorizeMs,
                            double inferenceMs, float score, long memDeltaBytes) {
            this(domain, null, parseMs, vectorizeMs, inferenceMs, 0.0, STATUS_OK, null, score, memDeltaBytes);
        }

        public StageMetrics(String domain, String modelId, double parseMs, double vectorizeMs,
                            double inferenceMs, float score, long memDeltaBytes) {
            this(domain, modelId, parseMs, vectorizeMs, inferenceMs, 0.0, STATUS_OK, null, score, memDeltaBytes);
        }

        public StageMetrics(String domain, String modelId, double parseMs, double vectorizeMs,
                            double inferenceMs, double cpuMs, String status, String errorMessage,
                            float score, long memDeltaBytes) {
            this.domain = domain;
            this.modelId = modelId;
            this.status = status != null ? status : STATUS_OK;
            this.errorMessage = errorMessage;
            this.parseMs = parseMs;
            this.vectorizeMs = vectorizeMs;
            this.inferenceMs = inferenceMs;
            this.cpuMs = cpuMs;
            this.score = score;
            this.memDeltaBytes = memDeltaBytes;
            this.cascade = false;
            this.mode = null;
            this.dexMs = 0.0;
            this.stage1Score = -1f;
            this.stage2Score = -1f;
            this.earlyExit = false;
        }

        public static StageMetrics cascade(
                String domain,
                String modelId,
                String mode,
                double parseMs,
                double dexMs,
                double vectorizeMs,
                double inferenceMs,
                double cpuMs,
                float stage1Score,
                float stage2Score,
                boolean earlyExit,
                String status,
                String errorMessage,
                float score,
                long memDeltaBytes) {
            StageMetrics metrics =
                    new StageMetrics(
                            domain,
                            modelId,
                            parseMs,
                            vectorizeMs,
                            inferenceMs,
                            cpuMs,
                            status,
                            errorMessage,
                            score,
                            memDeltaBytes);
            return metrics.withCascade(mode, dexMs, stage1Score, stage2Score, earlyExit);
        }

        private StageMetrics withCascade(
                String mode,
                double dexMs,
                float stage1Score,
                float stage2Score,
                boolean earlyExit) {
            return new StageMetrics(
                    domain,
                    modelId,
                    status,
                    errorMessage,
                    parseMs,
                    vectorizeMs,
                    inferenceMs,
                    cpuMs,
                    score,
                    memDeltaBytes,
                    true,
                    mode,
                    dexMs,
                    stage1Score,
                    stage2Score,
                    earlyExit);
        }

        private StageMetrics(
                String domain,
                String modelId,
                String status,
                String errorMessage,
                double parseMs,
                double vectorizeMs,
                double inferenceMs,
                double cpuMs,
                float score,
                long memDeltaBytes,
                boolean cascade,
                String mode,
                double dexMs,
                float stage1Score,
                float stage2Score,
                boolean earlyExit) {
            this.domain = domain;
            this.modelId = modelId;
            this.status = status;
            this.errorMessage = errorMessage;
            this.parseMs = parseMs;
            this.vectorizeMs = vectorizeMs;
            this.inferenceMs = inferenceMs;
            this.cpuMs = cpuMs;
            this.score = score;
            this.memDeltaBytes = memDeltaBytes;
            this.cascade = cascade;
            this.mode = mode;
            this.dexMs = dexMs;
            this.stage1Score = stage1Score;
            this.stage2Score = stage2Score;
            this.earlyExit = earlyExit;
        }
    }

    public static final class SessionMetrics {
        public String sessionId;
        public String trigger = "download";
        public long startedMs;
        public long endedMs;
        public double wallMsTotal;
        public int apkCount;
        public int apkScanned;
        public int apkFailed;
        public int apkSkippedDedup;
        public boolean cascadeEnabled;
        public org.json.JSONObject provenance;
        public BatterySampler.Snapshot batteryStart;
        public BatterySampler.Snapshot batteryEnd;
    }

    public static final class ScanMetrics {
        public String scanId = UUID.randomUUID().toString();
        public String sessionId;
        public long timestampMs = System.currentTimeMillis();
        public String trigger = "download";
        public String groundTruth;
        public boolean dedupSkipped;
        public String apkName;
        public String apkPath;
        public long apkSizeBytes;
        public String apkSha256;
        public final List<StageMetrics> stages = new ArrayList<>();
        public double wallMs;
        public double cpuMs;
        public long memDeltaBytes;
        public long javaHeapUsedBytes;
        public int peakTotalPssKb;
        public int totalDexFilesFound;
        public long structuralParsingTimeMs;
        public double sharedParseMs;
        public Float ensembleScore;
        public String ensembleDecision;
        public String ensemblePolicy;

        public String cascadePolicy;
        public Integer cascadeExitTier;
        public String cascadeExitReason;
        public Float cascadeFinalScore;
        public String cascadeDecision;
        public List<String> cascadeModelsRun;
        public List<String> cascadeModelsSkipped;

        /** Denormalized from session for Scan A/B filtering without JSONL join. */
        public boolean cascadeEnabled;
        /** Per-APK capacity % change (sampled at scan start/end). */
        public Double batteryPctDelta;
    }

    public static Double capacityPctDelta(
            BatterySampler.Snapshot start, BatterySampler.Snapshot end) {
        if (start == null || end == null) {
            return null;
        }
        if (start.capacityPct == Integer.MIN_VALUE || end.capacityPct == Integer.MIN_VALUE) {
            return null;
        }
        return (double) (end.capacityPct - start.capacityPct);
    }

    static double stageTotalMs(StageMetrics stage) {
        return stage.parseMs + stage.vectorizeMs + stage.inferenceMs;
    }

    static double sumOkStageMs(List<StageMetrics> stages) {
        double total = 0.0;
        for (StageMetrics stage : stages) {
            if (STATUS_OK.equals(stage.status)) {
                total += stageTotalMs(stage);
            }
        }
        return total;
    }

    static Double stageBatteryShare(double scanBatteryPct, StageMetrics stage, double okStageMsTotal) {
        if (!STATUS_OK.equals(stage.status) || okStageMsTotal <= 0.0) {
            return null;
        }
        return scanBatteryPct * (stageTotalMs(stage) / okStageMsTotal);
    }

    public static JSONObject buildScanObject(ScanMetrics scan) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("record_type", RECORD_TYPE_SCAN);
        obj.put("scan_id", scan.scanId);
        obj.put("timestamp_ms", scan.timestampMs);
        if (scan.sessionId != null && !scan.sessionId.isEmpty()) {
            obj.put("session_id", scan.sessionId);
        }

        JSONObject device = new JSONObject();
        device.put("model", Build.MODEL != null ? Build.MODEL : "unknown");
        device.put("manufacturer", Build.MANUFACTURER != null ? Build.MANUFACTURER : "unknown");
        device.put("api", Build.VERSION.SDK_INT);
        obj.put("device", device);

        JSONObject apk = new JSONObject();
        apk.put("name", scan.apkName);
        if (scan.apkPath != null) {
            apk.put("path", scan.apkPath);
        }
        apk.put("size_bytes", scan.apkSizeBytes);
        if (scan.apkSha256 != null && !scan.apkSha256.isEmpty()) {
            apk.put("sha256", scan.apkSha256);
            apk.put("sha256_short", shortSha256Prefix(scan.apkSha256));
        }
        obj.put("apk", apk);

        obj.put("trigger", scan.trigger);
        if (scan.groundTruth != null && !scan.groundTruth.isEmpty()) {
            obj.put("ground_truth", scan.groundTruth);
        }
        if (scan.dedupSkipped) {
            obj.put("dedup_skipped", true);
        }
        obj.put("cascade_enabled", scan.cascadeEnabled);

        Double scanBattery = scan.batteryPctDelta;
        double okStageMsTotal = scanBattery != null ? sumOkStageMs(scan.stages) : 0.0;

        JSONArray stages = new JSONArray();
        for (StageMetrics s : scan.stages) {
            JSONObject stage = new JSONObject();
            stage.put("domain", s.domain);
            if (s.modelId != null && !s.modelId.isEmpty()) {
                stage.put("model_id", s.modelId);
            }
            stage.put("status", s.status);
            if (s.errorMessage != null && !s.errorMessage.isEmpty()) {
                stage.put("error_message", s.errorMessage);
            }
            stage.put("parse_ms", s.parseMs);
            stage.put("vectorize_ms", s.vectorizeMs);
            stage.put("inference_ms", s.inferenceMs);
            stage.put("cpu_ms", s.cpuMs);
            if (STATUS_OK.equals(s.status) && s.score >= 0f) {
                stage.put("score", s.score);
            } else if (s.score >= 0f) {
                stage.put("score", s.score);
            }
            stage.put("mem_delta_bytes", s.memDeltaBytes);
            if (scanBattery != null) {
                Double stageBattery = stageBatteryShare(scanBattery, s, okStageMsTotal);
                if (stageBattery != null) {
                    stage.put("battery_pct_delta", stageBattery);
                } else {
                    stage.put("battery_pct_delta", 0.0);
                }
            }
            if (s.cascade) {
                stage.put("mode", s.mode);
                stage.put("dex_ms", s.dexMs);
                if (s.stage1Score >= 0f) {
                    stage.put("stage1_score", s.stage1Score);
                }
                if (s.stage2Score >= 0f) {
                    stage.put("stage2_score", s.stage2Score);
                }
                stage.put("early_exit", s.earlyExit);
            }
            stages.put(stage);
        }
        obj.put("stages", stages);

        if (scan.ensembleScore != null) {
            JSONObject ensemble = new JSONObject();
            ensemble.put("score", scan.ensembleScore);
            ensemble.put("decision", scan.ensembleDecision != null ? scan.ensembleDecision : "uncertain");
            ensemble.put("policy", scan.ensemblePolicy);
            obj.put("ensemble", ensemble);
        }

        if (scan.cascadePolicy != null) {
            JSONObject cascade = new JSONObject();
            cascade.put("policy", scan.cascadePolicy);
            if (scan.cascadeExitTier != null) {
                cascade.put("exit_tier", scan.cascadeExitTier);
            }
            if (scan.cascadeExitReason != null) {
                cascade.put("exit_reason", scan.cascadeExitReason);
            }
            if (scan.cascadeFinalScore != null) {
                cascade.put("final_score", scan.cascadeFinalScore);
            }
            if (scan.cascadeDecision != null) {
                cascade.put("decision", scan.cascadeDecision);
            }
            if (scan.cascadeModelsRun != null) {
                cascade.put("models_run", new JSONArray(scan.cascadeModelsRun));
            }
            if (scan.cascadeModelsSkipped != null) {
                cascade.put("models_skipped", new JSONArray(scan.cascadeModelsSkipped));
            }
            obj.put("cascade", cascade);
        }

        JSONObject totals = new JSONObject();
        totals.put("wall_ms", scan.wallMs);
        totals.put("cpu_ms", scan.cpuMs);
        totals.put("mem_delta_bytes", scan.memDeltaBytes);
        totals.put("java_heap_used_bytes", scan.javaHeapUsedBytes);
        totals.put("peak_total_pss_kb", scan.peakTotalPssKb);
        totals.put("total_dex_files_found", scan.totalDexFilesFound);
        totals.put("structural_parsing_time_ms", scan.structuralParsingTimeMs);
        if (scan.sharedParseMs > 0.0) {
            totals.put("shared_parse_ms", scan.sharedParseMs);
        }
        if (scanBattery != null) {
            totals.put("battery_pct_delta", scanBattery);
        } else {
            totals.put("battery_pct_delta", JSONObject.NULL);
        }
        obj.put("totals", totals);
        return obj;
    }

    public static JSONObject buildSessionObject(SessionMetrics session) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("record_type", RECORD_TYPE_SESSION);
        obj.put("session_id", session.sessionId);
        obj.put("trigger", session.trigger);
        obj.put("started_ms", session.startedMs);
        obj.put("ended_ms", session.endedMs);
        obj.put("wall_ms_total", session.wallMsTotal);
        obj.put("apk_count", session.apkCount);
        obj.put("apk_scanned", session.apkScanned);
        obj.put("apk_failed", session.apkFailed);
        obj.put("apk_skipped_dedup", session.apkSkippedDedup);
        obj.put("cascade_enabled", session.cascadeEnabled);
        if (session.provenance != null) {
            obj.put("provenance", session.provenance);
        }

        JSONObject device = new JSONObject();
        device.put("model", Build.MODEL != null ? Build.MODEL : "unknown");
        device.put("manufacturer", Build.MANUFACTURER != null ? Build.MANUFACTURER : "unknown");
        device.put("api", Build.VERSION.SDK_INT);
        obj.put("device", device);

        obj.put("battery", buildBatteryObject(session.batteryStart, session.batteryEnd));
        return obj;
    }

    private static JSONObject buildBatteryObject(
            BatterySampler.Snapshot start, BatterySampler.Snapshot end) throws Exception {
        JSONObject battery = new JSONObject();
        putBatteryInt(battery, "capacity_pct_start", start.capacityPct);
        putBatteryInt(battery, "capacity_pct_end", end.capacityPct);
        putBatteryDelta(battery, "capacity_pct_delta", start.capacityPct, end.capacityPct);

        putBatteryInt(battery, "charge_counter_uah_start", start.chargeCounterUah);
        putBatteryInt(battery, "charge_counter_uah_end", end.chargeCounterUah);
        putBatteryConsumed(
                battery, "charge_counter_uah_used", start.chargeCounterUah, end.chargeCounterUah);

        putBatteryInt(battery, "current_now_ua_start", start.currentNowUa);
        putBatteryInt(battery, "current_now_ua_end", end.currentNowUa);

        putBatteryInt(battery, "temperature_deci_c_start", start.temperatureDeciC);
        putBatteryInt(battery, "temperature_deci_c_end", end.temperatureDeciC);
        putBatteryDelta(
                battery, "temperature_deci_c_delta", start.temperatureDeciC, end.temperatureDeciC);
        return battery;
    }

    private static void putBatteryInt(JSONObject obj, String key, int value) throws Exception {
        if (value == Integer.MIN_VALUE) {
            obj.put(key, JSONObject.NULL);
        } else {
            obj.put(key, value);
        }
    }

    private static void putBatteryDelta(JSONObject obj, String key, int start, int end) throws Exception {
        if (start == Integer.MIN_VALUE || end == Integer.MIN_VALUE) {
            obj.put(key, JSONObject.NULL);
        } else {
            obj.put(key, end - start);
        }
    }

    /** Positive when remaining charge (µAh) decreased between start and end. */
    private static void putBatteryConsumed(JSONObject obj, String key, int start, int end)
            throws Exception {
        if (start == Integer.MIN_VALUE || end == Integer.MIN_VALUE) {
            obj.put(key, JSONObject.NULL);
        } else {
            obj.put(key, start - end);
        }
    }

    public static String jsonlFilename(boolean cascadeEnabled) {
        return cascadeEnabled ? SCAN_B_JSONL_FILENAME : SCAN_A_JSONL_FILENAME;
    }

    public static String legacyAggregateFilename(boolean cascadeEnabled) {
        return cascadeEnabled ? SCAN_B_LEGACY_AGGREGATE_FILENAME : SCAN_A_LEGACY_AGGREGATE_FILENAME;
    }

    public static File appendJsonLine(Context context, JSONObject line, boolean cascadeEnabled)
            throws Exception {
        File dir = getMetricsDir(context);
        File out = new File(dir, jsonlFilename(cascadeEnabled));
        try (FileOutputStream fos = new FileOutputStream(out, true);
             OutputStreamWriter w = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
            w.write(line.toString());
            w.write('\n');
        }
        return out;
    }

    public static File writeSession(Context context, SessionMetrics session) throws Exception {
        File out = appendJsonLine(context, buildSessionObject(session), session.cascadeEnabled);
        Log.i(TAG, "Appended session to: " + out.getAbsolutePath());
        return out;
    }

    public static File writeScan(Context context, ScanMetrics scan) throws Exception {
        File out = appendJsonLine(context, buildScanObject(scan), scan.cascadeEnabled);
        Log.i(TAG, "Appended scan to: " + out.getAbsolutePath());
        return out;
    }
}
