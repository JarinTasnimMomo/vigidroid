package com.msh.vigidroid;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Environment;
import android.os.SystemClock;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.core.app.JobIntentService;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.msh.vigidroid.pipeline.LegacyScanRunner;
import com.msh.vigidroid.pipeline.ModelPipeline;
import com.msh.vigidroid.pipeline.ScanApkResult;
import com.msh.vigidroid.pipeline.StageResult;
import com.msh.vigidroid.pipeline.ScanMetricsAssembler;
import com.msh.vigidroid.pipeline.ScanOrchestrator;
import com.msh.vigidroid.pipeline.ScanPipelineDependencies;
import com.msh.vigidroid.pipeline.ScanResultDetailBuilder;
import com.msh.vigidroid.pipeline.StageRunner;
import com.msh.vigidroid.pipeline.legacy.LegacyModelPipelines;

import org.json.JSONArray;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtSession;

public class ScanService extends JobIntentService {

    private static final int JOB_ID = 2001;
    private static final String TAG = "ScanService";

    public static final String EXTRA_SESSION_ID = "session_id";
    public static final String EXTRA_RESCAN_ALL = "rescan_all";
    public static final String EXTRA_APK_PATH = "apk_path";
    public static final String EXTRA_ENABLED_MODELS = "enabled_models";
    public static final String EXTRA_CASCADE_ENABLED = "cascade_enabled";
    /** Optional extra Download subfolders to scan (e.g. {@code Scanable}). */
    public static final String EXTRA_SCAN_SUBDIRS = "scan_subdirs";
    public static final String EXTRA_PROGRESS = "PROGRESS";

    /** Thesis device-eval APK folder under {@code Download/}. */
    static final String DEFAULT_SCAN_SUBDIR = "Scanable";

    private static volatile boolean cancelRequested;

    public static void requestCancel() {
        cancelRequested = true;
    }

    public static void clearCancel() {
        cancelRequested = false;
    }

    private OrtEnvironment ortEnvironment;
    private OrtSession ortSession;
    private OrtSession ortSessionCnn;
    private MlpHeaderOnnxRunner mlpHeaderRunner;
    private DexHeaderFeatureExtractor mlpHeaderExtractor;
    private PatternAOnnxRunner patternARunner;
    private DexHeaderFeatureExtractor patternAHeaderExtractor;
    private ManifestBowExtractor patternABowExtractor;
    private PatternBOnnxRunner patternBRunner;
    private DexHeaderFeatureExtractor patternBHeaderExtractor;
    private ManifestBowExtractor patternBBowExtractor;
    private LinRegDroidOnnxRunner linRegRunner;
    private LinRegPermissionExtractor linRegExtractor;
    private MldpPrunedOnnxRunner mldpRunner;
    private MldpPrunedPermissionExtractor mldpExtractor;
    private BroadcastMldpHybridOnnxRunner broadcastMldpRunner;
    private BroadcastMldpHybridExtractor broadcastMldpExtractor;
    private MldpDexHeaderExtractor mldpDexHeaderExtractor;
    private MldpDexHeaderModeAOnnxRunner mldpDexHeaderModeARunner;
    private MldpDexHeaderModeBOnnxRunner mldpDexHeaderModeBRunner;
    private DexheaderBroadcastFusionOnnxRunner dexheaderBroadcastFusionRunner;
    private DexheaderBroadcastFusionExtractor dexheaderBroadcastFusionExtractor;

    private final List<String> featureColumns = new ArrayList<>();
    private final Map<String, Integer> featureIndex = new HashMap<>();

    private ScanPipelineDependencies pipelineDependencies;
    private CascadePolicy cascadePolicy;
    private LegacyScanRunner legacyScanRunner;
    private ScanOrchestrator cascadeScanRunner;
    private List<ModelPipeline> legacyPipelines = List.of();

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, ScanService.class, JOB_ID, intent);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            loadFeatureColumns();
        } catch (Exception e) {
            Log.w(TAG, "XGBoost feature list not loaded (CNN-only mode OK)", e);
            sendLog("XGBoost features skipped: " + e.getMessage(), null);
        }
        try {
            initOnnxModel();
        } catch (Exception e) {
            Log.e(TAG, "ONNX init error", e);
            sendLog("ONNX init error: " + e.getMessage(), "Error");
        }
        try {
            initMlpHeaderPipeline();
        } catch (Exception e) {
            Log.w(TAG, "BM1 mlp_header pipeline not loaded", e);
            sendLog("BM1 mlp_header skipped: " + e.getMessage(), null);
        }
        try {
            initPatternAPipeline();
        } catch (Exception e) {
            Log.w(TAG, "Early-fusion Dex+manifest pipeline not loaded", e);
            sendLog("Early-fusion Dex+manifest skipped: " + e.getMessage(), null);
        }
        try {
            initPatternBPipeline();
        } catch (Exception e) {
            Log.w(TAG, "Dual-branch Dex+manifest pipeline not loaded", e);
            sendLog("Dual-branch Dex+manifest skipped: " + e.getMessage(), null);
        }
        try {
            initLinRegPermissionPipeline();
        } catch (Exception e) {
            Log.w(TAG, "LinRegDroid permission pipeline not loaded", e);
            sendLog("LinRegDroid permission skipped: " + e.getMessage(), null);
        }
        try {
            initMldpPrunedPermissionPipeline();
        } catch (Exception e) {
            Log.w(TAG, "MLDP pruned permission pipeline not loaded", e);
            sendLog("MLDP pruned permission skipped: " + e.getMessage(), null);
        }
        try {
            initBroadcastMldpHybridPipeline();
        } catch (Exception e) {
            Log.w(TAG, "Broadcast + MLDP hybrid pipeline not loaded", e);
            sendLog("Broadcast + MLDP hybrid skipped: " + e.getMessage(), null);
        }
        try {
            initMldpDexHeaderCascadePipeline();
        } catch (Exception e) {
            Log.w(TAG, "MLDP + Dex header cascade pipeline not loaded", e);
            sendLog("MLDP + Dex cascade skipped: " + e.getMessage(), null);
        }
        try {
            initDexheaderBroadcastFusionPipeline();
        } catch (Exception e) {
            Log.w(TAG, "Dex+Broadcast fusion pipeline not loaded", e);
            sendLog("Dex+Broadcast fusion skipped: " + e.getMessage(), null);
        }

        pipelineDependencies =
                new ScanPipelineDependencies(
                        ortEnvironment,
                        ortSession,
                        ortSessionCnn,
                        featureIndex,
                        mlpHeaderRunner,
                        mlpHeaderExtractor,
                        patternARunner,
                        patternAHeaderExtractor,
                        patternABowExtractor,
                        patternBRunner,
                        patternBHeaderExtractor,
                        patternBBowExtractor,
                        linRegRunner,
                        linRegExtractor,
                        mldpRunner,
                        mldpExtractor,
                        broadcastMldpRunner,
                        broadcastMldpExtractor,
                        mldpDexHeaderExtractor,
                        mldpDexHeaderModeARunner,
                        mldpDexHeaderModeBRunner,
                        dexheaderBroadcastFusionRunner,
                        dexheaderBroadcastFusionExtractor);
        try {
            cascadePolicy = CascadePolicy.load(this);
        } catch (Exception e) {
            Log.w(TAG, "Cascade policy not loaded; using disabled default", e);
            cascadePolicy = CascadePolicy.disabledDefault();
        }
        legacyScanRunner = new LegacyScanRunner(pipelineDependencies, cascadePolicy);
        cascadeScanRunner = new ScanOrchestrator(pipelineDependencies, cascadePolicy);
        legacyPipelines = LegacyModelPipelines.create(pipelineDependencies);
        if (cascadePolicy.isEnabled()) {
            sendLog("Cascade policy enabled: " + cascadePolicy.getPolicyName(), null);
        } else {
            sendLog("Cascade policy disabled (legacy all-models mode)", null);
        }

        DebugOnnxParitySelfTest.runIfDebug(
                this, mldpDexHeaderModeARunner, broadcastMldpRunner, dexheaderBroadcastFusionRunner);
    }

    @Override
    protected void onHandleWork(@NonNull Intent intent) {
        clearCancel();
        sendLog("ScanService started", "Running");

        boolean manual = intent.getBooleanExtra("manual_trigger", false);
        boolean rescanAll = intent.getBooleanExtra(EXTRA_RESCAN_ALL, false);
        String trigger = manual ? "manual" : "download";
        if (manual) {
            sendLog("Triggered by button", null);
        } else {
            sendLog("Triggered by BroadcastReceiver", null);
        }

        String sessionId = intent.getStringExtra(EXTRA_SESSION_ID);
        if (sessionId == null || sessionId.isEmpty()) {
            sessionId = UUID.randomUUID().toString();
        }
        sendLog("Session " + sessionId, null);

        CascadePolicy effectivePolicy = resolveCascadePolicy(intent);
        boolean cascadeEnabled = effectivePolicy.isEnabled();
        legacyScanRunner = new LegacyScanRunner(pipelineDependencies, effectivePolicy);
        cascadeScanRunner = new ScanOrchestrator(pipelineDependencies, effectivePolicy);
        sendLog(
                cascadeEnabled
                        ? "Scan mode: Cascade (deployed)"
                        : "Scan mode: Ablation (all models)",
                null);

        if (pipelineDependencies != null) {
            pipelineDependencies.enabledModelIds = parseEnabledModels(intent);
            if (pipelineDependencies.enabledModelIds != null
                    && !pipelineDependencies.enabledModelIds.isEmpty()) {
                sendLog(
                        "Model filter: " + String.join(", ", pipelineDependencies.enabledModelIds),
                        null);
            }
        }

        long startedMs = System.currentTimeMillis();
        long wallStart = SystemClock.elapsedRealtime();
        BatterySampler.Snapshot batteryStart = BatterySampler.sample(this);

        int apkCount = 0;
        int apkScanned = 0;
        int apkFailed = 0;
        int apkSkippedDedup = 0;
        org.json.JSONObject sessionProvenance = null;
        try {
            sessionProvenance = ProvenanceCollector.buildSessionProvenance(this, effectivePolicy);
        } catch (Exception ex) {
            Log.w(TAG, "Provenance collection failed", ex);
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (!Environment.isExternalStorageManager()) {
                    sendLog("No MANAGE_EXTERNAL_STORAGE permission. Abort.", "Error");
                    return;
                }
            }

            File downloads = new File(Environment.getExternalStorageDirectory(), "Download");
            if (!downloads.exists()) {
                sendLog("Downloads folder not found!", "Error");
                return;
            }

            List<File> targets =
                    resolveScanTargets(
                            downloads,
                            intent.getStringExtra(EXTRA_APK_PATH),
                            intent.getStringArrayListExtra(EXTRA_SCAN_SUBDIRS));
            if (targets.isEmpty()) {
                sendLog("No APKs found.", "Idle");
                return;
            }

            apkCount = targets.size();

            for (int index = 0; index < targets.size(); index++) {
                if (cancelRequested) {
                    sendLog("Scan cancelled by user.", "Idle");
                    break;
                }

                File apk = targets.get(index);
                sendProgress(index + 1, apkCount);
                sendLog("Processing: " + apk.getName(), "Parsing");

                try (FeatureContext ctx = FeatureContext.open(apk)) {
                    String sha256 = ctx.sha256Hex();
                    if (!rescanAll && ScanProcessedStore.contains(this, sha256)) {
                        apkSkippedDedup++;
                        sendLog("Skipped (already scanned): " + apk.getName(), null);
                        MetricsWriter.ScanMetrics skipScan =
                                ScanMetricsAssembler.dedupSkipped(
                                        trigger, apk, sha256, sessionId, cascadeEnabled);
                        writeScanMetrics(skipScan);
                        continue;
                    }

                    BatterySampler.Snapshot scanBatteryStart = BatterySampler.sample(this);
                    StageRunner.LogSink logSink = (message, status) -> sendLog(message, status);
                    ScanApkResult result =
                            cascadeEnabled
                                    ? cascadeScanRunner.run(ctx, apk.getName(), logSink)
                                    : legacyScanRunner.run(ctx, apk.getName(), logSink);
                    BatterySampler.Snapshot scanBatteryEnd = BatterySampler.sample(this);

                    MetricsWriter.ScanMetrics scan =
                            ScanMetricsAssembler.toScanMetrics(
                                    trigger,
                                    apk,
                                    result,
                                    effectivePolicy,
                                    cascadeEnabled,
                                    scanBatteryStart,
                                    scanBatteryEnd);
                    scan.sessionId = sessionId;
                    File metricsFile = writeScanMetrics(scan);
                    ScanProcessedStore.mark(this, sha256);

                    apkScanned++;
                    logStageErrors(apk.getName(), result);
                    String detailJson = ScanResultDetailBuilder.toJson(result);
                    sendScanResult(
                            apk.getName(),
                            result.ensembleScore,
                            result.ensembleDecision,
                            result.wallMs,
                            result.memDeltaBytes / (1024.0 * 1024.0),
                            metricsFile != null ? metricsFile.getName() : null,
                            detailJson);
                    sendLog("Scanned: " + apk.getName(), "Idle");
                } catch (Exception ex) {
                    apkFailed++;
                    Log.w(TAG, "Scan failed for " + apk.getName(), ex);
                    sendLog("Scan error for " + apk.getName() + ": " + ex.getMessage(), "Error");
                }
            }

            sendLog(
                    String.format(
                            Locale.US,
                            "Session complete: %d scanned, %d skipped (dedup), %d failed — "
                                    + "metrics retained for resume",
                            apkScanned,
                            apkSkippedDedup,
                            apkFailed),
                    "Idle");
        } finally {
            writeSessionRecord(
                    sessionId,
                    trigger,
                    startedMs,
                    System.currentTimeMillis(),
                    SystemClock.elapsedRealtime() - wallStart,
                    apkCount,
                    apkScanned,
                    apkFailed,
                    apkSkippedDedup,
                    cascadeEnabled,
                    batteryStart,
                    BatterySampler.sample(this),
                    sessionProvenance);
            if (pipelineDependencies != null) {
                pipelineDependencies.enabledModelIds = null;
            }
        }
    }

    private CascadePolicy resolveCascadePolicy(Intent intent) {
        if (cascadePolicy == null) {
            return CascadePolicy.disabledDefault();
        }
        if (!intent.hasExtra(EXTRA_CASCADE_ENABLED)) {
            return cascadePolicy;
        }
        return cascadePolicy.withEnabled(intent.getBooleanExtra(EXTRA_CASCADE_ENABLED, false));
    }

    private static Set<String> parseEnabledModels(Intent intent) {
        ArrayList<String> models = intent.getStringArrayListExtra(EXTRA_ENABLED_MODELS);
        if (models == null || models.isEmpty()) {
            return null;
        }
        Set<String> out = new HashSet<>();
        for (String modelId : models) {
            if (modelId != null && !modelId.trim().isEmpty()) {
                out.add(modelId.trim());
            }
        }
        return out.isEmpty() ? null : Collections.unmodifiableSet(out);
    }

    private static List<File> resolveScanTargets(
            File downloadsDir, String apkPathExtra, ArrayList<String> scanSubdirs) {
        List<File> targets = new ArrayList<>();
        if (apkPathExtra != null && !apkPathExtra.isEmpty()) {
            File single = new File(apkPathExtra);
            if (single.isFile() && single.getName().toLowerCase(Locale.US).endsWith(".apk")) {
                targets.add(single);
                return targets;
            }
        }

        Set<String> subdirs = new LinkedHashSet<>();
        subdirs.add("");
        subdirs.add(DEFAULT_SCAN_SUBDIR);
        if (scanSubdirs != null) {
            for (String sub : scanSubdirs) {
                if (sub != null && !sub.trim().isEmpty()) {
                    subdirs.add(sub.trim());
                }
            }
        }

        for (String sub : subdirs) {
            File dir = sub.isEmpty() ? downloadsDir : new File(downloadsDir, sub);
            collectApksFlat(dir, targets);
        }

        targets.sort((a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        return targets;
    }

    private static void collectApksFlat(File dir, List<File> out) {
        if (dir == null || !dir.isDirectory()) {
            return;
        }
        File[] files = dir.listFiles((d, name) -> name.toLowerCase(Locale.US).endsWith(".apk"));
        if (files == null) {
            return;
        }
        for (File file : files) {
            out.add(file);
        }
    }

    private File writeScanMetrics(MetricsWriter.ScanMetrics scan) {
        try {
            return MetricsWriter.writeScan(this, scan);
        } catch (Exception e) {
            Log.e(TAG, "Metrics write failed", e);
            sendLog("Metrics JSON error: " + e.getMessage(), null);
            return null;
        }
    }

    private void writeSessionRecord(
            String sessionId,
            String trigger,
            long startedMs,
            long endedMs,
            double wallMsTotal,
            int apkCount,
            int apkScanned,
            int apkFailed,
            int apkSkippedDedup,
            boolean cascadeEnabled,
            BatterySampler.Snapshot batteryStart,
            BatterySampler.Snapshot batteryEnd,
            org.json.JSONObject provenance) {
        MetricsWriter.SessionMetrics session = new MetricsWriter.SessionMetrics();
        session.sessionId = sessionId;
        session.trigger = trigger;
        session.startedMs = startedMs;
        session.endedMs = endedMs;
        session.wallMsTotal = wallMsTotal;
        session.apkCount = apkCount;
        session.apkScanned = apkScanned;
        session.apkFailed = apkFailed;
        session.apkSkippedDedup = apkSkippedDedup;
        session.cascadeEnabled = cascadeEnabled;
        session.provenance = provenance;
        session.batteryStart = batteryStart;
        session.batteryEnd = batteryEnd;
        try {
            MetricsWriter.writeSession(this, session);
            sendLog(
                    String.format(
                            Locale.US,
                            "Session metrics: %d scanned, %d failed, wall %.0f ms",
                            apkScanned,
                            apkFailed,
                            wallMsTotal),
                    null);
        } catch (Exception e) {
            Log.e(TAG, "Session metrics write failed", e);
            sendLog("Session metrics error: " + e.getMessage(), null);
        }
    }

    private void logStageErrors(String apkName, ScanApkResult result) {
        if (result == null || result.stages == null) {
            return;
        }
        for (StageResult stage : result.stages) {
            if (!StageResult.STATUS_ERROR.equals(stage.status)) {
                continue;
            }
            String modelId =
                    stage.modelId != null && !stage.modelId.isEmpty()
                            ? stage.modelId
                            : stage.domain;
            String message = stage.errorMessage;
            if (message == null || message.isEmpty()) {
                message = modelId + "@run: unknown error";
            }
            sendLog("Stage error " + apkName + " — " + message, "Error");
        }
    }

    private void sendLog(String log, String status) {
        Intent i = new Intent(MainActivity.ACTION_SCAN_LOG);
        i.putExtra("log", log);
        if (status != null) {
            i.putExtra("status", status);
        }
        LocalBroadcastManager.getInstance(this).sendBroadcast(i);
    }

    private void sendProgress(int current, int total) {
        Intent i = new Intent(MainActivity.ACTION_SCAN_LOG);
        i.putExtra("log", String.format(Locale.US, "Progress %d / %d", current, total));
        i.putExtra("status", EXTRA_PROGRESS + ":" + current + "/" + total);
        LocalBroadcastManager.getInstance(this).sendBroadcast(i);
    }

    private void sendScanResult(
            String apkName,
            float ensembleScore,
            String ensembleDecision,
            double totalMs,
            double totalMemMb,
            String metricsFileName,
            String detailJson) {
        Intent i = new Intent(MainActivity.ACTION_SCAN_RESULT);
        i.putExtra("apk_name", apkName);
        i.putExtra("ensemble_score", ensembleScore);
        i.putExtra("ensemble_decision", ensembleDecision);
        i.putExtra("total_ms", totalMs);
        i.putExtra("total_mem_mb", totalMemMb);
        if (metricsFileName != null) {
            i.putExtra("metrics_file", metricsFileName);
        }
        if (detailJson != null) {
            i.putExtra("scan_detail_json", detailJson);
        }
        LocalBroadcastManager.getInstance(this).sendBroadcast(i);
    }

    private void initOnnxModel() throws Exception {
        ortEnvironment = OrtEnvironment.getEnvironment();
        OrtSession.SessionOptions sessionOptions = OnnxSessionFactory.createOptions(this);

        boolean xgbOk = false;
        boolean cnnOk = false;

        try {
            File modelFile = new File(getCacheDir(), "mh1m_2500_rp_XGBoost.onnx");
            if (!modelFile.exists()) {
                try (InputStream is = getAssets().open("mh1m_2500_rp_XGBoost.onnx");
                        FileOutputStream fos = new FileOutputStream(modelFile)) {
                    byte[] buf = new byte[8192];
                    int r;
                    while ((r = is.read(buf)) != -1) {
                        fos.write(buf, 0, r);
                    }
                }
            }
            ortSession = ortEnvironment.createSession(modelFile.getAbsolutePath(), sessionOptions);
            xgbOk = true;
            sendLog("XGBoost ONNX loaded", null);
        } catch (Exception ex) {
            Log.w(TAG, "XGBoost ONNX not loaded", ex);
            ortSession = null;
            sendLog("XGBoost ONNX skipped: " + ex.getMessage(), null);
        }

        try {
            File cnnModelFile = new File(getCacheDir(), "bytecnn_basemodel_2020.onnx");
            if (!cnnModelFile.exists()) {
                try (InputStream is = getAssets().open("bytecnn_basemodel_2020.onnx");
                        FileOutputStream fos = new FileOutputStream(cnnModelFile)) {
                    byte[] buf = new byte[8192];
                    int r;
                    while ((r = is.read(buf)) != -1) {
                        fos.write(buf, 0, r);
                    }
                }
            }
            ortSessionCnn =
                    ortEnvironment.createSession(cnnModelFile.getAbsolutePath(), sessionOptions);
            cnnOk = true;
            sendLog("ByteCNN ONNX loaded", null);
        } catch (Exception ex) {
            Log.e(TAG, "ByteCNN ONNX not loaded", ex);
            ortSessionCnn = null;
            sendLog("ByteCNN ONNX missing: " + ex.getMessage(), "Error");
        }

        if (!xgbOk && !cnnOk) {
            throw new IllegalStateException("No ONNX models loaded from assets");
        }
    }

    private void initMlpHeaderPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        mlpHeaderExtractor = DexHeaderFeatureExtractor.fromAssets(this);
        mlpHeaderRunner = MlpHeaderOnnxRunner.create(this, ortEnvironment);
        sendLog("BM1 mlp_header ONNX loaded", null);
    }

    private void initPatternAPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        patternAHeaderExtractor =
                DexHeaderFeatureExtractor.fromAssets(
                        this, DexHeaderFeatureExtractor.EARLY_FUSION_DEX_MANIFEST_NORMALIZATION_ASSET);
        patternABowExtractor =
                ManifestBowExtractor.fromAssets(
                    this, ManifestBowExtractor.EARLY_FUSION_DEX_MANIFEST_VOCAB_ASSET);
        patternARunner = PatternAOnnxRunner.create(this, ortEnvironment);
        sendLog("Early-fusion Dex+manifest ONNX loaded", null);
    }

    private void initPatternBPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        patternBHeaderExtractor =
                DexHeaderFeatureExtractor.fromAssets(
                        this, DexHeaderFeatureExtractor.DUAL_BRANCH_DEX_MANIFEST_NORMALIZATION_ASSET);
        patternBBowExtractor =
                ManifestBowExtractor.fromAssets(
                    this, ManifestBowExtractor.DUAL_BRANCH_DEX_MANIFEST_VOCAB_ASSET);
        patternBRunner = PatternBOnnxRunner.create(this, ortEnvironment);
        sendLog("Dual-branch Dex+manifest ONNX loaded", null);
    }

    private void initLinRegPermissionPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        linRegExtractor = LinRegPermissionExtractor.fromAssets(this);
        linRegRunner = LinRegDroidOnnxRunner.create(this, ortEnvironment);
        sendLog(
                "LinRegDroid "
                        + ModelRegistry.LINREGDROID_PERMISSION.modelId
                        + " ONNX loaded (domain="
                        + ModelRegistry.LINREGDROID_PERMISSION.domain
                        + ")",
                null);
    }

    private void initMldpPrunedPermissionPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        mldpExtractor = MldpPrunedPermissionExtractor.fromAssets(this);
        mldpRunner = MldpPrunedOnnxRunner.create(this, ortEnvironment);
        sendLog(
                "MLDP "
                        + ModelRegistry.MLDP_PRUNED_PERMISSION.modelId
                        + " ONNX loaded (domain="
                        + ModelRegistry.MLDP_PRUNED_PERMISSION.domain
                        + ", type="
                        + mldpRunner.getModelType()
                        + ")",
                null);
    }

    private void initMldpDexHeaderCascadePipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        mldpDexHeaderExtractor = MldpDexHeaderExtractor.fromAssets(this);
        mldpDexHeaderModeARunner = MldpDexHeaderModeAOnnxRunner.create(this, ortEnvironment);
        mldpDexHeaderModeBRunner = MldpDexHeaderModeBOnnxRunner.create(this, ortEnvironment);
        sendLog(
                "MLDP+Dex cascade loaded (Mode A="
                        + ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_A.modelId
                        + ", Mode B="
                        + ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B.modelId
                        + ", domain="
                        + MldpDexHeaderModeAOnnxRunner.DOMAIN
                        + ")",
                null);
    }

    private void initDexheaderBroadcastFusionPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        dexheaderBroadcastFusionExtractor = DexheaderBroadcastFusionExtractor.fromAssets(this);
        dexheaderBroadcastFusionRunner =
                DexheaderBroadcastFusionOnnxRunner.create(this, ortEnvironment);
        sendLog(
                "Dex+Broadcast fusion "
                        + ModelRegistry.DEXHEADER_BROADCAST_FUSION.modelId
                        + " ONNX loaded (domain="
                        + ModelRegistry.DEXHEADER_BROADCAST_FUSION.domain
                        + ")",
                null);
    }

    private void initBroadcastMldpHybridPipeline() throws Exception {
        if (ortEnvironment == null) {
            ortEnvironment = OrtEnvironment.getEnvironment();
        }
        broadcastMldpExtractor = BroadcastMldpHybridExtractor.fromAssets(this);
        broadcastMldpRunner = BroadcastMldpHybridOnnxRunner.create(this, ortEnvironment);
        sendLog(
                "Broadcast+MLDP "
                        + ModelRegistry.BROADCAST_MLDP_HYBRID.modelId
                        + " ONNX loaded (domain="
                        + ModelRegistry.BROADCAST_MLDP_HYBRID.domain
                        + ", type="
                        + broadcastMldpRunner.getModelType()
                        + ")",
                null);
    }

    private void loadFeatureColumns() throws Exception {
        InputStream is = getAssets().open("mh1m_2500_rp_features.json.gzip");
        GZIPInputStream gzis = new GZIPInputStream(new BufferedInputStream(is));
        StringBuilder sb = new StringBuilder();
        byte[] buf = new byte[8192];
        int r;
        while ((r = gzis.read(buf)) != -1) {
            sb.append(new String(buf, 0, r));
        }
        gzis.close();

        JSONArray arr = new JSONArray(sb.toString());
        featureColumns.clear();
        featureIndex.clear();
        for (int i = 0; i < arr.length(); i++) {
            String f = arr.getString(i);
            featureColumns.add(f);
            featureIndex.put(f, i);
        }

        sendLog("Loaded " + featureColumns.size() + " feature columns", null);
    }

    @Override
    public void onDestroy() {
        if (legacyPipelines != null) {
            for (ModelPipeline pipeline : legacyPipelines) {
                try {
                    pipeline.close();
                } catch (Exception ignored) {
                }
            }
        }
        if (ortSession != null) {
            try {
                ortSession.close();
            } catch (Exception ignored) {
            }
        }
        if (ortSessionCnn != null) {
            try {
                ortSessionCnn.close();
            } catch (Exception ignored) {
            }
        }
        if (mlpHeaderRunner != null) {
            try {
                mlpHeaderRunner.close();
            } catch (Exception ignored) {
            }
        }
        if (patternARunner != null) {
            try {
                patternARunner.close();
            } catch (Exception ignored) {
            }
        }
        if (patternBRunner != null) {
            try {
                patternBRunner.close();
            } catch (Exception ignored) {
            }
        }
        if (linRegRunner != null) {
            try {
                linRegRunner.close();
            } catch (Exception ignored) {
            }
        }
        if (mldpRunner != null) {
            try {
                mldpRunner.close();
            } catch (Exception ignored) {
            }
        }
        if (broadcastMldpRunner != null) {
            try {
                broadcastMldpRunner.close();
            } catch (Exception ignored) {
            }
        }
        if (mldpDexHeaderModeARunner != null) {
            try {
                mldpDexHeaderModeARunner.close();
            } catch (Exception ignored) {
            }
        }
        if (mldpDexHeaderModeBRunner != null) {
            try {
                mldpDexHeaderModeBRunner.close();
            } catch (Exception ignored) {
            }
        }
        if (ortEnvironment != null) {
            try {
                ortEnvironment.close();
            } catch (Exception ignored) {
            }
        }
        super.onDestroy();
    }
}
