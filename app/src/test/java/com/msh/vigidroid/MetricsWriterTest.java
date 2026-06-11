package com.msh.vigidroid;

import com.msh.vigidroid.pipeline.ScanMetricsAssembler;

import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class MetricsWriterTest {

  @Test
  public void stageMetrics_modelIdOptional() {
    MetricsWriter.StageMetrics legacy =
        new MetricsWriter.StageMetrics("manifest_xgb", 1.0, 2.0, 3.0, 0.5f, 100L);
    assertNull(legacy.modelId);

    MetricsWriter.StageMetrics hybrid =
        new MetricsWriter.StageMetrics(
            ModelRegistry.BROADCAST_MLDP_HYBRID.domain,
            ModelRegistry.BROADCAST_MLDP_HYBRID.modelId,
            4.0,
            5.0,
            6.0,
            0.73f,
            200L);
    assertEquals("broadcast_mldp_hybrid", hybrid.modelId);
    assertEquals("manifest_mldp_perm_receiver_actions", hybrid.domain);
  }

  @Test
  public void cascadeStageMetrics_exposesModeBandDexFields() {
    MetricsWriter.StageMetrics modeB =
        MetricsWriter.StageMetrics.cascade(
            MldpDexHeaderModeBOnnxRunner.DOMAIN,
            ModelRegistry.MLDP_DEXHEADER_CASCADE_MODE_B.modelId,
            "B",
            1.0,
            0.0,
            0.5,
            2.0,
            0.25,
            0.91f,
            -1f,
            true,
            MetricsWriter.STATUS_OK,
            null,
            0.91f,
            42L);
    assertEquals(0.25, modeB.cpuMs, 1e-9);
    assertEquals(MetricsWriter.STATUS_OK, modeB.status);
    assertEquals("B", modeB.mode);
    assertEquals(0.0, modeB.dexMs, 1e-9);
    assertTrue(modeB.earlyExit);
    assertEquals(0.91f, modeB.stage1Score, 1e-6f);
  }

  @Test
  public void shortSha256Prefix_usesFirstEightHexChars() {
    String full = "0d35c6449ad9f98d273bccd9512a18e89fa29eace384d91f3e6ba9d0e5a05225";
    assertEquals("0d35c644", MetricsWriter.shortSha256Prefix(full));
  }

  @Test
  public void buildScanObject_includesSha256AndStageStatus() throws Exception {
    MetricsWriter.ScanMetrics scan = new MetricsWriter.ScanMetrics();
    scan.apkName = "eval_0001_benign.apk";
    scan.apkSizeBytes = 100;
    scan.apkSha256 = "a".repeat(64);
    scan.trigger = "manual";
    scan.stages.add(
        new MetricsWriter.StageMetrics(
            ModelRegistry.MANIFEST_XGB.domain,
            ModelRegistry.MANIFEST_XGB.modelId,
            1.0,
            2.0,
            3.0,
            0.1,
            MetricsWriter.STATUS_SKIPPED,
            null,
            -1f,
            0L));

    scan.sessionId = "sess-abc";
    scan.cascadeEnabled = false;
    org.json.JSONObject obj = MetricsWriter.buildScanObject(scan);
    assertEquals("scan", obj.getString("record_type"));
    assertEquals("sess-abc", obj.getString("session_id"));
    assertEquals(false, obj.getBoolean("cascade_enabled"));
    assertEquals("aaaaaaaa", obj.getJSONObject("apk").getString("sha256_short"));
    org.json.JSONObject stage = obj.getJSONArray("stages").getJSONObject(0);
    assertEquals("skipped", stage.getString("status"));
    assertEquals("manifest_xgb", stage.getString("model_id"));
    assertTrue(obj.getJSONObject("totals").isNull("battery_pct_delta"));
    assertEquals("scan", obj.getString("record_type"));
  }

  @Test
  public void buildScanObject_allocatesBatteryAcrossStages() throws Exception {
    MetricsWriter.ScanMetrics scan = new MetricsWriter.ScanMetrics();
    scan.apkName = "sample.apk";
    scan.apkSizeBytes = 1;
    scan.cascadeEnabled = false;
    scan.batteryPctDelta = -2.0;
    scan.stages.add(
        new MetricsWriter.StageMetrics(
            "bytecnn",
            "bytecnn",
            1.0,
            0.0,
            1.0,
            0.1,
            MetricsWriter.STATUS_OK,
            null,
            0.5f,
            10L));
    scan.stages.add(
        new MetricsWriter.StageMetrics(
            "manifest_xgb",
            "manifest_xgb",
            3.0,
            0.0,
            1.0,
            0.2,
            MetricsWriter.STATUS_OK,
            null,
            0.5f,
            20L));

    org.json.JSONObject obj = MetricsWriter.buildScanObject(scan);
    assertEquals(-2.0, obj.getJSONObject("totals").getDouble("battery_pct_delta"), 1e-9);
    org.json.JSONObject cnn = obj.getJSONArray("stages").getJSONObject(0);
    org.json.JSONObject xgb = obj.getJSONArray("stages").getJSONObject(1);
    assertEquals(-2.0 * (2.0 / 6.0), cnn.getDouble("battery_pct_delta"), 1e-9);
    assertEquals(-2.0 * (4.0 / 6.0), xgb.getDouble("battery_pct_delta"), 1e-9);
  }

  @Test
  public void buildScanObject_includesCascadeBlock() throws Exception {
    MetricsWriter.ScanMetrics scan = new MetricsWriter.ScanMetrics();
    scan.apkName = "test.apk";
    scan.apkSizeBytes = 1;
    scan.ensembleScore = 0.12f;
    scan.ensembleDecision = "benign";
    scan.ensemblePolicy = "cascade_v1";
    scan.cascadePolicy = "cascade_v1";
    scan.cascadeExitTier = 1;
    scan.cascadeExitReason = "low_confident_benign";
    scan.cascadeFinalScore = 0.12f;
    scan.cascadeDecision = "benign";
    scan.cascadeModelsRun = java.util.List.of("mldp_pruned_permission");
    scan.cascadeModelsSkipped = java.util.List.of("bytecnn");
    scan.cascadeEnabled = true;

    org.json.JSONObject obj = MetricsWriter.buildScanObject(scan);
    assertTrue(obj.getBoolean("cascade_enabled"));
    org.json.JSONObject cascade = obj.getJSONObject("cascade");
    assertEquals(1, cascade.getInt("exit_tier"));
    assertEquals("low_confident_benign", cascade.getString("exit_reason"));
    assertEquals(1, cascade.getJSONArray("models_run").length());
  }

  @Test
  public void buildScanObject_includesSharedParseMs() throws Exception {
    MetricsWriter.ScanMetrics scan = new MetricsWriter.ScanMetrics();
    scan.apkName = "sample.apk";
    scan.apkSizeBytes = 1;
    scan.sharedParseMs = 12.5;

    org.json.JSONObject obj = MetricsWriter.buildScanObject(scan);
    assertEquals(12.5, obj.getJSONObject("totals").getDouble("shared_parse_ms"), 1e-9);
  }

  @Test
  public void dedupSkippedScan_writesDedupFlag() throws Exception {
    File apk = new File(System.getProperty("java.io.tmpdir"), "eval_0001_benign.apk");
    //noinspection ResultOfMethodCallIgnored
    apk.deleteOnExit();
    if (!apk.exists() && !apk.createNewFile()) {
      throw new IllegalStateException("Could not create temp apk file");
    }
    MetricsWriter.ScanMetrics scan =
        ScanMetricsAssembler.dedupSkipped("manual", apk, "b".repeat(64), "sess-dedup", true);
    org.json.JSONObject obj = MetricsWriter.buildScanObject(scan);
    assertTrue(obj.getBoolean("dedup_skipped"));
    assertTrue(obj.getBoolean("cascade_enabled"));
    assertEquals("benign", obj.getString("ground_truth"));
  }

  @Test
  public void buildSessionObject_includesBatteryDeltas() throws Exception {
    BatterySampler.Snapshot start =
        new BatterySampler.Snapshot(85, 2_500_000, -500_000, 320);
    BatterySampler.Snapshot end =
        new BatterySampler.Snapshot(84, 2_499_500, -480_000, 322);

    MetricsWriter.SessionMetrics session = new MetricsWriter.SessionMetrics();
    session.sessionId = "sess-1";
    session.trigger = "manual";
    session.startedMs = 1_000L;
    session.endedMs = 60_000L;
    session.wallMsTotal = 59_000.0;
    session.apkCount = 10;
    session.apkScanned = 9;
    session.apkFailed = 1;
    session.batteryStart = start;
    session.batteryEnd = end;

    org.json.JSONObject obj = MetricsWriter.buildSessionObject(session);
    assertEquals("session", obj.getString("record_type"));
    assertEquals("sess-1", obj.getString("session_id"));
    assertEquals(9, obj.getInt("apk_scanned"));
    assertEquals(1, obj.getInt("apk_failed"));
    org.json.JSONObject battery = obj.getJSONObject("battery");
    assertEquals(-1, battery.getInt("capacity_pct_delta"));
    assertEquals(500, battery.getInt("charge_counter_uah_used"));
    assertEquals(2, battery.getInt("temperature_deci_c_delta"));
  }

  @Test
  public void jsonlFilename_splitByCascadeMode() {
    assertEquals(MetricsWriter.SCAN_A_JSONL_FILENAME, MetricsWriter.jsonlFilename(false));
    assertEquals(MetricsWriter.SCAN_B_JSONL_FILENAME, MetricsWriter.jsonlFilename(true));
    assertEquals(
        MetricsWriter.SCAN_A_LEGACY_AGGREGATE_FILENAME,
        MetricsWriter.legacyAggregateFilename(false));
    assertEquals(
        MetricsWriter.SCAN_B_LEGACY_AGGREGATE_FILENAME,
        MetricsWriter.legacyAggregateFilename(true));
  }
}
