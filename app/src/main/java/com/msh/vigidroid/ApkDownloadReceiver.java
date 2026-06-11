package com.msh.vigidroid;

import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import java.io.File;
import java.util.UUID;

/** Scan a single newly downloaded APK (A3) via DownloadManager or content URI. */
public class ApkDownloadReceiver extends BroadcastReceiver {

  private static final String TAG = "ApkDownloadReceiver";

  @Override
  public void onReceive(Context context, Intent intent) {
    if (intent == null) {
      return;
    }

    String apkPath = null;
    String action = intent.getAction();

    if (DownloadManager.ACTION_DOWNLOAD_COMPLETE.equals(action)) {
      apkPath = resolveDownloadManagerPath(context, intent);
    } else if (Intent.ACTION_VIEW.equals(action) || Intent.ACTION_SEND.equals(action)) {
      apkPath = resolveUriPath(intent.getData());
    }

    if (apkPath == null) {
      Uri data = intent.getData();
      if (data != null && data.toString().toLowerCase().endsWith(".apk")) {
        apkPath = resolveUriPath(data);
      }
    }

    if (apkPath == null) {
      return;
    }

    Intent serviceIntent = new Intent(context, ScanService.class);
    serviceIntent.putExtra("manual_trigger", false);
    serviceIntent.putExtra(ScanService.EXTRA_APK_PATH, apkPath);
    serviceIntent.putExtra(ScanService.EXTRA_SESSION_ID, UUID.randomUUID().toString());
    ScanService.enqueueWork(context, serviceIntent);
    Log.i(TAG, "Queued download scan: " + apkPath);
  }

  private static String resolveDownloadManagerPath(Context context, Intent intent) {
    long downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L);
    if (downloadId < 0) {
      return null;
    }
    DownloadManager dm = (DownloadManager) context.getSystemService(Context.DOWNLOAD_SERVICE);
    if (dm == null) {
      return null;
    }
    try (Cursor cursor = dm.query(new DownloadManager.Query().setFilterById(downloadId))) {
      if (cursor == null || !cursor.moveToFirst()) {
        return null;
      }
      int statusIdx = cursor.getColumnIndex(DownloadManager.COLUMN_STATUS);
      if (statusIdx >= 0) {
        int status = cursor.getInt(statusIdx);
        if (status != DownloadManager.STATUS_SUCCESSFUL) {
          return null;
        }
      }
      int uriIdx = cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI);
      if (uriIdx < 0) {
        return null;
      }
      String localUri = cursor.getString(uriIdx);
      return resolveUriPath(Uri.parse(localUri));
    } catch (Exception ex) {
      Log.w(TAG, "DownloadManager query failed", ex);
      return null;
    }
  }

  private static String resolveUriPath(Uri uri) {
    if (uri == null) {
      return null;
    }
    if ("file".equalsIgnoreCase(uri.getScheme())) {
      File file = new File(uri.getPath());
      if (file.isFile() && file.getName().toLowerCase().endsWith(".apk")) {
        return file.getAbsolutePath();
      }
    }
    String path = uri.getPath();
    if (path != null) {
      File file = new File(path);
      if (file.isFile() && file.getName().toLowerCase().endsWith(".apk")) {
        return file.getAbsolutePath();
      }
    }
    return null;
  }
}
