package com.msh.vigidroid;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** Copy bundled assets into app cache for ONNX Runtime file loading. */
public final class ModelAssetHelper {

    private ModelAssetHelper() {}

    public static File copyAssetToCache(Context context, String assetPath, String cacheFileName)
            throws Exception {
        File out = new File(context.getCacheDir(), cacheFileName);
        if (out.exists() && out.length() > 0) {
            return out;
        }
        try (InputStream is = context.getAssets().open(assetPath);
             FileOutputStream fos = new FileOutputStream(out)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = is.read(buf)) != -1) {
                fos.write(buf, 0, read);
            }
        }
        return out;
    }

    public static String readAssetText(Context context, String assetPath) throws Exception {
        try (InputStream is = context.getAssets().open(assetPath)) {
            byte[] bytes = new byte[is.available()];
            int offset = 0;
            while (offset < bytes.length) {
                int read = is.read(bytes, offset, bytes.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
            return new String(bytes, 0, offset, java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}
