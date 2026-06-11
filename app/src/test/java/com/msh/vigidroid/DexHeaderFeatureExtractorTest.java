package com.msh.vigidroid;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DexHeaderFeatureExtractorTest {

    @Test
    public void validateMagic_acceptsStandardDex() {
        byte[] dex = buildMinimalDex();
        assertTrue(DexHeaderFeatureExtractor.validateMagic(dex));
    }

    @Test
    public void extractRawHeaderFeatures_reads104BytesAfterMagic() {
        byte[] dex = buildMinimalDex();
        for (int i = 0; i < 104; i++) {
            dex[8 + i] = (byte) (i + 1);
        }
        float[] features = DexHeaderFeatureExtractor.extractRawHeaderFeatures(dex);
        assertEquals(104, features.length);
        assertEquals(1f / 255f, features[0], 1e-6f);
        assertEquals(104f / 255f, features[103], 1e-6f);
    }

    @Test
    public void transformMinMax_matchesPythonConstantDimRule() {
        float[] mins = new float[104];
        float[] maxs = new float[104];
        Arrays.fill(mins, 0f);
        Arrays.fill(maxs, 2f);
        maxs[0] = mins[0]; // constant dimension → denom forced to 1

        DexHeaderFeatureExtractor extractor = new DexHeaderFeatureExtractor(mins, maxs);
        float[] raw = new float[104];
        raw[1] = 1f;
        float[] out = extractor.transformMinMax(raw);
        assertEquals(0f, out[0], 1e-6f);
        assertEquals(0.5f, out[1], 1e-6f);
    }

    @Test
    public void dexSortKey_ordersClassesDexFirst() {
        assertTrue(DexHeaderFeatureExtractor.dexSortKey("classes.dex")
                < DexHeaderFeatureExtractor.dexSortKey("classes2.dex"));
    }

    private static byte[] buildMinimalDex() {
        byte[] dex = new byte[DexHeaderFeatureExtractor.DEX_HEADER_SIZE];
        dex[0] = 'd';
        dex[1] = 'e';
        dex[2] = 'x';
        dex[3] = '\n';
        dex[4] = '0';
        dex[5] = '3';
        dex[6] = '5';
        dex[7] = 0;
        return dex;
    }
}
