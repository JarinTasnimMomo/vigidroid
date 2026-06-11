package com.msh.vigidroid;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;

/** Session-level battery snapshot via {@link BatteryManager} (no extra permission). */
public final class BatterySampler {

    private BatterySampler() {}

    public static final class Snapshot {
        public final int capacityPct;
        public final int chargeCounterUah;
        public final int currentNowUa;
        public final int temperatureDeciC;

        public Snapshot(int capacityPct, int chargeCounterUah, int currentNowUa, int temperatureDeciC) {
            this.capacityPct = capacityPct;
            this.chargeCounterUah = chargeCounterUah;
            this.currentNowUa = currentNowUa;
            this.temperatureDeciC = temperatureDeciC;
        }
    }

    public static Snapshot sample(Context context) {
        BatteryManager batteryManager =
                (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);

        int capacityPct = Integer.MIN_VALUE;
        int chargeCounterUah = Integer.MIN_VALUE;
        int currentNowUa = Integer.MIN_VALUE;
        if (batteryManager != null) {
            capacityPct = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
            chargeCounterUah =
                    batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER);
            currentNowUa = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW);
        }

        int temperatureDeciC = Integer.MIN_VALUE;
        Intent sticky =
                context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (sticky != null) {
            temperatureDeciC = sticky.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
        }

        return new Snapshot(capacityPct, chargeCounterUah, currentNowUa, temperatureDeciC);
    }
}
