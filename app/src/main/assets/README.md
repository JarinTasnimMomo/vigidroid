# VigiDroid assets

Copy model files here before building the app.

## Required for 1D-CNN (Pipeline B)

| File | How to get it |
|------|----------------|
| `bytecnn_basemodel_2020.onnx` | Run `cd 1dcnn && python train_and_export.py` |

## Required for XGBoost (Pipeline A) — if you have them

| File | Notes |
|------|--------|
| `mh1m_2500_rp_XGBoost.onnx` | Pre-trained baseline; restore from backup or re-export from your XGBoost training pipeline |
| `mh1m_2500_rp_features.json.gzip` | Feature vocabulary (~2500 columns); must match the XGBoost model |

If XGBoost files are missing, the app still runs **CNN-only** (see `ScanService`); XGBoost scores will show as `-1`.
