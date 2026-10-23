# XShield — Research Build

CSV-first starter for analysing labelled network-flow data and training a baseline classifier. It does not yet claim live monitoring, PCAP extraction, TLS feature extraction, or SHAP explanations.

## Setup (Windows PowerShell; Python 3.11 recommended)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Upload a labelled CSV, select the target column and input features, then run the baseline.

## Important dataset limitation
CICIDS2017 is a labelled flow dataset, but its ordinary CSV must not automatically be treated as containing TLS handshake metadata. Flow-only data cannot validate TLS-only or Combined Flow+TLS experiments. Do not invent TLS values.

## Research cautions
- The initial random split is a smoke-test baseline, not a final research protocol.
- Inspect target leakage and identifier columns.
- Check duplicates and near-duplicates.
- Consider capture/session/time-aware splits.
- Feature importance is not SHAP and does not prove causality.
- Do not present metrics from one split as real-world performance.

## Milestones
1. Confirm dataset and feature schema.
2. Establish a reproducible baseline.
3. Add valid Flow-only/TLS-only/Combined experiments.
4. Add genuine SHAP explanations.
5. Add PCAP ingestion only after extraction is verified.
