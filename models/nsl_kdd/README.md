# Imported NSL-KDD Model Assets

- `rf_model.pkl`: trained Random Forest binary IDS model.
- `dt_model.pkl`: trained Decision Tree binary IDS model.
- `encoder.pkl`: one-hot encoder for `protocol_type`, `service`, and `flag`.
- `scaler.pkl`: numerical feature scaler.
- `KDDTrain+_20Percent.txt`: NSL-KDD training subset from the imported project.
- `original_script.py`: original CLI/manual IDS script for reference.

The application wraps these files through `nsl_kdd_adapter.py`. The imported model is binary, so the adapter predicts `Normal Traffic` versus `Attack` and then maps attack traffic into a likely family (`DoS`, `Probe`, `R2L`, `U2R`, or `Botnet / Suspicious`) using live-flow heuristics for dashboard compatibility.
