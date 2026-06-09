# Hybrid Botnet-Capable Flow Model

This folder contains the trainer for the app-native IDS model. It is designed for labeled flow CSVs from datasets such as CICIDS2017, CTU-13, UNSW-NB15, or similar CICFlowMeter/NetFlow exports.

Train with a CSV file or a folder of CSV files:

```bash
python3 models/hybrid_flow/train_hybrid_flow.py /path/to/labeled_flow_csvs
```

The trainer maps common labels into the project classes:

- `normal`
- `dos`
- `probe`
- `r2l`
- `u2r`
- `botnet`

It refuses to save a model if no botnet rows are found. After successful training, the backend automatically promotes this model ahead of the NSL-KDD model.
