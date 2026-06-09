import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, RobustScaler


ROOT = Path(__file__).resolve().parent

FEATURES = [
    "source_bytes",
    "destination_bytes",
    "packet_count",
    "duration",
    "failed_login_count",
    "connection_rate",
    "same_host_rate",
    "error_rate",
]
CATEGORICAL = ["protocol", "service", "flag"]

PORT_SERVICES = {
    20: "ftp",
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "smtp",
    143: "smtp",
    443: "https",
    465: "smtp",
    587: "smtp",
    993: "smtp",
    995: "smtp",
}


def main():
    parser = argparse.ArgumentParser(
        description="Train the app-native hybrid IDS model from CICIDS/CTU/UNSW-style CSV flow datasets."
    )
    parser.add_argument("paths", nargs="+", help="CSV file or directory paths containing labeled flow records.")
    parser.add_argument("--sample", type=int, default=350000, help="Maximum rows to keep before training.")
    parser.add_argument("--trees", type=int, default=220, help="Random Forest tree count.")
    args = parser.parse_args()

    csv_paths = expand_csv_paths(args.paths)
    if not csv_paths:
        raise SystemExit("No CSV files found.")

    frames = []
    sources = []
    for path in csv_paths:
        frame = load_csv(path)
        if frame.empty:
            continue
        normalized = normalize_dataset(frame)
        if normalized.empty:
            continue
        normalized["dataset_source"] = path.name
        frames.append(normalized)
        sources.append(str(path))

    if not frames:
        raise SystemExit("No supported labeled flow rows found.")

    data = pd.concat(frames, ignore_index=True)
    data = data.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES + CATEGORICAL + ["label"])
    data = data[data["label"].isin(["normal", "dos", "probe", "r2l", "u2r", "botnet"])]
    data = balance_sample(data, args.sample)

    if data["label"].nunique() < 2:
        raise SystemExit("Training needs at least two labels.")
    if "botnet" not in set(data["label"]):
        raise SystemExit("No botnet rows were found. Use CICIDS2017 Bot/Botnet or CTU-13 labeled botnet CSVs.")

    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    encoded = pd.DataFrame(encoder.fit_transform(data[CATEGORICAL]))
    encoded.columns = encoder.get_feature_names_out(CATEGORICAL)

    scaler = RobustScaler()
    numeric = data[FEATURES].copy()
    numeric[FEATURES] = scaler.fit_transform(numeric[FEATURES])

    x = pd.concat([numeric.reset_index(drop=True), encoded.reset_index(drop=True)], axis=1)
    y = data["label"].values
    x_train, x_test, y_train, y_test = train_test_split(
        x.values,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=args.trees,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)

    metadata = {
        "classes": sorted(set(y)),
        "accuracy": report["accuracy"],
        "training_rows": int(len(data)),
        "label_counts": {key: int(value) for key, value in data["label"].value_counts().sort_index().items()},
        "dataset_sources": sources,
        "feature_schema": FEATURES + CATEGORICAL,
    }

    ROOT.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ROOT / "hybrid_flow_model.pkl")
    joblib.dump(encoder, ROOT / "hybrid_flow_encoder.pkl")
    joblib.dump(scaler, ROOT / "hybrid_flow_scaler.pkl")
    (ROOT / "hybrid_flow_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (ROOT / "hybrid_flow_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


def expand_csv_paths(paths):
    csv_paths = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if path.is_dir():
            csv_paths.extend(sorted(path.rglob("*.csv")))
        elif path.suffix.lower() == ".csv":
            csv_paths.append(path)
    return [path for path in csv_paths if path.exists()]


def load_csv(path):
    try:
        return pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding="latin1", low_memory=False)


def normalize_dataset(frame):
    frame = frame.copy()
    lookup = {clean_name(column): column for column in frame.columns}
    label_column = find_column(lookup, ["label", "class", "attack", "category", "outcome"])
    if not label_column:
        return pd.DataFrame()

    result = pd.DataFrame()
    result["source_bytes"] = numeric_column(
        frame,
        lookup,
        ["total length of fwd packet", "total length of fwd packets", "totlen fwd pkts", "src_bytes", "sbytes"],
        default=0,
    )
    result["destination_bytes"] = numeric_column(
        frame,
        lookup,
        ["total length of bwd packet", "total length of bwd packets", "totlen bwd pkts", "dst_bytes", "dbytes"],
        default=0,
    )
    fwd_packets = numeric_column(
        frame,
        lookup,
        ["total fwd packet", "total fwd packets", "tot fwd pkts", "spkts"],
        default=0,
    )
    bwd_packets = numeric_column(
        frame,
        lookup,
        ["total bwd packets", "total backward packets", "tot bwd pkts", "dpkts"],
        default=0,
    )
    direct_packets = numeric_column(frame, lookup, ["total packets", "totpkts", "packet_count"], default=0)
    result["packet_count"] = np.maximum(1, direct_packets.where(direct_packets > 0, fwd_packets + bwd_packets))

    duration = numeric_column(frame, lookup, ["flow duration", "dur", "duration"], default=0)
    result["duration"] = normalize_duration(duration)
    result["failed_login_count"] = numeric_column(
        frame,
        lookup,
        ["num_failed_logins", "failed login count", "failed_login_count"],
        default=0,
    )
    rate = numeric_column(
        frame,
        lookup,
        ["flow packets/s", "flow pkts/s", "packets/s", "srate", "connection_rate"],
        default=0,
    )
    result["connection_rate"] = rate.where(rate > 0, result["packet_count"] / result["duration"].clip(lower=0.001))
    result["same_host_rate"] = derive_same_host_rate(frame, lookup)
    result["error_rate"] = derive_error_rate(frame, lookup, result["packet_count"])
    result["protocol"] = derive_protocol(frame, lookup)
    result["service"] = derive_service(frame, lookup)
    result["flag"] = derive_flag(frame, lookup)
    result["label"] = frame[label_column].map(map_label)
    return result


def clean_name(name):
    return " ".join(str(name).strip().lower().replace("_", " ").replace("-", " ").split())


def find_column(lookup, candidates):
    for candidate in candidates:
        cleaned = clean_name(candidate)
        if cleaned in lookup:
            return lookup[cleaned]
    return None


def numeric_column(frame, lookup, candidates, default=0):
    column = find_column(lookup, candidates)
    if not column:
        return pd.Series(default, index=frame.index, dtype="float64")
    return pd.to_numeric(frame[column], errors="coerce").fillna(default).clip(lower=0)


def normalize_duration(series):
    series = pd.to_numeric(series, errors="coerce").fillna(0).clip(lower=0)
    if series.quantile(0.95) > 10000:
        return series / 1_000_000
    if series.quantile(0.95) > 1000:
        return series / 1000
    return series


def derive_same_host_rate(frame, lookup):
    column = find_column(lookup, ["destination ip", "dst ip", "dstaddr", "destination address"])
    if not column:
        return pd.Series(0.0, index=frame.index)
    counts = frame[column].astype(str).map(frame[column].astype(str).value_counts())
    return (counts / max(1, len(frame))).clip(0, 1).astype("float64")


def derive_error_rate(frame, lookup, packet_count):
    rst = numeric_column(frame, lookup, ["rst flag count", "fwd rst flags", "bwd rst flags"], default=0)
    syn = numeric_column(frame, lookup, ["syn flag count"], default=0)
    rej = numeric_column(frame, lookup, ["rejected", "rerror_rate", "serror_rate"], default=0)
    return ((rst + syn + rej) / packet_count.clip(lower=1)).clip(0, 1)


def derive_protocol(frame, lookup):
    column = find_column(lookup, ["protocol", "proto", "protocol type", "protocol_type"])
    if not column:
        return pd.Series("tcp", index=frame.index)
    raw = frame[column].astype(str).str.lower().str.strip()
    mapped = raw.map({"6": "tcp", "17": "udp", "1": "icmp"}).fillna(raw)
    return mapped.where(mapped.isin(["tcp", "udp", "icmp"]), "tcp")


def derive_service(frame, lookup):
    service_column = find_column(lookup, ["service"])
    if service_column:
        return frame[service_column].astype(str).str.lower().str.strip().replace("", "http")
    port_column = find_column(lookup, ["destination port", "dst port", "dport", "destination_port"])
    if not port_column:
        return pd.Series("http", index=frame.index)
    ports = pd.to_numeric(frame[port_column], errors="coerce").fillna(80).astype(int)
    return ports.map(PORT_SERVICES).fillna("http")


def derive_flag(frame, lookup):
    rst = numeric_column(frame, lookup, ["rst flag count", "fwd rst flags", "bwd rst flags"], default=0)
    syn = numeric_column(frame, lookup, ["syn flag count"], default=0)
    if rst.gt(0).any() or syn.gt(0).any():
        return pd.Series(np.where(rst > 0, "RSTO", np.where(syn > 0, "S0", "SF")), index=frame.index)
    flag_column = find_column(lookup, ["flag", "state"])
    if flag_column:
        raw = frame[flag_column].astype(str).str.upper()
        return raw.where(raw.isin(["SF", "S0", "REJ", "RSTO"]), "SF")
    return pd.Series("SF", index=frame.index)


def map_label(value):
    text = clean_name(value)
    if text in {"benign", "normal", "background"}:
        return "normal"
    if "bot" in text or "neris" in text or "rbot" in text or "virut" in text:
        return "botnet"
    if "ddos" in text or "dos" in text or "heartbleed" in text:
        return "dos"
    if "portscan" in text or "port scan" in text or "scan" in text or "recon" in text:
        return "probe"
    if "patator" in text or "brute" in text or "ftp" in text or "ssh" in text:
        return "r2l"
    if "infiltration" in text or "web attack" in text or "xss" in text or "sql" in text:
        return "u2r"
    return "botnet"


def balance_sample(data, max_rows):
    if len(data) <= max_rows:
        return data.sample(frac=1, random_state=42).reset_index(drop=True)
    per_class = max(1, max_rows // data["label"].nunique())
    pieces = []
    for _, group in data.groupby("label"):
        pieces.append(group.sample(n=min(len(group), per_class), random_state=42))
    sampled = pd.concat(pieces)
    if len(sampled) < max_rows:
        remainder = data.drop(sampled.index, errors="ignore")
        if not remainder.empty:
            sampled = pd.concat(
                [sampled, remainder.sample(n=min(len(remainder), max_rows - len(sampled)), random_state=42)],
            )
    return sampled.sample(frac=1, random_state=42).reset_index(drop=True)


if __name__ == "__main__":
    main()
