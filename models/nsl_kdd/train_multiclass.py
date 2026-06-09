import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, RobustScaler


ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "KDDTrain+_20Percent.txt"

COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "outcome",
    "level",
]

DOS = {
    "apache2",
    "back",
    "land",
    "mailbomb",
    "neptune",
    "pod",
    "processtable",
    "smurf",
    "teardrop",
    "udpstorm",
    "worm",
}
PROBE = {"ipsweep", "mscan", "nmap", "portsweep", "saint", "satan"}
R2L = {
    "ftp_write",
    "guess_passwd",
    "httptunnel",
    "imap",
    "multihop",
    "named",
    "phf",
    "sendmail",
    "snmpgetattack",
    "snmpguess",
    "spy",
    "warezclient",
    "warezmaster",
    "xlock",
    "xsnoop",
}
U2R = {
    "buffer_overflow",
    "loadmodule",
    "perl",
    "ps",
    "rootkit",
    "sqlattack",
    "xterm",
}


def attack_family(label):
    if label == "normal":
        return "normal"
    if label in DOS:
        return "dos"
    if label in PROBE:
        return "probe"
    if label in R2L:
        return "r2l"
    if label in U2R:
        return "u2r"
    return "botnet"


def main():
    data = pd.read_csv(DATA_PATH, names=COLUMNS)
    y = data["outcome"].map(attack_family)
    x = data.drop(["outcome", "level"], axis=1)

    cat_cols = ["protocol_type", "service", "flag"]
    num_cols = [col for col in x.columns if col not in cat_cols]

    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    encoded = pd.DataFrame(encoder.fit_transform(x[cat_cols]))
    encoded.columns = encoder.get_feature_names_out(cat_cols)

    scaler = RobustScaler()
    numeric = x[num_cols].copy()
    numeric[num_cols] = scaler.fit_transform(numeric[num_cols])

    prepared = pd.concat([numeric.reset_index(drop=True), encoded.reset_index(drop=True)], axis=1)
    x_train, x_test, y_train, y_test = train_test_split(
        prepared.values,
        y.values,
        test_size=0.2,
        random_state=42,
        stratify=y.values,
    )

    model = RandomForestClassifier(
        n_estimators=160,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)

    joblib.dump(model, ROOT / "rf_multiclass_model.pkl")
    joblib.dump(encoder, ROOT / "multiclass_encoder.pkl")
    joblib.dump(scaler, ROOT / "multiclass_scaler.pkl")
    (ROOT / "multiclass_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"classes": sorted(set(y)), "accuracy": report["accuracy"]}, indent=2))


if __name__ == "__main__":
    main()
