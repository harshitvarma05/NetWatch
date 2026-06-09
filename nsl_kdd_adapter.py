from pathlib import Path
import warnings


warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


NSL_COLUMNS = [
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
]


class NSLKDDModel:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.available = False
        self.multiclass_available = False
        self.status = "NSL-KDD model not loaded"
        self.error = None
        self.feature_names = []
        self._load()

    def _load(self):
        try:
            import joblib
            import pandas as pd
        except Exception as exc:
            self.error = f"Missing ML dependency: {exc}"
            self.status = "Install requirements.txt to enable imported NSL-KDD model"
            return

        try:
            self.pd = pd
            self.rf_model = joblib.load(self.model_dir / "rf_model.pkl")
            self.dt_model = joblib.load(self.model_dir / "dt_model.pkl")
            self.scaler = joblib.load(self.model_dir / "scaler.pkl")
            self.encoder = joblib.load(self.model_dir / "encoder.pkl")
            self.multiclass_model = None
            self.multiclass_scaler = None
            self.multiclass_encoder = None
            if (self.model_dir / "rf_multiclass_model.pkl").exists():
                self.multiclass_model = joblib.load(self.model_dir / "rf_multiclass_model.pkl")
                self.multiclass_scaler = joblib.load(self.model_dir / "multiclass_scaler.pkl")
                self.multiclass_encoder = joblib.load(self.model_dir / "multiclass_encoder.pkl")
                self.multiclass_available = True
            encoded_features = list(self.encoder.get_feature_names_out(["protocol_type", "service", "flag"]))
            numerical = [name for name in NSL_COLUMNS if name not in {"protocol_type", "service", "flag"}]
            self.feature_names = numerical + encoded_features
            self.available = True
            self.status = "Imported NSL-KDD multiclass Random Forest active" if self.multiclass_available else "Imported NSL-KDD binary Random Forest active"
        except Exception as exc:
            self.error = str(exc)
            self.status = "Imported NSL-KDD assets could not be loaded"

    def health(self):
        return {
            "available": self.available,
            "multiclass": self.multiclass_available,
            "status": self.status,
            "error": self.error,
            "source": "models/nsl_kdd",
        }

    def predict(self, live_row):
        if not self.available:
            raise RuntimeError(self.status)

        nsl_row = self.live_to_nsl(live_row)
        original = dict(nsl_row)
        dataframe = self.pd.DataFrame([nsl_row], columns=NSL_COLUMNS)
        if self.multiclass_available:
            return self.predict_multiclass(dataframe, original)

        transformed = self.preprocess(dataframe)
        values = transformed.values
        rf_prediction = int(self.rf_model.predict(values)[0])
        rf_probabilities = self.rf_model.predict_proba(values)[0]
        attack_probability = float(rf_probabilities[1]) if len(rf_probabilities) > 1 else float(rf_prediction)
        normal_probability = 1.0 - attack_probability

        if rf_prediction == 0:
            label = "normal"
            confidence = normal_probability
        else:
            label = self.attack_family(original)
            confidence = attack_probability

        probabilities = self.family_probabilities(label, normal_probability, attack_probability)
        return {
            "label": label,
            "label_name": self.label_name(label),
            "confidence": round(confidence * 100, 1),
            "probabilities": probabilities,
            "explanation": self.explain(original, transformed),
            "recommended_action": self.response_policy(label),
            "model_source": "Imported NSL-KDD Random Forest",
        }

    def predict_multiclass(self, dataframe, original):
        transformed = self.preprocess(
            dataframe,
            encoder=self.multiclass_encoder,
            scaler=self.multiclass_scaler,
        )
        values = transformed.values
        label = str(self.multiclass_model.predict(values)[0])
        probability_values = self.multiclass_model.predict_proba(values)[0]
        class_probabilities = {
            str(class_name): float(probability)
            for class_name, probability in zip(self.multiclass_model.classes_, probability_values)
        }
        confidence = class_probabilities.get(label, 0.0)
        probabilities = {
            self.label_name(name): round(class_probabilities.get(name, 0.0) * 100, 1)
            for name in ["normal", "dos", "probe", "r2l", "u2r", "botnet"]
        }
        return {
            "label": label,
            "label_name": self.label_name(label),
            "confidence": round(confidence * 100, 1),
            "probabilities": probabilities,
            "explanation": self.explain(original, transformed),
            "recommended_action": self.response_policy(label),
            "model_source": "Imported NSL-KDD Multiclass Random Forest",
        }

    def preprocess(self, dataframe, encoder=None, scaler=None):
        encoder = encoder or self.encoder
        scaler = scaler or self.scaler
        cat_cols = ["protocol_type", "service", "flag"]
        num_cols = [col for col in dataframe.columns if col not in cat_cols]
        encoded = self.pd.DataFrame(encoder.transform(dataframe[cat_cols]))
        encoded.columns = encoder.get_feature_names_out(cat_cols)
        dataframe = dataframe.drop(cat_cols, axis=1).reset_index(drop=True)
        dataframe[num_cols] = scaler.transform(dataframe[num_cols])
        return self.pd.concat([dataframe, encoded], axis=1)

    def live_to_nsl(self, row):
        packet_count = max(1, int(float(row.get("packet_count", 1))))
        connection_rate = max(0.0, float(row.get("connection_rate", 0)))
        same_host_rate = max(0.0, min(1.0, float(row.get("same_host_rate", 0))))
        error_rate = max(0.0, min(1.0, float(row.get("error_rate", 0))))
        service = row.get("service", "http")
        if service not in self.known_services():
            service = "http"
        flag = row.get("flag", "SF")
        if flag not in self.known_flags():
            flag = "SF"
        protocol = row.get("protocol", "tcp")
        if protocol not in {"tcp", "udp", "icmp"}:
            protocol = "tcp"

        return {
            "duration": max(0.0, float(row.get("duration", 0))),
            "protocol_type": protocol,
            "service": service,
            "flag": flag,
            "src_bytes": max(0, int(float(row.get("source_bytes", 0)))),
            "dst_bytes": max(0, int(float(row.get("destination_bytes", 0)))),
            "land": 1 if row.get("source_ip") == row.get("destination_ip") else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": max(0, int(float(row.get("failed_login_count", 0)))),
            "logged_in": 1 if flag == "SF" else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": min(511, max(packet_count, int(connection_rate * 8))),
            "srv_count": min(511, max(1, packet_count)),
            "serror_rate": error_rate if flag == "S0" else 0.0,
            "srv_serror_rate": error_rate if flag == "S0" else 0.0,
            "rerror_rate": error_rate if flag in {"REJ", "RSTO"} else 0.0,
            "srv_rerror_rate": error_rate if flag in {"REJ", "RSTO"} else 0.0,
            "same_srv_rate": same_host_rate or 0.1,
            "diff_srv_rate": max(0.0, 1.0 - same_host_rate),
            "srv_diff_host_rate": max(0.0, 1.0 - same_host_rate) * 0.5,
            "dst_host_count": min(255, max(1, int(connection_rate * 10) or packet_count)),
            "dst_host_srv_count": min(255, max(1, int(packet_count * same_host_rate) or 1)),
            "dst_host_same_srv_rate": same_host_rate,
            "dst_host_diff_srv_rate": max(0.0, 1.0 - same_host_rate),
            "dst_host_same_src_port_rate": same_host_rate,
            "dst_host_srv_diff_host_rate": max(0.0, 1.0 - same_host_rate) * 0.4,
            "dst_host_serror_rate": error_rate if flag == "S0" else 0.0,
            "dst_host_srv_serror_rate": error_rate if flag == "S0" else 0.0,
            "dst_host_rerror_rate": error_rate if flag in {"REJ", "RSTO"} else 0.0,
            "dst_host_srv_rerror_rate": error_rate if flag in {"REJ", "RSTO"} else 0.0,
        }

    def known_services(self):
        return {
            value.split("service_", 1)[1]
            for value in self.encoder.get_feature_names_out(["protocol_type", "service", "flag"])
            if value.startswith("service_")
        }

    def known_flags(self):
        return {
            value.split("flag_", 1)[1]
            for value in self.encoder.get_feature_names_out(["protocol_type", "service", "flag"])
            if value.startswith("flag_")
        }

    def attack_family(self, row):
        if row["count"] > 90 or row["serror_rate"] > 0.55 or row["dst_host_serror_rate"] > 0.55:
            return "dos"
        if row["rerror_rate"] > 0.35 or row["diff_srv_rate"] > 0.65:
            return "probe"
        if row["num_failed_logins"] >= 3:
            return "r2l"
        if row["root_shell"] or row["su_attempted"] or row["num_root"]:
            return "u2r"
        return "botnet"

    def family_probabilities(self, label, normal_probability, attack_probability):
        labels = ["normal", "dos", "probe", "r2l", "u2r", "botnet"]
        values = {name: 0.0 for name in labels}
        values["normal"] = normal_probability
        if label == "normal":
            remainder = max(0.0, 1.0 - normal_probability)
            for name in labels[1:]:
                values[name] = remainder / 5
        else:
            values[label] = attack_probability
            remainder = max(0.0, 1.0 - normal_probability - attack_probability)
            for name in labels[1:]:
                if name != label:
                    values[name] = remainder / 4
        return {self.label_name(name): round(values[name] * 100, 1) for name in labels}

    def explain(self, original, transformed):
        reasons = []
        candidates = [
            ("count", original["count"], "Connection count in recent window"),
            ("src_bytes", original["src_bytes"], "Source bytes transferred"),
            ("dst_bytes", original["dst_bytes"], "Destination bytes transferred"),
            ("serror_rate", original["serror_rate"], "SYN error rate"),
            ("rerror_rate", original["rerror_rate"], "Rejected connection rate"),
            ("dst_host_same_src_port_rate", original["dst_host_same_src_port_rate"], "Repeated source-port pattern"),
            ("num_failed_logins", original["num_failed_logins"], "Failed login attempts"),
            ("duration", original["duration"], "Connection duration"),
        ]
        for feature, value, reason in candidates:
            score = abs(float(value))
            if feature in {"serror_rate", "rerror_rate", "dst_host_same_src_port_rate"}:
                score *= 120
            elif feature == "duration":
                score = 40 / (1 + score)
            elif feature == "num_failed_logins":
                score *= 50
            reasons.append((feature, score, reason))

        top = sorted(reasons, key=lambda item: item[1], reverse=True)[:4]
        total = sum(item[1] for item in top) or 1
        return [
            {
                "feature": feature,
                "contribution": round(score / total * 100),
                "reason": reason,
            }
            for feature, score, reason in top
        ]

    def label_name(self, label):
        return {
            "normal": "Normal Traffic",
            "dos": "DoS Attack",
            "probe": "Probe / Scanning Attack",
            "r2l": "R2L Attack",
            "u2r": "U2R Attack",
            "botnet": "Botnet / Suspicious Traffic",
        }[label]

    def response_policy(self, label):
        return {
            "normal": {"severity": "Low", "action": "Allow traffic", "type": "allow"},
            "dos": {"severity": "Critical", "action": "Block IP temporarily", "type": "block"},
            "probe": {"severity": "High", "action": "Rate-limit and monitor source", "type": "rate_limit"},
            "r2l": {"severity": "High", "action": "Raise credential abuse alert", "type": "alert"},
            "u2r": {"severity": "Critical", "action": "Isolate host and alert admin", "type": "alert"},
            "botnet": {"severity": "High", "action": "Add to suspicious IP list", "type": "suspicious"},
        }[label]
