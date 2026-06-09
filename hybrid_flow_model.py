from pathlib import Path
import json
import warnings


warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


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

ATTACK_LABELS = {
    "normal": "Normal Traffic",
    "dos": "DoS Attack",
    "probe": "Probe / Scanning Attack",
    "r2l": "R2L Attack",
    "u2r": "U2R Attack",
    "botnet": "Botnet / Suspicious Traffic",
}

RESPONSE_POLICY = {
    "normal": {"severity": "Low", "action": "Allow traffic", "type": "allow"},
    "dos": {"severity": "Critical", "action": "Block IP temporarily", "type": "block"},
    "probe": {"severity": "High", "action": "Rate-limit and monitor source", "type": "rate_limit"},
    "r2l": {"severity": "High", "action": "Raise credential abuse alert", "type": "alert"},
    "u2r": {"severity": "Critical", "action": "Isolate host and alert admin", "type": "alert"},
    "botnet": {"severity": "High", "action": "Add to suspicious IP list", "type": "suspicious"},
}


class HybridFlowModel:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.available = False
        self.status = "Hybrid botnet-capable flow model not trained"
        self.error = None
        self.metadata = {}
        self.feature_names = []
        self._load()

    def _load(self):
        try:
            import joblib
            import pandas as pd
        except Exception as exc:
            self.error = f"Missing ML dependency: {exc}"
            self.status = "Install requirements.txt to enable hybrid flow model"
            return

        model_path = self.model_dir / "hybrid_flow_model.pkl"
        encoder_path = self.model_dir / "hybrid_flow_encoder.pkl"
        scaler_path = self.model_dir / "hybrid_flow_scaler.pkl"
        metadata_path = self.model_dir / "hybrid_flow_metadata.json"
        if not all(path.exists() for path in [model_path, encoder_path, scaler_path, metadata_path]):
            return

        try:
            self.pd = pd
            self.model = joblib.load(model_path)
            self.encoder = joblib.load(encoder_path)
            self.scaler = joblib.load(scaler_path)
            self.metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            encoded_features = list(self.encoder.get_feature_names_out(CATEGORICAL))
            self.feature_names = FEATURES + encoded_features
            self.available = True
            classes = ", ".join(self.metadata.get("classes", []))
            self.status = f"Hybrid flow Random Forest active ({classes})"
        except Exception as exc:
            self.error = str(exc)
            self.status = "Hybrid flow assets could not be loaded"

    def health(self):
        return {
            "available": self.available,
            "status": self.status,
            "error": self.error,
            "source": str(self.model_dir),
            "classes": self.metadata.get("classes", []),
            "accuracy": self.metadata.get("accuracy"),
            "training_rows": self.metadata.get("training_rows"),
            "label_counts": self.metadata.get("label_counts", {}),
            "dataset_sources": self.metadata.get("dataset_sources", []),
        }

    def predict(self, live_row):
        if not self.available:
            raise RuntimeError(self.status)

        row = self.normalize_live_row(live_row)
        dataframe = self.pd.DataFrame([row], columns=FEATURES + CATEGORICAL)
        transformed = self.preprocess(dataframe)
        values = transformed.values
        label = str(self.model.predict(values)[0])
        probability_values = self.model.predict_proba(values)[0]
        raw_probabilities = {
            str(class_name): float(probability)
            for class_name, probability in zip(self.model.classes_, probability_values)
        }
        label, confidence = self.calibrate(label, raw_probabilities, row)
        probabilities = {
            ATTACK_LABELS[name]: round(raw_probabilities.get(name, 0.0) * 100, 1)
            for name in ATTACK_LABELS
        }
        return {
            "label": label,
            "label_name": ATTACK_LABELS.get(label, label),
            "confidence": round(confidence * 100, 1),
            "probabilities": probabilities,
            "explanation": self.explain(row, transformed),
            "recommended_action": RESPONSE_POLICY.get(label, RESPONSE_POLICY["botnet"]),
            "model_source": "Hybrid Flow Botnet-Capable Random Forest",
        }

    def calibrate(self, label, probabilities, row):
        confidence = probabilities.get(label, 0.0)
        botnet_probability = probabilities.get("botnet", 0.0)
        normal_probability = probabilities.get("normal", 0.0)
        borderline_botnet = (
            label == "normal"
            and botnet_probability >= 0.38
            and normal_probability - botnet_probability <= 0.12
        )
        suspicious_transport = (
            row.get("error_rate", 0) >= 0.4
            or row.get("connection_rate", 0) >= 100
            or row.get("flag") in {"S0", "RSTO", "REJ"}
        )
        if borderline_botnet and suspicious_transport:
            return "botnet", botnet_probability
        return label, confidence

    def preprocess(self, dataframe):
        encoded = self.pd.DataFrame( self.encoder.transform(dataframe[CATEGORICAL]) )
        encoded.columns = self.encoder.get_feature_names_out(CATEGORICAL)
        numeric = dataframe[FEATURES].copy()
        numeric[FEATURES] = self.scaler.transform(numeric[FEATURES])
        return self.pd.concat([numeric.reset_index(drop=True), encoded.reset_index(drop=True)], axis=1)

    def normalize_live_row(self, row):
        normalized = {}
        for feature in FEATURES:
            try:
                normalized[feature] = max(0.0, float(row.get(feature, 0)))
            except (TypeError, ValueError):
                normalized[feature] = 0.0
        normalized["protocol"] = str(row.get("protocol", "tcp")).lower()
        if normalized["protocol"] not in {"tcp", "udp", "icmp"}:
            normalized["protocol"] = "tcp"
        normalized["service"] = str(row.get("service", "http")).lower()
        normalized["flag"] = str(row.get("flag", "SF")).upper()
        return normalized

    def explain(self, row, transformed):
        importances = getattr(self.model, "feature_importances_", None)
        if importances is None:
            importances = [1 / len(transformed.columns)] * len(transformed.columns)

        values = transformed.iloc[0].abs().tolist()
        scored = []
        for feature, importance, value in zip(transformed.columns, importances, values):
            scored.append((feature, float(importance) * (float(value) + 0.15)))
        top = sorted(scored, key=lambda item: item[1], reverse=True)[:4]
        total = sum(score for _, score in top) or 1
        return [
            {
                "feature": feature,
                "contribution": round(score / total * 100),
                "reason": self.reason_text(feature, row),
            }
            for feature, score in top
        ]

    def reason_text(self, feature, row):
        names = {
            "source_bytes": "Source-byte volume matched learned attack flows",
            "destination_bytes": "Destination-byte volume shaped the decision",
            "packet_count": "Packet count matched learned flow behavior",
            "duration": "Flow duration was important for this class",
            "failed_login_count": "Failed login activity raised risk",
            "connection_rate": "Connection rate matched suspicious flow timing",
            "same_host_rate": "Repeated host contact pattern influenced the score",
            "error_rate": "Connection error pattern influenced the score",
        }
        if feature in names:
            return names[feature]
        if feature.startswith("protocol_"):
            return f"Protocol pattern matched {row['protocol'].upper()} traffic"
        if feature.startswith("service_"):
            return f"Service pattern matched {row['service']} traffic"
        if feature.startswith("flag_"):
            return f"TCP flag pattern matched {row['flag']} state"
        return feature
