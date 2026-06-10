from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import atexit
import csv
import io
import ipaddress
import json
import math
import os
import random
import re
import secrets
import select
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, pstdev
from urllib.parse import urlparse

from hybrid_flow_model import HybridFlowModel
from nsl_kdd_adapter import NSLKDDModel


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

PORT_SERVICES = {
    "20": "ftp",
    "21": "ftp",
    "22": "ssh",
    "25": "smtp",
    "53": "dns",
    "80": "http",
    "110": "smtp",
    "143": "smtp",
    "443": "https",
    "465": "smtp",
    "587": "smtp",
    "993": "smtp",
    "995": "smtp",
}

DEMO_CASES = [
    {
        "name": "Normal web flow",
        "key": "normal",
        "record": {
            "source_ip": "10.10.1.12",
            "destination_ip": "172.217.166.4",
            "source_bytes": 6448,
            "destination_bytes": 1152,
            "packet_count": 48,
            "duration": 112.74069,
            "failed_login_count": 0,
            "connection_rate": 0.425755776,
            "same_host_rate": 0,
            "error_rate": 0,
            "protocol": "tcp",
            "service": "http",
            "flag": "SF",
        },
    },
    {
        "name": "DoS reset flow",
        "key": "dos",
        "record": {
            "source_ip": "203.0.113.45",
            "destination_ip": "10.10.1.20",
            "source_bytes": 20,
            "destination_bytes": 11595,
            "packet_count": 14,
            "duration": 9.157589,
            "failed_login_count": 0,
            "connection_rate": 1.528786671,
            "same_host_rate": 0,
            "error_rate": 0.21428571428571427,
            "protocol": "tcp",
            "service": "http",
            "flag": "RSTO",
        },
    },
    {
        "name": "Probe scan flow",
        "key": "probe",
        "record": {
            "source_ip": "198.51.100.72",
            "destination_ip": "10.10.1.30",
            "source_bytes": 0,
            "destination_bytes": 0,
            "packet_count": 2,
            "duration": 0.000124,
            "failed_login_count": 0,
            "connection_rate": 16129.03226,
            "same_host_rate": 0,
            "error_rate": 0,
            "protocol": "icmp",
            "service": "http",
            "flag": "SF",
        },
    },
    {
        "name": "Botnet C2 flow",
        "key": "botnet",
        "record": {
            "source_ip": "185.44.77.10",
            "destination_ip": "10.10.1.40",
            "source_bytes": 196,
            "destination_bytes": 128,
            "packet_count": 9,
            "duration": 0.081379,
            "failed_login_count": 0,
            "connection_rate": 110.5936421,
            "same_host_rate": 0,
            "error_rate": 0.2222222222222222,
            "protocol": "tcp",
            "service": "http",
            "flag": "S0",
        },
    },
    {
        "name": "R2L login abuse",
        "key": "r2l",
        "record": {
            "source_ip": "172.16.9.55",
            "destination_ip": "10.10.1.50",
            "source_bytes": 420,
            "destination_bytes": 690,
            "packet_count": 38,
            "duration": 15,
            "failed_login_count": 9,
            "connection_rate": 10,
            "same_host_rate": 0.42,
            "error_rate": 0.25,
            "protocol": "tcp",
            "service": "ssh",
            "flag": "REJ",
        },
    },
]


def clamp(value, low, high):
    return max(low, min(high, value))


def normalish(mu, sigma, low=0, high=None):
    value = random.gauss(mu, sigma)
    if high is None:
        return max(low, value)
    return clamp(value, low, high)


def build_record(label, idx):
    ip_pool = {
        "normal": "10.0.0.",
        "dos": "203.0.113.",
        "probe": "198.51.100.",
        "r2l": "172.16.9.",
        "u2r": "192.0.2.",
        "botnet": "185.44.77.",
    }
    protocol = random.choices(["tcp", "udp", "icmp"], weights=[0.72, 0.2, 0.08])[0]
    service = random.choice(["http", "https", "dns", "ssh", "ftp", "smtp"])
    flag = random.choice(["SF", "S0", "REJ", "RSTO"])

    if label == "normal":
        values = dict(
            source_bytes=normalish(850, 260),
            destination_bytes=normalish(1250, 350),
            packet_count=normalish(28, 10),
            duration=normalish(7.5, 3.0, 0.2),
            failed_login_count=normalish(0.2, 0.5, 0, 2),
            connection_rate=normalish(4.5, 2.0, 0, 18),
            same_host_rate=normalish(0.22, 0.12, 0, 1),
            error_rate=normalish(0.04, 0.04, 0, 0.22),
        )
        flag = random.choices(["SF", "S0", "REJ"], weights=[0.86, 0.08, 0.06])[0]
    elif label == "dos":
        values = dict(
            source_bytes=normalish(9000, 2300),
            destination_bytes=normalish(260, 120),
            packet_count=normalish(820, 210),
            duration=normalish(0.85, 0.45, 0.05, 3),
            failed_login_count=normalish(0, 0.2, 0, 1),
            connection_rate=normalish(120, 30, 35, 240),
            same_host_rate=normalish(0.88, 0.08, 0.55, 1),
            error_rate=normalish(0.18, 0.12, 0, 0.6),
        )
        service = random.choice(["http", "https", "dns"])
        flag = random.choices(["S0", "REJ", "RSTO"], weights=[0.55, 0.25, 0.2])[0]
    elif label == "probe":
        values = dict(
            source_bytes=normalish(500, 160),
            destination_bytes=normalish(220, 110),
            packet_count=normalish(95, 35),
            duration=normalish(2.2, 1.2, 0.1, 7),
            failed_login_count=normalish(0.4, 0.7, 0, 3),
            connection_rate=normalish(64, 18, 20, 130),
            same_host_rate=normalish(0.34, 0.18, 0, 0.78),
            error_rate=normalish(0.46, 0.16, 0.15, 0.9),
        )
        service = random.choice(["ssh", "ftp", "smtp", "dns"])
        flag = random.choices(["REJ", "S0", "RSTO"], weights=[0.5, 0.3, 0.2])[0]
    elif label == "r2l":
        values = dict(
            source_bytes=normalish(420, 160),
            destination_bytes=normalish(690, 260),
            packet_count=normalish(38, 16),
            duration=normalish(15, 6, 1, 35),
            failed_login_count=normalish(8, 3, 2, 18),
            connection_rate=normalish(10, 5, 0, 30),
            same_host_rate=normalish(0.42, 0.16, 0.1, 0.82),
            error_rate=normalish(0.25, 0.12, 0, 0.65),
        )
        service = random.choice(["ssh", "ftp", "smtp"])
        flag = random.choices(["SF", "REJ"], weights=[0.55, 0.45])[0]
    elif label == "u2r":
        values = dict(
            source_bytes=normalish(180, 90),
            destination_bytes=normalish(3900, 900),
            packet_count=normalish(18, 8),
            duration=normalish(26, 9, 3, 60),
            failed_login_count=normalish(1.5, 1.2, 0, 6),
            connection_rate=normalish(3, 2, 0, 12),
            same_host_rate=normalish(0.18, 0.1, 0, 0.45),
            error_rate=normalish(0.08, 0.07, 0, 0.35),
        )
        service = random.choice(["ssh", "ftp"])
        flag = "SF"
    else:
        values = dict(
            source_bytes=normalish(2600, 850),
            destination_bytes=normalish(920, 330),
            packet_count=normalish(135, 45),
            duration=normalish(4, 2, 0.2, 12),
            failed_login_count=normalish(1.4, 1.1, 0, 6),
            connection_rate=normalish(38, 13, 10, 90),
            same_host_rate=normalish(0.68, 0.13, 0.3, 0.95),
            error_rate=normalish(0.22, 0.12, 0, 0.58),
        )
        service = random.choice(["http", "https", "dns", "smtp"])
        flag = random.choices(["SF", "S0", "RSTO"], weights=[0.45, 0.35, 0.2])[0]

    record = {key: round(value, 3) for key, value in values.items()}
    record.update(
        {
            "source_ip": f"{ip_pool[label]}{(idx % 230) + 10}",
            "destination_ip": f"10.10.{idx % 20}.{(idx % 200) + 20}",
            "protocol": protocol,
            "service": service,
            "flag": flag,
            "actual_label": label,
        }
    )
    return record


class ExplainableIDSModel:
    def __init__(self):
        random.seed(42)
        self.training_data = []
        self.labels = list(ATTACK_LABELS.keys())
        self.means = {}
        self.stds = {}
        self.centroids = {}
        self.category_values = defaultdict(set)
        self.feature_names = []
        self._train()

    def _generate_training_data(self):
        weights = {
            "normal": 900,
            "dos": 230,
            "probe": 170,
            "r2l": 95,
            "u2r": 65,
            "botnet": 140,
        }
        rows = []
        idx = 0
        for label, count in weights.items():
            for _ in range(count):
                rows.append(build_record(label, idx))
                idx += 1
        random.shuffle(rows)
        return rows

    def _train(self):
        self.training_data = self._generate_training_data()
        for feature in FEATURES:
            values = [row[feature] for row in self.training_data]
            self.means[feature] = mean(values)
            self.stds[feature] = pstdev(values) or 1
            self.feature_names.append(feature)
        for row in self.training_data:
            for feature in CATEGORICAL:
                self.category_values[feature].add(row[feature])
        for feature in CATEGORICAL:
            for value in sorted(self.category_values[feature]):
                self.feature_names.append(f"{feature}={value}")

        vectors_by_label = defaultdict(list)
        for row in self.training_data:
            vectors_by_label[row["actual_label"]].append(self.vectorize(row))
        for label, vectors in vectors_by_label.items():
            self.centroids[label] = [
                mean([vector[i] for vector in vectors]) for i in range(len(self.feature_names))
            ]

    def vectorize(self, row):
        vector = []
        for feature in FEATURES:
            value = float(row.get(feature, 0))
            vector.append((value - self.means[feature]) / self.stds[feature])
        for feature in CATEGORICAL:
            actual = row.get(feature, "")
            for value in sorted(self.category_values[feature]):
                vector.append(1.0 if actual == value else 0.0)
        return vector

    def predict(self, row):
        vector = self.vectorize(row)
        distances = {}
        for label, centroid in self.centroids.items():
            distances[label] = math.sqrt(sum((a - b) ** 2 for a, b in zip(vector, centroid)))
        nearest = min(distances, key=distances.get)
        scores = {label: math.exp(-distance) for label, distance in distances.items()}
        total = sum(scores.values()) or 1
        probabilities = {label: score / total for label, score in scores.items()}
        confidence = probabilities[nearest]
        nearest, confidence, probabilities = self.calibrate(row, nearest, confidence, probabilities)
        return {
            "label": nearest,
            "label_name": ATTACK_LABELS[nearest],
            "confidence": round(confidence * 100, 1),
            "probabilities": {
                ATTACK_LABELS[label]: round(prob * 100, 1)
                for label, prob in sorted(probabilities.items(), key=lambda item: item[1], reverse=True)
            },
            "explanation": self.explain(row, vector, nearest),
            "recommended_action": RESPONSE_POLICY[nearest],
        }

    def calibrate(self, row, nearest, confidence, probabilities):
        packet_count = float(row.get("packet_count", 0))
        source_bytes = float(row.get("source_bytes", 0))
        duration = float(row.get("duration", 0))
        connection_rate = float(row.get("connection_rate", 0))
        same_host_rate = float(row.get("same_host_rate", 0))
        error_rate = float(row.get("error_rate", 0))
        failed_login_count = float(row.get("failed_login_count", 0))

        benign_small_flow = (
            packet_count <= 4
            and source_bytes < 1200
            and error_rate < 0.18
            and failed_login_count == 0
            and connection_rate < 30
        )
        strong_dos = packet_count > 250 or connection_rate > 75 or (duration < 1 and same_host_rate > 0.75)
        strong_probe = error_rate > 0.35 or connection_rate > 45
        strong_login_abuse = failed_login_count >= 4
        strong_botnet = source_bytes > 2200 and same_host_rate > 0.55

        attack_supported = strong_dos or strong_probe or strong_login_abuse or strong_botnet
        if nearest != "normal" and (benign_small_flow or (confidence < 0.58 and not attack_supported)):
            probabilities = dict(probabilities)
            probabilities["normal"] = max(probabilities.get("normal", 0), 0.62)
            leftover = max(0.0, 1.0 - probabilities["normal"])
            attack_labels = [label for label in probabilities if label != "normal"]
            attack_total = sum(probabilities[label] for label in attack_labels) or 1
            for label in attack_labels:
                probabilities[label] = probabilities[label] / attack_total * leftover
            return "normal", probabilities["normal"], probabilities

        if nearest == "dos" and not strong_dos and confidence < 0.7:
            return "probe" if strong_probe else "normal", max(confidence, 0.6), probabilities
        return nearest, confidence, probabilities

    def explain(self, row, vector, label):
        normal_centroid = self.centroids["normal"]
        target_centroid = self.centroids[label]
        raw_contributions = []

        for index, feature_name in enumerate(self.feature_names):
            evidence = abs(vector[index] - normal_centroid[index])
            alignment = abs(target_centroid[index] - normal_centroid[index]) + 0.15
            raw_contributions.append((feature_name, evidence * alignment))

        top = sorted(raw_contributions, key=lambda item: item[1], reverse=True)[:4]
        total = sum(value for _, value in top) or 1
        explanation = []
        for feature_name, value in top:
            percent = round((value / total) * 79 + 6)
            explanation.append(
                {
                    "feature": feature_name,
                    "contribution": percent,
                    "reason": self.reason_text(feature_name, row, label),
                }
            )
        return explanation

    def reason_text(self, feature_name, row, label):
        display = {
            "source_bytes": "Abnormal source bytes",
            "destination_bytes": "Unusual destination bytes",
            "packet_count": "High packet rate",
            "duration": "Low duration" if row.get("duration", 0) < 3 else "Long session duration",
            "failed_login_count": "Repeated failed logins",
            "connection_rate": "High connection rate",
            "same_host_rate": "Same destination host repeatedly contacted",
            "error_rate": "High error or rejection rate",
        }
        if feature_name in display:
            return display[feature_name]
        if feature_name.startswith("service="):
            return f"Service pattern matched {label.upper()} behavior"
        if feature_name.startswith("flag="):
            return "TCP flag pattern indicated suspicious connection state"
        if feature_name.startswith("protocol="):
            return "Protocol choice matched known attack pattern"
        return feature_name


class LiveTrafficCollector:
    def __init__(self):
        self.first_seen = {}
        self.previous_total_bytes = None
        self.previous_sample_time = None
        self.root = Path(__file__).resolve().parent
        self.collector_source = self.root / "collector" / "live_collector.cpp"
        binary_name = "live_collector.exe" if os.name == "nt" else "live_collector"
        self.collector_binary = self.root / "collector" / binary_name
        self.platform = "windows" if os.name == "nt" else "unix"
        self.mode = "initializing"
        self.status = "Collector not started"
        self.last_error = None
        self.process = None
        self.process_lock = threading.Lock()
        self.started_at = None
        self.cpp_retry_after = 0
        self.latest_packets = []
        self.capture_seconds = os.environ.get("IDS_CAPTURE_SECONDS", "1")
        self.capture_device = os.environ.get("IDS_CAPTURE_DEVICE", "")
        atexit.register(self.stop)

    def configure(self, capture_seconds=None, capture_device=None):
        changed = False
        if capture_seconds is not None and str(capture_seconds) != str(self.capture_seconds):
            self.capture_seconds = str(capture_seconds)
            changed = True
        if capture_device is not None and str(capture_device) != str(self.capture_device):
            self.capture_device = str(capture_device)
            changed = True
        if changed:
            self.stop()

    def collect(self):
        pcap_records = self._collect_with_cpp()
        if pcap_records:
            self.mode = "pcap"
            self.status = f"C++ packet collector active ({len(pcap_records)} flows)"
            self.last_error = None
            return pcap_records
        if pcap_records == []:
            self.last_error = None

        now = time.time()
        connections = self._read_connections()
        total_bytes = self._read_interface_bytes()
        elapsed = max(1.0, now - self.previous_sample_time) if self.previous_sample_time else 1.0
        byte_delta = 0
        if total_bytes is not None and self.previous_total_bytes is not None:
            byte_delta = max(0, total_bytes - self.previous_total_bytes)
        self.previous_total_bytes = total_bytes
        self.previous_sample_time = now

        active = [
            item
            for item in connections
            if self._is_useful_connection(item)
        ]
        total_active = max(1, len(active))
        host_counts = Counter(item["remote_ip"] for item in active)
        error_count = sum(1 for item in active if item["flag"] != "SF")
        connection_rate = round(len(active) / elapsed, 3)
        bytes_per_connection = byte_delta / total_active if byte_delta else 0

        records = []
        for item in active:
            key = f"{item['protocol']}:{item['local_ip']}:{item['local_port']}->{item['remote_ip']}:{item['remote_port']}"
            self.first_seen.setdefault(key, now)
            duration = max(0.1, now - self.first_seen[key])
            source_bytes = max(64, bytes_per_connection * 0.58)
            destination_bytes = max(64, bytes_per_connection * 0.42)
            packet_count = max(1, round((source_bytes + destination_bytes) / 900))
            records.append(
                {
                    "source_ip": item["remote_ip"],
                    "destination_ip": item["local_ip"],
                    "source_bytes": round(source_bytes, 3),
                    "destination_bytes": round(destination_bytes, 3),
                    "packet_count": packet_count,
                    "duration": round(duration, 3),
                    "protocol": item["protocol"],
                    "service": self._service_name(item["remote_port"], item["local_port"]),
                    "flag": item["flag"],
                    "failed_login_count": 0,
                    "connection_rate": connection_rate,
                    "same_host_rate": round(host_counts[item["remote_ip"]] / total_active, 3),
                    "error_rate": round(error_count / total_active, 3),
                    "source": "os-fallback",
                }
            )
        self.mode = "pcap-context" if pcap_records == [] else "os-fallback"
        if records:
            detail = "C++ stream idle; showing filtered OS connection context"
            if pcap_records is None:
                detail = "C++ packet capture unavailable; using filtered OS connections"
            self.status = f"{detail} ({len(records)} flows)"
        else:
            self.status = "C++ stream idle; no useful external flows visible" if pcap_records == [] else "No live flows visible to fallback collector"
        return records

    def health(self):
        return {
            "mode": self.mode,
            "status": self.status,
            "last_error": self.last_error,
            "collector_binary": str(self.collector_binary),
            "collector_source": str(self.collector_source),
            "streaming": self.process is not None and self.process.poll() is None,
            "uptime_seconds": round(time.time() - self.started_at) if self.started_at else 0,
            "packet_rows": len(self.latest_packets),
            "platform": self.platform,
        }

    def _collect_with_cpp(self):
        if not self._ensure_cpp_collector():
            return None
        with self.process_lock:
            if not self._ensure_stream_process():
                return None
            line = self._read_stream_line()
            if line is None:
                return []
            payload = json.loads(line)
            device = payload.get("device", "")
            flows = payload.get("flows", [])
            packets = payload.get("packets", [])
            for flow in flows:
                flow["collector_device"] = device
            clean_packets = []
            for packet in packets:
                packet = dict(packet)
                packet["collector_device"] = device
                clean_packets.append(packet)
            if clean_packets:
                self.latest_packets = (self.latest_packets + clean_packets)[-1000:]
            return flows

    def _ensure_stream_process(self):
        if self.process is not None and self.process.poll() is None:
            return True
        if time.time() < self.cpp_retry_after:
            return False
        self.stop()
        try:
            command = [
                str(self.collector_binary),
                "--stream",
                "--duration",
                str(self.capture_seconds),
            ]
            if self.capture_device:
                command.extend(["--device", self.capture_device])
            self.process = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
            )
            self.started_at = time.time()
            self.mode = "pcap"
            self.status = "C++ packet collector stream starting"
            return True
        except OSError as exc:
            self.last_error = str(exc)
            self.cpp_retry_after = time.time() + 20
            return False

    def _read_stream_line(self):
        if not self.process or not self.process.stdout:
            return None
        if os.name == "nt":
            line = self.process.stdout.readline()
        else:
            ready, _, _ = select.select([self.process.stdout], [], [], 1.6)
            if not ready:
                if self.process.poll() is not None:
                    self.last_error = self._collector_stderr()
                    self.cpp_retry_after = time.time() + 20
                    self.stop()
                    return None
                self.status = "C++ packet collector running; waiting for next flow window"
                return None
            line = self.process.stdout.readline()
        if not line:
            self.last_error = self._collector_stderr()
            self.cpp_retry_after = time.time() + 20
            self.stop()
            return None
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            self.last_error = f"Invalid collector JSON: {exc}"
            return None
        return line

    def _collector_stderr(self):
        if not self.process or not self.process.stderr:
            return "Collector stopped"
        try:
            ready, _, _ = select.select([self.process.stderr], [], [], 0)
            if ready:
                return self.process.stderr.read().strip() or "Collector stopped"
        except OSError:
            pass
        return "Collector stopped"

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        self.started_at = None

    def _ensure_cpp_collector(self):
        if not self.collector_source.exists():
            self.last_error = "collector/live_collector.cpp is missing"
            return False
        if self.collector_binary.exists() and self.collector_binary.stat().st_mtime >= self.collector_source.stat().st_mtime:
            return True
        command = self._collector_build_command()
        if not command:
            if os.name == "nt":
                self.last_error = "Npcap SDK/compiler not configured; using Windows OS connection fallback"
            else:
                self.last_error = "C++ compiler or libpcap not available; using OS connection fallback"
            return False
        try:
            subprocess.check_output(
                command,
                text=True,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = str(exc)
            return False

    def _collector_build_command(self):
        if os.name != "nt":
            compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
            if not compiler:
                return None
            return [
                compiler,
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                str(self.collector_source),
                "-lpcap",
                "-o",
                str(self.collector_binary),
            ]

        npcap_sdk = os.environ.get("NPCAP_SDK") or os.environ.get("NPCAP_SDK_DIR")
        if not npcap_sdk:
            candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Npcap" / "SDK"
            if candidate.exists():
                npcap_sdk = str(candidate)
        if not npcap_sdk:
            return None
        sdk = Path(npcap_sdk)
        include_dir = sdk / "Include"
        arch = "x64" if os.environ.get("PROCESSOR_ARCHITECTURE", "").endswith("64") else ""
        lib_dir = sdk / "Lib" / arch if arch else sdk / "Lib"
        if not lib_dir.exists():
            lib_dir = sdk / "Lib"

        cl = shutil.which("cl")
        if cl:
            return [
                cl,
                "/EHsc",
                "/std:c++17",
                "/O2",
                f"/I{include_dir}",
                str(self.collector_source),
                "/link",
                f"/LIBPATH:{lib_dir}",
                "wpcap.lib",
                "Packet.lib",
                "Ws2_32.lib",
                f"/OUT:{self.collector_binary}",
            ]

        gxx = shutil.which("g++") or shutil.which("clang++")
        if gxx:
            return [
                gxx,
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                f"-I{include_dir}",
                str(self.collector_source),
                f"-L{lib_dir}",
                "-lwpcap",
                "-lPacket",
                "-lws2_32",
                "-o",
                str(self.collector_binary),
            ]
        return None

    def _read_connections(self):
        if os.name == "nt":
            return self._read_windows_connections()
        try:
            output = subprocess.check_output(
                ["netstat", "-an"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            return []

        records = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            protocol = parts[0].lower()
            if not protocol.startswith(("tcp", "udp")):
                continue
            local_ip, local_port = self._split_endpoint(parts[3])
            remote_ip, remote_port = self._split_endpoint(parts[4] if len(parts) > 4 else "")
            state = parts[5] if protocol.startswith("tcp") and len(parts) > 5 else "ESTABLISHED"
            records.append(
                {
                    "protocol": "tcp" if protocol.startswith("tcp") else "udp",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "flag": self._tcp_flag(state, protocol),
                }
            )
        return records

    def _read_interface_bytes(self):
        if os.name == "nt":
            return self._read_windows_interface_bytes()
        try:
            output = subprocess.check_output(
                ["netstat", "-ibn"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            return None

        best_total = 0
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 10 or parts[0].startswith(("lo", "gif", "stf")):
                continue
            numeric = [int(value) for value in parts if value.isdigit()]
            if len(numeric) >= 4:
                best_total = max(best_total, numeric[-4] + numeric[-1])
        return best_total or None


    def _powershell_command(self):
        return shutil.which("powershell") or shutil.which("pwsh") or "powershell"

    def _read_windows_connections(self):
        script = """
$rows = Get-NetTCPConnection -ErrorAction SilentlyContinue |
  Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','*') -and $_.RemotePort -ne 0 } |
  Select-Object @{Name='protocol';Expression={'tcp'}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State
$rows | ConvertTo-Json -Compress
"""
        try:
            output = subprocess.check_output(
                [self._powershell_command(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=4,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            return []
        if not output:
            return []
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, dict):
            parsed = [parsed]
        records = []
        for item in parsed or []:
            local_ip = str(item.get("LocalAddress", ""))
            remote_ip = str(item.get("RemoteAddress", ""))
            local_port = str(item.get("LocalPort", "0") or "0")
            remote_port = str(item.get("RemotePort", "0") or "0")
            records.append(
                {
                    "protocol": "tcp",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "flag": self._tcp_flag(str(item.get("State", "ESTABLISHED")), "tcp"),
                }
            )
        return records

    def _read_windows_interface_bytes(self):
        script = """
$stats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
$rx = ($stats | Measure-Object -Property ReceivedBytes -Sum).Sum
$tx = ($stats | Measure-Object -Property SentBytes -Sum).Sum
[pscustomobject]@{bytes=[int64]($rx + $tx)} | ConvertTo-Json -Compress
"""
        try:
            output = subprocess.check_output(
                [self._powershell_command(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=4,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            parsed = json.loads(output)
            return int(parsed.get("bytes", 0)) or None
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def _split_endpoint(self, endpoint):
        if not endpoint or endpoint in {"*.*", "*"}:
            return "*", "0"
        endpoint = endpoint.strip("[]")
        if "." not in endpoint:
            return endpoint, "0"
        host, port = endpoint.rsplit(".", 1)
        host = re.sub(r"^::ffff:", "", host)
        return host or "*", port if port.isdigit() else "0"

    def _is_useful_connection(self, item):
        remote_ip = item.get("remote_ip", "")
        local_ip = item.get("local_ip", "")
        remote_port = item.get("remote_port", "0")
        if self._is_noise_address(remote_ip) or self._is_noise_address(local_ip):
            return False
        if remote_port == "0":
            return False
        return True

    def _is_noise_address(self, address):
        if not address:
            return True
        address = address.strip().strip("[]")
        address = address.split("%", 1)[0]
        if address in {"*", "*.*", "localhost"}:
            return True
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return True
        return (
            parsed.is_unspecified
            or parsed.is_loopback
            or parsed.is_multicast
            or parsed.is_link_local
            or parsed.is_reserved
        )

    def _service_name(self, remote_port, local_port):
        return PORT_SERVICES.get(remote_port) or PORT_SERVICES.get(local_port) or "http"

    def _tcp_flag(self, state, protocol):
        if protocol.startswith("udp"):
            return "SF"
        state = state.upper()
        if state in {"ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2"}:
            return "SF"
        if state in {"SYN_SENT", "SYN_RECEIVED", "LISTEN"}:
            return "S0"
        if state in {"CLOSED", "CLOSING", "LAST_ACK", "TIME_WAIT"}:
            return "RSTO"
        return "REJ"


class Storage:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    record_json TEXT NOT NULL,
                    prediction_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS defense_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    label TEXT NOT NULL,
                    action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    type TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

    def save_predictions(self, rows, predictions):
        if not rows:
            return
        now = time.time()
        with self.lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO predictions (
                    created_at, source_ip, destination_ip, label, confidence, record_json, prediction_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        now,
                        row.get("source_ip", ""),
                        row.get("destination_ip", ""),
                        result.get("label", ""),
                        float(result.get("confidence", 0) or 0),
                        json.dumps(row),
                        json.dumps(result),
                    )
                    for row, result in zip(rows, predictions)
                ],
            )

    def recent_predictions(self, limit=5000):
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT record_json, prediction_json
                FROM predictions
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        parsed = [(json.loads(record), json.loads(prediction)) for record, prediction in reversed(rows)]
        return parsed

    def save_defense(self, entry):
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO defense_actions (created_at, source_ip, label, action, severity, type)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["timestamp"],
                    entry["source_ip"],
                    entry["label"],
                    entry["action"],
                    entry["severity"],
                    entry["type"],
                ),
            )

    def defense_entries(self):
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT created_at, source_ip, label, action, severity, type
                FROM defense_actions
                ORDER BY id ASC
                """
            ).fetchall()
        return [
            {
                "timestamp": created_at,
                "source_ip": source_ip,
                "label": label,
                "action": action,
                "severity": severity,
                "type": action_type,
            }
            for created_at, source_ip, label, action, severity, action_type in rows
        ]

    def clear_runtime(self):
        with self.lock, self._connect() as conn:
            conn.execute("DELETE FROM predictions")
            conn.execute("DELETE FROM defense_actions")

    def load_settings(self):
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {key: json.loads(value) for key, value in rows}

    def save_settings(self, settings):
        with self.lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                [(key, json.dumps(value)) for key, value in settings.items()],
            )


class AuthManager:
    def __init__(self):
        self.passcode = os.environ.get("IDS_PASSCODE", "netwatch")
        self.sessions = set()

    def enabled(self):
        return os.environ.get("IDS_AUTH_DISABLED", "0") != "1"

    def login(self, passcode):
        if not self.enabled() or secrets.compare_digest(str(passcode), self.passcode):
            token = secrets.token_urlsafe(24)
            self.sessions.add(token)
            return token
        return None

    def authenticated(self, headers):
        if not self.enabled():
            return True
        cookie = headers.get("Cookie", "")
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "ids_session" and value in self.sessions:
                return True
        return False


AUTH = AuthManager()


class IDSState:
    def __init__(self):
        self.root = Path(__file__).resolve().parent
        self.storage = Storage(os.environ.get("IDS_DB_PATH", self.root / "netwatch.sqlite3"))
        self.fallback_model = ExplainableIDSModel()
        self.hybrid_model = HybridFlowModel(self.root / "models" / "hybrid_flow")
        self.imported_model = NSLKDDModel(self.root / "models" / "nsl_kdd")
        self.collector = LiveTrafficCollector()
        self.settings = {
            "capture_seconds": int(os.environ.get("IDS_CAPTURE_SECONDS", "1")),
            "capture_device": os.environ.get("IDS_CAPTURE_DEVICE", ""),
            "csv_row_limit": 250,
            "r2l_specialist_enabled": True,
            "high_risk_confidence": 78,
        }
        self.settings.update(self.storage.load_settings())
        self.apply_settings(self.settings, persist=False)
        self.records = []
        self.results = []
        self.latest_live = []
        self.collector.latest_packets = []
        self.last_capture_at = None
        self.blocked_ips = []
        self.suspicious_ips = []
        self.alerts = []
        self.rate_limited_ips = []
        self.load_persisted_state()

    def load_persisted_state(self):
        persisted = self.storage.recent_predictions()
        if persisted:
            self.records = [record for record, _ in persisted][-5000:]
            self.results = [result for _, result in persisted][-5000:]
            self.latest_live = [
                {"record": record, "prediction": result}
                for record, result in list(zip(self.records, self.results))[-50:]
            ]
            self.last_capture_at = time.time()

        for entry in self.storage.defense_entries():
            if entry["type"] == "block" and entry["source_ip"] not in self.blocked_ips:
                self.blocked_ips.append(entry["source_ip"])
            elif entry["type"] == "suspicious" and entry["source_ip"] not in self.suspicious_ips:
                self.suspicious_ips.append(entry["source_ip"])
            elif entry["type"] == "rate_limit" and entry["source_ip"] not in self.rate_limited_ips:
                self.rate_limited_ips.append(entry["source_ip"])
            elif entry["type"] == "alert":
                self.alerts.append(entry)

    def apply_settings(self, updates, persist=True):
        clean = dict(self.settings)
        def integer(name, default):
            value = updates.get(name, default)
            if value in {"", None}:
                value = default
            return int(value)

        if "capture_seconds" in updates:
            clean["capture_seconds"] = max(1, min(10, integer("capture_seconds", 1)))
        if "capture_device" in updates:
            clean["capture_device"] = str(updates["capture_device"] or "").strip()
        if "csv_row_limit" in updates:
            clean["csv_row_limit"] = max(1, min(1000, integer("csv_row_limit", 250)))
        if "r2l_specialist_enabled" in updates:
            clean["r2l_specialist_enabled"] = bool(updates["r2l_specialist_enabled"])
        if "high_risk_confidence" in updates:
            clean["high_risk_confidence"] = max(1, min(100, integer("high_risk_confidence", 78)))
        self.settings = clean
        self.collector.configure(clean["capture_seconds"], clean["capture_device"])
        if persist:
            self.storage.save_settings(self.settings)
        return self.settings

    def reset_runtime(self):
        self.collector.stop()
        self.storage.clear_runtime()
        self.records = []
        self.results = []
        self.latest_live = []
        self.collector.latest_packets = []
        self.last_capture_at = None
        self.blocked_ips = []
        self.suspicious_ips = []
        self.alerts = []
        self.rate_limited_ips = []
        return {"reset": True, "dashboard": self.dashboard()}

    def capture_live(self):
        records = self.collector.collect()
        predictions = [self.predict(row) for row in records]
        self.latest_live = [
            {"record": row, "prediction": result} for row, result in zip(records, predictions)
        ]
        self.last_capture_at = time.time()
        self.records.extend(records)
        self.results.extend(predictions)
        self.records = self.records[-5000:]
        self.results = self.results[-5000:]
        self.storage.save_predictions(records, predictions)
        return {
            "captured": len(records),
            "flows": self.latest_live,
            "packets": self.collector.latest_packets[-250:],
            "dashboard": self.dashboard(),
            "collector": self.collector.health(),
        }

    def latest_prediction(self):
        if not self.latest_live:
            self.capture_live()
        if self.latest_live:
            return self.latest_live[0]
        empty = self.empty_record()
        return {"record": empty, "prediction": self.predict(empty)}

    def predict(self, row):
        hybrid_result = None
        nsl_result = None
        if self.hybrid_model.available:
            try:
                hybrid_result = self.hybrid_model.predict(row)
            except Exception as exc:
                self.hybrid_model.error = str(exc)
                self.hybrid_model.status = "Hybrid flow model failed; using NSL-KDD model"
        if self.imported_model.available:
            try:
                nsl_result = self.imported_model.predict(row)
            except Exception as exc:
                self.imported_model.error = str(exc)
                self.imported_model.status = "Imported model failed; using fallback classifier"
        if hybrid_result and nsl_result:
            return self.ensemble_prediction(hybrid_result, nsl_result, row)
        if hybrid_result:
            hybrid_result["model_source"] = "Hybrid Flow Botnet-Capable Random Forest"
            return hybrid_result
        if nsl_result:
            return nsl_result
        result = self.fallback_model.predict(row)
        result["model_source"] = "Built-in fallback classifier"
        return result

    def ensemble_prediction(self, hybrid_result, nsl_result, row):
        nsl_specialist = nsl_result["label"] in {"r2l", "u2r"}
        nsl_confident = nsl_result["confidence"] >= 42
        login_abuse = float(row.get("failed_login_count", 0) or 0) >= 3
        if self.settings.get("r2l_specialist_enabled", True) and login_abuse and hybrid_result["label"] == "normal":
            return self.credential_abuse_prediction(hybrid_result, nsl_result, row)
        choose_nsl = nsl_specialist and nsl_confident and (
            hybrid_result["label"] == "normal"
            or login_abuse
            or nsl_result["confidence"] >= hybrid_result["confidence"] - 8
        )
        chosen = dict(nsl_result if choose_nsl else hybrid_result)
        chosen["model_source"] = (
            "Ensemble: NSL-KDD specialist override"
            if choose_nsl
            else "Ensemble: Hybrid Flow primary"
        )
        chosen["ensemble"] = {
            "hybrid": {
                "label": hybrid_result["label"],
                "confidence": hybrid_result["confidence"],
                "source": hybrid_result.get("model_source", "Hybrid Flow"),
            },
            "nsl_kdd": {
                "label": nsl_result["label"],
                "confidence": nsl_result["confidence"],
                "source": nsl_result.get("model_source", "NSL-KDD"),
            },
            "decision": "nsl_kdd" if choose_nsl else "hybrid",
        }
        chosen["probabilities"] = self.merge_probabilities(
            hybrid_result.get("probabilities", {}),
            nsl_result.get("probabilities", {}),
        )
        return chosen

    def credential_abuse_prediction(self, hybrid_result, nsl_result, row):
        failed = float(row.get("failed_login_count", 0) or 0)
        confidence = round(min(94, 64 + failed * 3), 1)
        probabilities = self.merge_probabilities(
            hybrid_result.get("probabilities", {}),
            nsl_result.get("probabilities", {}),
        )
        probabilities = self.force_probability(probabilities, ATTACK_LABELS["r2l"], confidence)
        return {
            "label": "r2l",
            "label_name": ATTACK_LABELS["r2l"],
            "confidence": confidence,
            "probabilities": probabilities,
            "explanation": [
                {
                    "feature": "failed_login_count",
                    "contribution": 46,
                    "reason": "Repeated failed logins matched remote-to-local abuse",
                },
                {
                    "feature": "service",
                    "contribution": 22,
                    "reason": "Login-oriented service increased credential risk",
                },
                {
                    "feature": "flag",
                    "contribution": 18,
                    "reason": "Rejected connection state supported abuse pattern",
                },
                {
                    "feature": "duration",
                    "contribution": 14,
                    "reason": "Session timing matched credential attack behavior",
                },
            ],
            "recommended_action": RESPONSE_POLICY["r2l"],
            "model_source": "Ensemble: Credential abuse specialist",
            "ensemble": {
                "hybrid": {
                    "label": hybrid_result["label"],
                    "confidence": hybrid_result["confidence"],
                    "source": hybrid_result.get("model_source", "Hybrid Flow"),
                },
                "nsl_kdd": {
                    "label": nsl_result["label"],
                    "confidence": nsl_result["confidence"],
                    "source": nsl_result.get("model_source", "NSL-KDD"),
                },
                "decision": "credential-specialist",
            },
        }

    def force_probability(self, probabilities, forced_label, forced_value):
        adjusted = dict(probabilities)
        other_labels = [label for label in adjusted if label != forced_label]
        other_total = sum(float(adjusted[label] or 0) for label in other_labels) or 1
        leftover = max(0.0, 100.0 - forced_value)
        for label in other_labels:
            adjusted[label] = round(float(adjusted[label] or 0) / other_total * leftover, 1)
        adjusted[forced_label] = round(forced_value, 1)
        return adjusted

    def merge_probabilities(self, hybrid_probabilities, nsl_probabilities):
        merged = {}
        for label, display in ATTACK_LABELS.items():
            merged[display] = max(
                float(hybrid_probabilities.get(display, 0) or 0),
                float(nsl_probabilities.get(display, 0) or 0),
            )
        total = sum(merged.values()) or 1
        if total > 100:
            merged = {label: round(value / total * 100, 1) for label, value in merged.items()}
        return merged

    def model_health(self):
        if self.hybrid_model.available:
            active = "Ensemble: Hybrid Flow + NSL-KDD Specialists" if self.imported_model.available else "Hybrid Flow Botnet-Capable Random Forest"
        elif self.imported_model.available and self.imported_model.multiclass_available:
            active = "Imported NSL-KDD Multiclass Random Forest"
        elif self.imported_model.available:
            active = "Imported NSL-KDD Binary Random Forest"
        else:
            active = "Built-in fallback classifier"
        return {
            "primary": self.hybrid_model.health() if self.hybrid_model.available else self.imported_model.health(),
            "hybrid": self.hybrid_model.health(),
            "nsl_kdd": self.imported_model.health(),
            "active": active,
            "mode": "ensemble" if self.hybrid_model.available and self.imported_model.available else "single-model",
        }

    def empty_record(self):
        return {
            "source_ip": "0.0.0.0",
            "destination_ip": "127.0.0.1",
            "source_bytes": 0,
            "destination_bytes": 0,
            "packet_count": 0,
            "duration": 0,
            "protocol": "tcp",
            "service": "http",
            "flag": "SF",
            "failed_login_count": 0,
            "connection_rate": 0,
            "same_host_rate": 0,
            "error_rate": 0,
            "source": "idle",
        }

    def dashboard(self):
        labels = [result["label"] for result in self.results]
        counts = Counter(labels)
        severity_counts = Counter(result["recommended_action"]["severity"] for result in self.results)
        attack_count = len(labels) - counts["normal"]
        attacks_only = {k: v for k, v in counts.items() if k != "normal"}
        most_common_attack = max(attacks_only, key=attacks_only.get) if attacks_only else "normal"
        risky_ips = {
            row["source_ip"]
            for row, result in zip(self.records, self.results)
            if result["label"] != "normal" and result["confidence"] >= self.settings.get("high_risk_confidence", 78)
        }
        top_sources = Counter(row["source_ip"] for row in self.records).most_common(5)
        return {
            "total_flows": len(self.records),
            "normal": counts["normal"],
            "attack": attack_count,
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "most_common_attack": ATTACK_LABELS[most_common_attack],
            "high_risk_ips": len(risky_ips),
            "top_sources": [{"ip": ip, "count": count} for ip, count in top_sources],
            "attack_breakdown": {
                ATTACK_LABELS[label]: counts[label] for label in self.fallback_model.labels
            },
            "live_flows": len(self.latest_live),
            "packet_rows": len(self.collector.latest_packets),
            "last_capture_at": self.last_capture_at,
            "collector": self.collector.health(),
            "model": self.model_health(),
            "blocked_ips": self.blocked_ips,
            "suspicious_ips": self.suspicious_ips,
            "alerts": self.alerts[-8:],
            "rate_limited_ips": self.rate_limited_ips,
            "settings": self.settings,
        }

    def analyze_batch(self, size=5000):
        return self.capture_live()["dashboard"]

    def demo_cases(self):
        cases = []
        for case in DEMO_CASES:
            record = dict(case["record"])
            prediction = self.predict(record)
            cases.append({**case, "prediction": prediction})
        return cases

    def run_demo_case(self, key):
        for case in DEMO_CASES:
            if case["key"] == key:
                record = dict(case["record"])
                prediction = self.predict(record)
                self.latest_live = [{"record": record, "prediction": prediction}]
                self.records.append(record)
                self.results.append(prediction)
                self.records = self.records[-5000:]
                self.results = self.results[-5000:]
                self.storage.save_predictions([record], [prediction])
                self.last_capture_at = time.time()
                return {
                    "flow": self.latest_live[0],
                    "dashboard": self.dashboard(),
                }
        raise ValueError("Unknown demo case")

    def analyze_csv(self, csv_text, limit=250):
        rows = self.csv_records(csv_text)
        if not rows:
            raise ValueError("No supported rows found in CSV")
        rows = rows[: max(1, min(int(limit or self.settings.get("csv_row_limit", 250)), 1000))]
        predictions = [self.predict(row) for row in rows]
        labels = Counter(result["label"] for result in predictions)
        flows = [{"record": row, "prediction": result} for row, result in zip(rows, predictions)]
        self.latest_live = flows[:50]
        self.records.extend(rows)
        self.results.extend(predictions)
        self.records = self.records[-5000:]
        self.results = self.results[-5000:]
        self.storage.save_predictions(rows, predictions)
        self.last_capture_at = time.time()
        return {
            "rows": len(rows),
            "summary": {
                "normal": labels["normal"],
                "attack": len(rows) - labels["normal"],
                "breakdown": {ATTACK_LABELS[label]: labels[label] for label in ATTACK_LABELS},
                "most_common": ATTACK_LABELS[max(labels, key=labels.get)] if labels else "Normal Traffic",
            },
            "flows": flows[:100],
            "dashboard": self.dashboard(),
        }

    def csv_records(self, csv_text):
        try:
            import pandas as pd
            from models.hybrid_flow.train_hybrid_flow import normalize_dataset
        except Exception:
            pd = None
            normalize_dataset = None

        if pd and normalize_dataset:
            dataframe = pd.read_csv(io.StringIO(csv_text), low_memory=False)
            normalized = normalize_dataset(dataframe)
            if not normalized.empty:
                rows = []
                for index, row in enumerate(normalized.to_dict(orient="records")):
                    row.pop("label", None)
                    row.setdefault("source_ip", f"csv.source.{index % 255}")
                    row.setdefault("destination_ip", "csv.destination")
                    rows.append(row)
                return rows

        reader = csv.DictReader(io.StringIO(csv_text))
        rows = []
        for index, raw in enumerate(reader):
            rows.append(self.normalize_project_row(raw, index))
        return rows

    def normalize_project_row(self, raw, index):
        def number(name, default=0):
            try:
                return float(raw.get(name, default) or default)
            except (TypeError, ValueError):
                return default

        return {
            "source_ip": raw.get("source_ip") or raw.get("src_ip") or f"csv.source.{index % 255}",
            "destination_ip": raw.get("destination_ip") or raw.get("dst_ip") or "csv.destination",
            "source_bytes": number("source_bytes"),
            "destination_bytes": number("destination_bytes"),
            "packet_count": number("packet_count", 1),
            "duration": number("duration"),
            "failed_login_count": number("failed_login_count"),
            "connection_rate": number("connection_rate"),
            "same_host_rate": number("same_host_rate"),
            "error_rate": number("error_rate"),
            "protocol": (raw.get("protocol") or "tcp").lower(),
            "service": (raw.get("service") or "http").lower(),
            "flag": (raw.get("flag") or "SF").upper(),
        }

    def export_report(self):
        return {
            "generated_at": time.time(),
            "dashboard": self.dashboard(),
            "model": self.model_health(),
            "latest_flows": self.latest_live[:100],
            "latest_packets": self.collector.latest_packets[-500:],
            "defense": {
                "blocked_ips": self.blocked_ips,
                "rate_limited_ips": self.rate_limited_ips,
                "suspicious_ips": self.suspicious_ips,
                "alerts": self.alerts,
            },
        }

    def system_info(self):
        dataset = self.root / "CICIDS2017_friday.csv"
        return {
            "project": "NetWatch",
            "version": "1.0.0",
            "platform": "Windows" if os.name == "nt" else "Unix/macOS",
            "root": str(self.root),
            "database": str(self.storage.path),
            "database_exists": self.storage.path.exists(),
            "auth_enabled": AUTH.enabled(),
            "dataset": {
                "name": dataset.name,
                "exists": dataset.exists(),
                "size_mb": round(dataset.stat().st_size / (1024 * 1024), 1) if dataset.exists() else 0,
            },
            "collector": self.collector.health(),
            "model": self.model_health(),
            "settings": self.settings,
            "runtime": {
                "predictions_loaded": len(self.results),
                "latest_window": len(self.latest_live),
                "packet_rows": len(self.collector.latest_packets),
                "defense_actions": len(self.storage.defense_entries()),
            },
        }

    def predictions_csv(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "source_ip",
                "destination_ip",
                "label",
                "confidence",
                "severity",
                "action",
                "model_source",
                "top_explanation",
            ]
        )
        for row, result in zip(self.records, self.results):
            explanation = result.get("explanation", [{}])
            writer.writerow(
                [
                    row.get("source_ip", ""),
                    row.get("destination_ip", ""),
                    result.get("label_name", result.get("label", "")),
                    result.get("confidence", ""),
                    result.get("recommended_action", {}).get("severity", ""),
                    result.get("recommended_action", {}).get("action", ""),
                    result.get("model_source", ""),
                    explanation[0].get("reason", "") if explanation else "",
                ]
            )
        return output.getvalue()

    def defense_csv(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "source_ip", "label", "action", "severity", "type"])
        for entry in self.storage.defense_entries():
            writer.writerow(
                [
                    entry["timestamp"],
                    entry["source_ip"],
                    entry["label"],
                    entry["action"],
                    entry["severity"],
                    entry["type"],
                ]
            )
        return output.getvalue()

    def apply_defense(self, source_ip, label):
        policy = RESPONSE_POLICY.get(label, RESPONSE_POLICY["botnet"])
        entry = {
            "source_ip": source_ip,
            "label": ATTACK_LABELS.get(label, label),
            "action": policy["action"],
            "severity": policy["severity"],
            "timestamp": time.time(),
        }
        if policy["type"] == "block" and source_ip not in self.blocked_ips:
            self.blocked_ips.append(source_ip)
        elif policy["type"] == "suspicious" and source_ip not in self.suspicious_ips:
            self.suspicious_ips.append(source_ip)
        elif policy["type"] == "rate_limit" and source_ip not in self.rate_limited_ips:
            self.rate_limited_ips.append(source_ip)
        elif policy["type"] == "alert":
            self.alerts.append(entry)
        entry["type"] = policy["type"]
        self.storage.save_defense(entry)
        return entry


STATE = IDSState()


class Handler(BaseHTTPRequestHandler):
    def _send(self, data, status=200, headers=None):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, text, content_type="text/plain", status=200, headers=None):
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/") and path != "/api/session" and not AUTH.authenticated(self.headers):
            self._send({"error": "Authentication required"}, 401)
            return
        if path == "/api/session":
            self._send(
                {
                    "authenticated": AUTH.authenticated(self.headers),
                    "auth_enabled": AUTH.enabled(),
                    "default_passcode_hint": "netwatch" if AUTH.passcode == "netwatch" else "",
                }
            )
        elif path == "/api/dashboard":
            STATE.capture_live()
            self._send(STATE.dashboard())
        elif path == "/api/sample":
            self._send(STATE.latest_prediction())
        elif path == "/api/live":
            self._send(STATE.capture_live())
        elif path == "/api/packets":
            self._send({"packets": STATE.collector.latest_packets[-500:], "collector": STATE.collector.health()})
        elif path == "/api/health":
            self._send({"status": "ok", "collector": STATE.collector.health(), "model": STATE.model_health()})
        elif path == "/api/demo-cases":
            self._send({"cases": STATE.demo_cases()})
        elif path == "/api/export":
            self._send(STATE.export_report())
        elif path == "/api/export-predictions.csv":
            self._send_text(
                STATE.predictions_csv(),
                "text/csv",
                headers={"Content-Disposition": "attachment; filename=netwatch-predictions.csv"},
            )
        elif path == "/api/export-defense.csv":
            self._send_text(
                STATE.defense_csv(),
                "text/csv",
                headers={"Content-Disposition": "attachment; filename=netwatch-defense.csv"},
            )
        elif path == "/api/settings":
            self._send({"settings": STATE.settings})
        elif path == "/api/about":
            self._send(STATE.system_info())
        elif path == "/api/blocked":
            self._send(
                {
                    "blocked_ips": STATE.blocked_ips,
                    "suspicious_ips": STATE.suspicious_ips,
                    "rate_limited_ips": STATE.rate_limited_ips,
                    "alerts": STATE.alerts,
                }
            )
        else:
            self.serve_static(path)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self._read_json()
            if path == "/api/login":
                token = AUTH.login(data.get("passcode", ""))
                if not token:
                    self._send({"error": "Invalid passcode"}, 401)
                    return
                self._send(
                    {"authenticated": True},
                    headers={"Set-Cookie": f"ids_session={token}; Path=/; SameSite=Lax"},
                )
                return
            if path.startswith("/api/") and not AUTH.authenticated(self.headers):
                self._send({"error": "Authentication required"}, 401)
                return
            if path == "/api/predict":
                result = STATE.predict(data)
                self._send({"record": data, "prediction": result})
            elif path == "/api/demo-case":
                self._send(STATE.run_demo_case(data["key"]))
            elif path == "/api/csv":
                self._send(STATE.analyze_csv(data.get("csv", ""), data.get("limit", STATE.settings.get("csv_row_limit", 250))))
            elif path == "/api/settings":
                self._send({"settings": STATE.apply_settings(data)})
            elif path == "/api/reset":
                self._send(STATE.reset_runtime())
            elif path == "/api/batch":
                self._send(STATE.capture_live())
            elif path == "/api/defense":
                result = STATE.apply_defense(data["source_ip"], data["label"])
                self._send({"applied": result, "dashboard": STATE.dashboard()})
            else:
                self._send({"error": "Not found"}, 404)
        except Exception as exc:
            self._send({"error": str(exc)}, 400)

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        root = os.path.join(os.path.dirname(__file__), "static")
        requested = os.path.abspath(os.path.join(root, path.lstrip("/")))
        if not requested.startswith(os.path.abspath(root)):
            self._send({"error": "Invalid path"}, 403)
            return
        if not os.path.exists(requested):
            self._send({"error": "Not found"}, 404)
            return
        content_type = "text/html"
        if requested.endswith(".css"):
            content_type = "text/css"
        elif requested.endswith(".js"):
            content_type = "application/javascript"
        with open(requested, "rb") as file:
            payload = file.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Explainable IDS running at http://127.0.0.1:{port}")
    server.serve_forever()
