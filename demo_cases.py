#!/usr/bin/env python3
import argparse
import json
import os
import urllib.request
from urllib.error import URLError
from urllib.request import Request, urlopen


CASES = [
    {
        "name": "Normal web flow",
        "expected": "normal",
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
        "name": "DDoS-style reset flow",
        "expected": "dos",
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
        "name": "Port scan / probe flow",
        "expected": "probe",
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
        "name": "Botnet command-and-control style flow",
        "expected": "botnet",
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
]


def main():
    parser = argparse.ArgumentParser(description="Run repeatable NetWatch IDS demo cases against the local API.")
    parser.add_argument("--url", default="http://127.0.0.1:8010", help="Base URL for the running IDS server.")
    parser.add_argument("--passcode", default=os.environ.get("IDS_PASSCODE", "netwatch"), help="Local dashboard passcode.")
    parser.add_argument("--apply-defense", action="store_true", help="Apply recommended defense actions for attack cases.")
    args = parser.parse_args()

    opener = login(args.url, args.passcode)
    health = get_json(opener, f"{args.url}/api/health")
    print(f"Server: {args.url}")
    print(f"Active model: {health['model']['active']}")
    print()

    passed = 0
    for index, case in enumerate(CASES, start=1):
        payload = post_json(opener, f"{args.url}/api/predict", case["record"])
        prediction = payload["prediction"]
        ok = prediction["label"] == case["expected"]
        passed += int(ok)
        status = "PASS" if ok else "CHECK"
        print(f"{index}. {case['name']} [{status}]")
        print(f"   expected: {case['expected']}")
        print(f"   predicted: {prediction['label']} ({prediction['confidence']}%)")
        print(f"   action: {prediction['recommended_action']['action']}")
        if prediction.get("explanation"):
            top = prediction["explanation"][0]
            print(f"   top explanation: {top['reason']} (+{top['contribution']}%)")
        if args.apply_defense and prediction["label"] != "normal":
            applied = post_json(
                opener,
                f"{args.url}/api/defense",
                {"source_ip": case["record"]["source_ip"], "label": prediction["label"]},
            )
            print(f"   defense applied: {applied['applied']['action']}")
        print()

    print(f"Result: {passed}/{len(CASES)} demo cases matched expected labels.")
    if args.apply_defense:
        dashboard = get_json(opener, f"{args.url}/api/dashboard")
        total_actions = (
            len(dashboard.get("blocked_ips", []))
            + len(dashboard.get("rate_limited_ips", []))
            + len(dashboard.get("suspicious_ips", []))
            + len(dashboard.get("alerts", []))
        )
        print(f"Defense state now has {total_actions} applied response entries.")


def login(base_url, passcode):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    request = Request(
        f"{base_url}/api/login",
        data=json.dumps({"passcode": passcode}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener.open(request, timeout=10) as response:
            json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise SystemExit(f"Could not authenticate with IDS server: {exc}")
    return opener


def get_json(opener, url):
    try:
        with opener.open(url, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise SystemExit(f"Could not reach IDS server at {url}: {exc}")


def post_json(opener, url, payload):
    data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise SystemExit(f"API request failed at {url}: {exc}")


if __name__ == "__main__":
    main()
