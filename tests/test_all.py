
import os
import sys
import time
import unittest
from pathlib import Path

import requests

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 15

# PCAP candidates used by the project
PCAP_CANDIDATES = [
    "datasets/processed/netsentry_test.pcap",
    "datasets/processed/phase1_test_capture.pcapng",
    "datasets/processed/57c81bec8b6347529b80d4443fd8d97d.pcapng",
    "netsentry_test.pcap",
]

results = []
session = requests.Session()


def record(name, passed, details=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, passed, details))
    print(f"[{status}] {name}" + (f" - {details}" if details else ""))


def request_test(name, method, path, expected=(200,), **kwargs):
    try:
        response = session.request(
            method,
            BASE_URL + path,
            timeout=TIMEOUT,
            **kwargs,
        )
        passed = response.status_code in expected
        details = f"HTTP {response.status_code}; expected {expected}"

        if not passed:
            details += f"; body={response.text[:180]!r}"

        record(name, passed, details)
        return response
    except requests.RequestException as exc:
        record(name, False, str(exc))
        return None


def main():
    print("=" * 65)
    print("NetSentry AI - Complete API Smoke Test")
    print("=" * 65)
    print(f"Server: {BASE_URL}\n")

    # 1. Confirm server is reachable before running the remaining tests.
    try:
        response = session.get(
            BASE_URL + "/api/v1/health", timeout=TIMEOUT
        )
        if response.status_code != 200:
            record(
                "Server health / startup",
                False,
                f"HTTP {response.status_code}",
            )
            print("\nStart the server with:")
            print("uvicorn backend.app.main:app --reload")
            return
        record("Server health / startup", True, "HTTP 200")
    except requests.RequestException as exc:
        record("Server health / startup", False, str(exc))
        print("\nStart the server in another terminal with:")
        print("uvicorn backend.app.main:app --reload")
        return

    # 2. Basic API endpoints
    request_test("API health", "GET", "/api/v1/health")
    request_test("System information", "GET", "/api/v1/system/info")

    # 3. Prediction validation.
    # An empty payload should be rejected, not accepted as a valid prediction.
    request_test(
        "Prediction rejects missing features",
        "POST",
        "/api/v1/predict",
        expected=(400, 422),
        json={},
    )

    # 4. Monitoring and saved analysis endpoints
    get_tests = [
        ("Latest report", "/api/v1/monitoring/latest"),
        ("Suspicious flows", "/api/v1/monitoring/suspicious"),
        ("All flows", "/api/v1/monitoring/flows?status=all"),
        ("Report history", "/api/v1/monitoring/history?skip=0&limit=20"),
        ("Statistics", "/api/v1/monitoring/statistics"),
        ("Historical flows", "/api/v1/monitoring/history/flows"),
        ("Historical alerts", "/api/v1/monitoring/history/alerts"),
        ("Live detection status", "/api/v1/monitoring/live/detection-status"),
        ("Live status", "/api/v1/monitoring/live/status"),
        ("Live flows", "/api/v1/monitoring/live/flows"),
        ("Live packets", "/api/v1/monitoring/live/packets"),
        ("Export", "/api/v1/monitoring/export"),
    ]

    for name, path in get_tests:
        response = request_test(name, "GET", path)
        if response is not None and response.status_code == 200:
            # Verify JSON responses where JSON is expected.
            if name != "Export":
                try:
                    response.json()
                except ValueError:
                    record(
                        name + " returns valid JSON",
                        False,
                        "Response was not valid JSON",
                    )

    # 5. Retrieve the latest report by ID if history provides one.
    history = request_test(
        "History data structure",
        "GET",
        "/api/v1/monitoring/history?skip=0&limit=1",
    )
    if history is not None and history.status_code == 200:
        try:
            data = history.json()
            reports = data.get("reports", [])
            if reports and "id" in reports[0]:
                report_id = reports[0]["id"]
                request_test(
                    f"Retrieve report {report_id}",
                    "GET",
                    f"/api/v1/monitoring/history/{report_id}",
                )
            else:
                record(
                    "Retrieve report by ID",
                    True,
                    "SKIPPED: no saved reports yet",
                )
        except (ValueError, AttributeError):
            record(
                "History data structure",
                False,
                "Unexpected response format",
            )

    # 6. Test PCAP upload if a known capture file is available.
    pcap_path = next(
        (Path(p) for p in PCAP_CANDIDATES if Path(p).is_file()),
        None,
    )

    if pcap_path is None:
        record(
            "PCAP upload / analysis",
            True,
            "SKIPPED: no known PCAP file found in the current folder",
        )
        print(
            "  Put a test PCAP in one of the candidate paths "
            "to enable this test."
        )
    else:
        try:
            with pcap_path.open("rb") as capture:
                response = session.post(
                    BASE_URL + "/api/v1/pcap/analyze",
                    files={
                        "file": (
                            pcap_path.name,
                            capture,
                            "application/octet-stream",
                        )
                    },
                    timeout=60,
                )
            passed = response.status_code == 200
            record(
                "PCAP upload / analysis",
                passed,
                f"File={pcap_path}; HTTP {response.status_code}",
            )
            if not passed:
                print("  Response:", response.text[:300])
        except (OSError, requests.RequestException) as exc:
            record("PCAP upload / analysis", False, str(exc))

    # 7. Final report
    passed_count = sum(1 for _, passed, _ in results if passed)
    failed = [item for item in results if not item[1]]
    total = len(results)

    print("\n" + "=" * 65)
    print("FINAL TEST SUMMARY")
    print("=" * 65)
    print(f"Total checks : {total}")
    print(f"PASS         : {passed_count}")
    print(f"FAIL         : {len(failed)}")
    print(f"Pass rate    : {passed_count / total * 100:.1f}%" if total else "N/A")

    if failed:
        print("\nFailed checks:")
        for name, _, details in failed:
            print(f"  - {name}: {details}")
        print("\nRESULT: SOME TESTS FAILED")
        sys.exit(1)
    else:
        print("\nRESULT: ALL EXECUTED CHECKS PASSED")
        print(
            "Note: skipped tests and ML prediction accuracy "
            "are not validated by this result."
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
