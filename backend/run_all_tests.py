
import json
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
results = []

def check(name, path, expected=(200,)):
    try:
        req = urllib.request.Request(
            BASE_URL + path,
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")

        passed = status in expected
        detail = f"HTTP {status}"
        if passed:
            try:
                json.loads(body)
                detail += " | JSON response"
            except json.JSONDecodeError:
                detail += " | Non-JSON response"

    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", errors="replace")
        passed = status in expected
        detail = f"HTTP {status}: {body[:120]}"

    except Exception as exc:
        passed = False
        detail = str(exc)

    results.append((name, passed, detail))
    print(f"[{'PASS' if passed else 'FAIL'}] {name}: {detail}")

def main():
    print("=" * 60)
    print("NETSENTRY AI - API SMOKE TEST")
    print("=" * 60)

    # Basic API and analysis endpoints
    check("Health", "/api/v1/health")
    check("System info", "/api/v1/system/info")
    check("Analysis history", "/api/v1/monitoring/history?skip=0&limit=20")
    check("Statistics", "/api/v1/monitoring/statistics")
    check("Latest report", "/api/v1/monitoring/latest")
    check("Suspicious flows", "/api/v1/monitoring/suspicious")
    check("All flows", "/api/v1/monitoring/flows?status=all")

    # History-related endpoints
    check("Historical flows", "/api/v1/monitoring/history/flows")
    check("Historical alerts", "/api/v1/monitoring/history/alerts")

    # Live monitoring read endpoints
    check("Live status", "/api/v1/monitoring/live/status")
    check("Live detection status",
          "/api/v1/monitoring/live/detection-status")
    check("Live flows", "/api/v1/monitoring/live/flows")
    check("Live packets", "/api/v1/monitoring/live/packets")

    # Export can return JSON or a downloadable file.
    check("Export", "/api/v1/monitoring/export")

    print("\n" + "=" * 60)
    passed = sum(ok for _, ok, _ in results)
    failed = len(results) - passed
    print(f"TOTAL: {len(results)} | PASSED: {passed} | FAILED: {failed}")

    if failed:
        print("\nFailures to investigate:")
        for name, ok, detail in results:
            if not ok:
                print(f"- {name}: {detail}")

    print("\nNote: HTTP success does not prove AI detection accuracy.")

if __name__ == "__main__":
    main()
