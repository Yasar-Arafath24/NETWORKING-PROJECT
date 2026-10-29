from threading import Event
import sys

from backend.app.services.live_monitor import LiveMonitor


def test_live_capture_status_hides_internal_exception_details(monkeypatch):
    monitor = LiveMonitor()

    def fail_capture(_interface, _stop_event):
        raise RuntimeError("private-device-path-or-secret")

    monkeypatch.setattr(monitor, "_capture_live", fail_capture)
    monitor._worker("live", "test-interface", 1.0, Event())

    status = monitor.status()
    if sys.platform == "win32" and not __import__("scapy.config", fromlist=["conf"]).conf.use_pcap:
        assert "Npcap is unavailable" in status["error"]
    else:
        assert "Live capture could not start" in status["error"]
    assert "private-device-path-or-secret" not in status["error"]
    assert status["state"] == "error"


def test_windows_npcap_unavailable_is_reported_before_worker_starts(monkeypatch):
    from backend.app.services import live_monitor

    monkeypatch.setattr(live_monitor.sys, "platform", "win32")
    monkeypatch.setattr(live_monitor.conf, "use_pcap", False)
    service = LiveMonitor()

    try:
        service.start_live("adapter")
    except live_monitor.CaptureProviderUnavailable as exc:
        assert "Npcap is unavailable" in str(exc)
    else:
        raise AssertionError("start_live should reject a missing Npcap provider")

    assert service.status()["running"] is False


def test_invalid_capture_interface_is_rejected(monkeypatch):
    from backend.app.services import live_monitor

    monkeypatch.setattr(live_monitor, "capture_capabilities", lambda: {"available": True, "error": None})
    monkeypatch.setattr(live_monitor, "get_if_list", lambda: ["Ethernet 1"])
    try:
        live_monitor.validate_capture_interface("missing adapter")
    except live_monitor.InvalidCaptureInterface as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("an unknown interface should be rejected")


def test_capture_start_and_stop_is_safe_and_produces_no_fake_packets(monkeypatch):
    from backend.app.services import live_monitor

    monkeypatch.setattr(live_monitor, "validate_capture_interface", lambda _interface: None)
    calls = []

    def idle_sniff(**kwargs):
        calls.append(kwargs["iface"])
        kwargs["stop_filter"](None)

    monkeypatch.setattr(live_monitor, "sniff", idle_sniff)
    service = LiveMonitor()
    first_status = service.start_live("Ethernet 1", owner_id=4)
    assert first_status["running"] is True

    try:
        service.start_live("Ethernet 1", owner_id=4)
    except RuntimeError as exc:
        assert "already running" in str(exc)
    else:
        raise AssertionError("duplicate capture must be rejected")

    stopped = service.stop()
    assert stopped["running"] is False
    assert service.status()["total_packets"] == 0
    assert service.status()["total_flows"] == 0
    assert calls


def test_worker_classifies_capture_permission_error(monkeypatch):
    from backend.app.services import live_monitor

    service = LiveMonitor()
    monkeypatch.setattr(service, "_capture_live", lambda _interface, _event: (_ for _ in ()).throw(PermissionError("denied")))
    service._worker("live", "Ethernet 1", 1.0, Event())
    assert "Capture permission denied" in service.status()["error"]


def test_empty_live_capture_stays_zero_without_inventing_results(monkeypatch):
    service = LiveMonitor()
    monkeypatch.setattr(service, "_capture_live", lambda _interface, _event: None)
    service._worker("live", "Ethernet 1", 1.0, Event())
    assert service.status()["total_packets"] == 0
    assert service.status()["total_flows"] == 0
    assert service.get_flows() == []


def test_pcap_replay_status_hides_internal_exception_details(monkeypatch):
    monitor = LiveMonitor()

    def fail_replay(_path, _speed, _stop_event):
        raise RuntimeError("private-capture-path-or-secret")

    monkeypatch.setattr(monitor, "_replay_pcap", fail_replay)
    monitor._worker("replay", "private-capture-path", 1.0, Event())

    status = monitor.status()
    assert status["error"] == "PCAP replay failed. Confirm the file is a readable PCAP/PCAPNG inside the datasets directory."
    assert "private-capture-path-or-secret" not in status["error"]
    assert status["state"] == "error"


def test_live_detection_status_hides_internal_exception_details(monkeypatch):
    from backend.app.services import live_monitor
    from backend.app.services.live_detection import LiveDetectionService

    class FakeMonitor:
        owner_id = 7

        @staticmethod
        def status():
            return {"running": False, "started_at": "test-session"}

        @staticmethod
        def get_flows(limit):
            assert limit == 1000
            return [{"flow_id": 3, "packet_count": 1, "total_bytes": 60, "duration": 0.1}]

    service = LiveDetectionService()

    def fail_assessment(_flow, _session_id, _owner_id):
        raise RuntimeError("private-database-path-or-secret")

    monkeypatch.setattr(live_monitor, "monitor", FakeMonitor())
    monkeypatch.setattr(service, "_assess_flow", fail_assessment)
    service._run()

    status = service.status()
    assert status["last_error"] == "Flow detection failed for one or more flows."
    assert "private-database-path-or-secret" not in status["last_error"]
