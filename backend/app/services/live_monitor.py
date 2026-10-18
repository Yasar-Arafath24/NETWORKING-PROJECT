"""
NetSentry AI - Live Network Monitoring Service

Supports:
- Live packet capture using Scapy
- PCAP/PCAPNG replay
- Bidirectional network-flow tracking
- Live monitoring statistics
- Thread-safe start, stop, and status operations

This service observes traffic only. It does not block packets.
"""

from collections import deque
from pathlib import Path
from threading import Event, Lock, Thread
from time import sleep, time
from datetime import datetime, timezone
from typing import Optional
import math

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader, sniff


class LiveMonitor:
    """Thread-safe network monitoring service."""

    def __init__(self):
        self._lock = Lock()
        self._stop_event = Event()
        self._thread: Optional[Thread] = None

        self._running = False
        self._mode = None
        self._source = None
        self._started_at = None
        self._last_packet_at = None
        self._error = None

        self._total_packets = 0
        self._total_bytes = 0
        self._total_flows = 0

        self._flows = {}
        self._recent_packets = deque(maxlen=1000)

    @staticmethod
    def _timestamp():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _extract_packet(packet):
        """Extract useful metadata from an IP packet."""

        if IP in packet:
            network_layer = packet[IP]
            src_ip = network_layer.src
            dst_ip = network_layer.dst
        elif IPv6 in packet:
            network_layer = packet[IPv6]
            src_ip = network_layer.src
            dst_ip = network_layer.dst
        else:
            return None

        if TCP in packet:
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = 0
            dst_port = 0
        else:
            protocol = "OTHER"
            src_port = 0
            dst_port = 0

        try:
            packet_timestamp = float(packet.time)
            if not math.isfinite(packet_timestamp):
                packet_timestamp = time()
        except (AttributeError, TypeError, ValueError, OverflowError):
            packet_timestamp = time()

        try:
            packet_size = int(len(packet))
        except (TypeError, ValueError):
            packet_size = 0

        return {
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamp": packet_timestamp,
            "size": packet_size,
        }

    def _process_packet(self, packet):
        """Update monitoring counters and bidirectional flow statistics."""

        details = self._extract_packet(packet)

        if details is None:
            return

        src_endpoint = (
            details["src_ip"],
            details["src_port"],
        )
        dst_endpoint = (
            details["dst_ip"],
            details["dst_port"],
        )

        forward = src_endpoint <= dst_endpoint

        if forward:
            flow_key = (
                details["protocol"],
                src_endpoint,
                dst_endpoint,
            )
        else:
            flow_key = (
                details["protocol"],
                dst_endpoint,
                src_endpoint,
            )

        packet_timestamp = details["timestamp"]
        packet_size = details["size"]

        with self._lock:
            self._total_packets += 1
            self._total_bytes += packet_size
            self._last_packet_at = self._timestamp()

            flow = self._flows.get(flow_key)

            if flow is None:
                self._total_flows += 1

                flow = {
                    "flow_id": self._total_flows,
                    "src_ip": details["src_ip"],
                    "dst_ip": details["dst_ip"],
                    "src_port": details["src_port"],
                    "dst_port": details["dst_port"],
                    "protocol": details["protocol"],
                    "packet_count": 0,
                    "total_bytes": 0,
                    "duration": 0.0,
                    "packet_rate": 0.0,
                    "byte_rate": 0.0,
                    "average_packet_size": 0.0,
                    "min_packet_size": packet_size,
                    "max_packet_size": packet_size,
                    "forward_packets": 0,
                    "backward_packets": 0,
                    "forward_bytes": 0,
                    "backward_bytes": 0,
                    "_first_timestamp": packet_timestamp,
                    "_last_timestamp": packet_timestamp,
                }

                self._flows[flow_key] = flow

            flow["packet_count"] += 1
            flow["total_bytes"] += packet_size

            if forward:
                flow["forward_packets"] += 1
                flow["forward_bytes"] += packet_size
            else:
                flow["backward_packets"] += 1
                flow["backward_bytes"] += packet_size

            flow["_first_timestamp"] = min(
                flow["_first_timestamp"],
                packet_timestamp,
            )
            flow["_last_timestamp"] = max(
                flow["_last_timestamp"],
                packet_timestamp,
            )

            flow["duration"] = (
                flow["_last_timestamp"] - flow["_first_timestamp"]
            )

            flow["packet_rate"] = (
                flow["packet_count"] / flow["duration"]
                if flow["duration"] > 0
                else 0.0
            )

            flow["byte_rate"] = (
                flow["total_bytes"] / flow["duration"]
                if flow["duration"] > 0
                else 0.0
            )

            flow["average_packet_size"] = (
                flow["total_bytes"] / flow["packet_count"]
            )

            flow["min_packet_size"] = min(
                flow["min_packet_size"],
                packet_size,
            )

            flow["max_packet_size"] = max(
                flow["max_packet_size"],
                packet_size,
            )

            self._recent_packets.append({
                "timestamp": self._timestamp(),
                "src_ip": details["src_ip"],
                "dst_ip": details["dst_ip"],
                "protocol": details["protocol"],
                "size": packet_size,
            })

    def start_live(self, interface=None):
        """Start capturing packets from an authorized interface."""

        return self._start(
            mode="live",
            source=interface,
        )

    def start_replay(self, pcap_path, speed=1.0):
        """Replay a PCAP or PCAPNG file in timestamp order."""

        path = Path(pcap_path).expanduser().resolve()

        if not path.is_file():
            raise FileNotFoundError(
                f"Capture file not found: {path}"
            )

        if not path.suffix.lower() in {".pcap", ".pcapng"}:
            raise ValueError(
                "Replay requires a .pcap or .pcapng file."
            )

        if (
            isinstance(speed, bool)
            or not isinstance(speed, (int, float))
            or not math.isfinite(speed)
            or speed <= 0
            or speed > 100
        ):
            raise ValueError(
                "Replay speed must be greater than 0 and at most 100."
            )

        return self._start(
            mode="replay",
            source=str(path),
            speed=float(speed),
        )

    def _start(self, mode, source, speed=1.0):
        """Start the background monitoring worker."""

        with self._lock:
            if self._running:
                raise RuntimeError(
                    "Monitoring is already running."
                )

            self._stop_event = Event()

            self._mode = mode
            self._source = source
            self._started_at = self._timestamp()
            self._last_packet_at = None
            self._error = None

            self._total_packets = 0
            self._total_bytes = 0
            self._total_flows = 0

            self._flows.clear()
            self._recent_packets.clear()

            self._running = True

            self._thread = Thread(
                target=self._worker,
                args=(mode, source, speed, self._stop_event),
                daemon=True,
                name="netsentry-live-monitor",
            )

            self._thread.start()

        return self.status()

    def _worker(self, mode, source, speed, stop_event):
        """Run capture or replay outside the API request thread."""

        try:
            if mode == "replay":
                self._replay_pcap(source, speed, stop_event)
            else:
                self._capture_live(source, stop_event)

        except Exception as exc:
            with self._lock:
                self._error = (
                    f"{type(exc).__name__}: {exc}"
                )

        finally:
            with self._lock:
                self._running = False

    def _replay_pcap(self, path, speed, stop_event):
        """Read a capture file and replay its packets."""

        previous_timestamp = None

        with PcapReader(path) as reader:
            for packet in reader:
                if stop_event.is_set():
                    break

                try:
                    current_timestamp = float(packet.time)
                except (AttributeError, TypeError, ValueError):
                    current_timestamp = None

                if (
                    previous_timestamp is not None
                    and current_timestamp is not None
                ):
                    delay = max(
                        0.0,
                        current_timestamp - previous_timestamp,
                    ) / speed

                    # Keep stop requests responsive during long gaps.
                    deadline = time() + min(delay, 3600.0)

                    while not stop_event.is_set():
                        remaining = deadline - time()

                        if remaining <= 0:
                            break

                        stop_event.wait(min(remaining, 0.25))

                if stop_event.is_set():
                    break

                self._process_packet(packet)

                if current_timestamp is not None:
                    previous_timestamp = current_timestamp

    def _capture_live(self, interface, stop_event):
        """Capture live traffic in short, interruptible intervals."""

        while not stop_event.is_set():
            sniff(
                iface=interface or None,
                prn=self._process_packet,
                store=False,
                timeout=1,
                stop_filter=lambda _: stop_event.is_set(),
            )

    def stop(self):
        """Request monitoring to stop."""

        with self._lock:
            if not self._running:
                return self.status()

            self._stop_event.set()
            thread = self._thread

        # Do not join while holding the state lock.
        if thread is not None and thread is not __import__("threading").current_thread():
            thread.join(timeout=3.0)

        return self.status()

    def status(self):
        """Return monitoring status and current statistics."""

        with self._lock:
            return {
                "running": self._running,
                "mode": self._mode,
                "source": self._source,
                "started_at": self._started_at,
                "last_packet_at": self._last_packet_at,
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "total_flows": self._total_flows,
                "error": self._error,
            }

    def get_flows(self, limit=100):
        """Return a bounded list of current flow snapshots."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer.")

        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000.")

        with self._lock:
            flows = list(self._flows.values())[-limit:]

            # Do not expose internal timestamps or mutable state.
            return [
                {
                    key: value
                    for key, value in flow.items()
                    if not key.startswith("_")
                }
                for flow in flows
            ]

    def get_recent_packets(self, limit=100):
        """Return recent packet metadata, not packet payloads."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer.")

        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000.")

        with self._lock:
            return list(self._recent_packets)[-limit:]


# One shared monitor instance for the application.
monitor = LiveMonitor()