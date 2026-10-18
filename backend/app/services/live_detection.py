
"""
NetSentry AI - Live Flow Detection and Persistent Alerts.

Evaluates live flow snapshots using the existing Isolation Forest
detector and persists flow assessments and alerts in SQLAlchemy.

This service is observe-only. It does not block network traffic.
"""

import logging
import math
from datetime import datetime, timezone
from threading import Event, Lock, Thread

from backend.app.models.live_monitoring import (
    LiveFlowRecord,
    NetworkAlert,
)
from backend.app.services.database import SessionLocal

logger = logging.getLogger(__name__)


class LiveDetectionService:
    """Background service for flow assessment and alert persistence."""

    def __init__(self):
        self._lock = Lock()
        self._thread = None
        self._stop_event = Event()
        self._last_error = None
        self._processed = {}

    def status(self):
        """Return the current detection-worker status."""
        with self._lock:
            thread = self._thread
            return {
                "running": (
                    thread is not None
                    and thread.is_alive()
                ),
                "last_error": self._last_error,
                "processed_flow_snapshots": len(self._processed),
            }

    def start(self):
        """Start the detection worker if it is not already running."""
        with self._lock:
            if (
                self._thread is not None
                and self._thread.is_alive()
            ):
                return {
                    "running": True,
                    "already_running": True,
                }

            self._stop_event = Event()
            self._last_error = None
            self._processed = {}

            self._thread = Thread(
                target=self._run,
                daemon=True,
                name="netsentry-live-detection",
            )
            self._thread.start()

        return {
            "running": True,
            "already_running": False,
        }

    def stop(self, timeout=3.0):
        """Request the detection worker to stop."""
        self._stop_event.set()
        thread = self._thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

        return self.status()

    @staticmethod
    def _session_id(monitor_status):
        """Use the capture start timestamp to identify a session."""
        return (
            monitor_status.get("started_at")
            or "unknown-session"
        )

    @staticmethod
    def _severity(anomaly_score):
        """
        Return a provisional severity based on the model score.

        Isolation Forest decision scores are not probabilities.
        These thresholds are placeholders, not validated attack
        severity thresholds.
        """
        score = float(anomaly_score)

        if score <= -0.20:
            return "HIGH"

        if score <= -0.05:
            return "MEDIUM"

        return "LOW"

    def _assess_flow(self, flow, session_id):
        """Predict, persist the flow snapshot, and upsert its alert."""
        from ml.anomaly_detector import predict_anomalies

        predictions = predict_anomalies([flow])

        if not predictions:
            raise ValueError("The detector returned no prediction.")

        prediction = predictions[0]
        anomaly = bool(prediction["anomaly"])
        label = str(prediction["label"])
        score = float(prediction["anomaly_score"])

        if not math.isfinite(score):
            raise ValueError(
                "The detector returned a non-finite anomaly score."
            )

        required_features = (
            "packet_count",
            "total_bytes",
            "duration",
            "packet_rate",
            "byte_rate",
            "average_packet_size",
            "min_packet_size",
            "max_packet_size",
            "forward_packets",
            "backward_packets",
            "forward_bytes",
            "backward_bytes",
        )

        feature_data = {
            key: flow[key]
            for key in required_features
        }

        flow_id = int(flow["flow_id"])
        now = datetime.now(timezone.utc)

        db = SessionLocal()

        try:
            # Upsert the latest flow snapshot for this session.
            record = (
                db.query(LiveFlowRecord)
                .filter_by(
                    session_id=session_id,
                    flow_id=flow_id,
                )
                .first()
            )

            if record is None:
                record = LiveFlowRecord(
                    session_id=session_id,
                    flow_id=flow_id,
                    src_ip=str(flow.get("src_ip", "")),
                    dst_ip=str(flow.get("dst_ip", "")),
                    src_port=int(flow.get("src_port", 0)),
                    dst_port=int(flow.get("dst_port", 0)),
                    protocol=str(flow.get("protocol", "OTHER")),
                    first_seen=now,
                )
                db.add(record)

            record.packet_count = int(flow["packet_count"])
            record.total_bytes = int(flow["total_bytes"])
            record.duration = float(flow["duration"])
            record.anomaly = anomaly
            record.label = label
            record.anomaly_score = score
            record.features = feature_data
            record.last_updated = now

            # Maintain at most one alert per flow in each session.
            alert = (
                db.query(NetworkAlert)
                .filter_by(
                    session_id=session_id,
                    flow_id=flow_id,
                )
                .first()
            )

            if anomaly:
                severity = self._severity(score)

                alert_flow_data = {
                    **flow,
                    "label": label,
                    "anomaly_score": score,
                }

                if alert is None:
                    alert = NetworkAlert(
                        session_id=session_id,
                        flow_id=flow_id,
                        severity=severity,
                        title="Suspicious network flow detected",
                        description=(
                            f"{flow.get('protocol', 'OTHER')} flow "
                            f"{flow.get('src_ip', '?')}:"
                            f"{flow.get('src_port', 0)} -> "
                            f"{flow.get('dst_ip', '?')}:"
                            f"{flow.get('dst_port', 0)} "
                            "was classified as anomalous by the "
                            "Isolation Forest model."
                        ),
                        anomaly_score=score,
                        flow_data=alert_flow_data,
                        created_at=now,
                    )
                    db.add(alert)
                else:
                    # Update the existing alert as the flow evolves.
                    alert.severity = severity
                    alert.anomaly_score = score
                    alert.flow_data = alert_flow_data

            db.commit()

            return {
                "session_id": session_id,
                "flow_id": flow_id,
                "label": label,
                "anomaly": anomaly,
                "anomaly_score": score,
                "alert_created_or_updated": anomaly,
            }

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

    def _run(self):
        """Poll flow snapshots and assess new or changed flows."""
        from backend.app.services.live_monitor import monitor

        try:
            while not self._stop_event.is_set():
                monitor_status = monitor.status()
                session_id = self._session_id(monitor_status)

                try:
                    flows = monitor.get_flows(limit=1000)
                except Exception:
                    logger.exception(
                        "Unable to retrieve live flow snapshots."
                    )
                    raise

                for flow in flows:
                    if self._stop_event.is_set():
                        break

                    flow_id = int(flow["flow_id"])

                    # Detect whether the snapshot has changed.
                    signature = (
                        flow.get("packet_count"),
                        flow.get("total_bytes"),
                        flow.get("duration"),
                    )

                    key = (session_id, flow_id)

                    if self._processed.get(key) == signature:
                        continue

                    try:
                        self._assess_flow(flow, session_id)

                        # Mark processed only after successful persistence.
                        self._processed[key] = signature

                    except Exception as exc:
                        message = (
                            f"Flow {flow_id} assessment failed: "
                            f"{type(exc).__name__}: {exc}"
                        )

                        logger.exception("%s", message)

                        with self._lock:
                            self._last_error = message

                # When capture or replay ends, process the final snapshots
                # once, then exit. The loop above skips unchanged snapshots.
                if not monitor_status.get("running"):
                    break

                self._stop_event.wait(1.0)

        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"

            logger.exception(
                "Live detection worker failed: %s",
                message,
            )

            with self._lock:
                self._last_error = message


live_detection = LiveDetectionService()
