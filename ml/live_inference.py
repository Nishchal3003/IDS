"""
live_inference.py  -  Phase 4 real-time detection engine.
PRIMARY FOCUS: PortScan and DoS attack detection.

Combines:
  1. ML classifier     (ml/predict.py :: classify_flow)
  2. PortScanDetector  - sliding-window behavioural port scan detection
  3. SYNFloodDetector  - sliding-window SYN-flood / DoS detection

PortScanDetector is ported verbatim from BSaiCharan-GH/XAI-NIDS ml/live_inference.py.
SYNFloodDetector and LiveInferenceEngine are completed following the same design
pattern (the XAI-NIDS source was committed truncated).
"""

from collections import defaultdict, deque
import time
import numpy as np


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _capture_timestamp(value):
    """Convert any timestamp representation to Unix seconds. From XAI-NIDS."""
    if value is None:
        return time.time()
    if isinstance(value, (int, float, np.integer, np.floating)):
        v = float(value)
        return v if np.isfinite(v) else time.time()
    try:
        import pandas as pd
        return pd.Timestamp(value).timestamp()
    except Exception:
        return time.time()


def _to_number(value, default=0):
    """Safely coerce value to float."""
    try:
        v = float(value)
        return v if np.isfinite(v) else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# PortScanDetector  (PRIMARY focus)
# ---------------------------------------------------------------------------

class PortScanDetector:
    """
    Sliding-window port-scan detector.

    Detects when a single source IP contacts >= minimum_unique_ports distinct
    destination ports on a single target within window_seconds.

    Ported verbatim from BSaiCharan-GH/XAI-NIDS ml/live_inference.py.
    """

    def __init__(self, window_seconds=5.0, minimum_unique_ports=10, cooldown_seconds=10.0):
        self.window_seconds       = float(window_seconds)
        self.minimum_unique_ports = int(minimum_unique_ports)
        self.cooldown_seconds     = float(cooldown_seconds)
        self.connections          = defaultdict(deque)
        self.last_alert           = {}

    def process_flow(self, features):
        source           = features.get("src_ip")
        destination      = features.get("dst_ip")
        destination_port = features.get("dst_port") or features.get("Destination Port")

        if not source or not destination:
            return {"detected": False}
        if destination_port is None:
            return {"detected": False}
        try:
            destination_port = int(destination_port)
        except (TypeError, ValueError):
            return {"detected": False}

        now = _capture_timestamp(features.get("capture_ts"))
        key = (str(source), str(destination))

        self.connections[key].append({"time": now, "port": destination_port})

        cutoff = now - self.window_seconds
        while self.connections[key] and self.connections[key][0]["time"] < cutoff:
            self.connections[key].popleft()

        flows        = self.connections[key]
        unique_ports = len({item["port"] for item in flows})
        connections  = len(flows)
        elapsed      = max(now - flows[0]["time"], 0.001) if flows else 0.001
        scan_rate    = connections / elapsed

        detected   = unique_ports >= self.minimum_unique_ports
        suppressed = False
        if detected:
            last_alert = self.last_alert.get(key, 0.0)
            if now - last_alert < self.cooldown_seconds:
                suppressed = True
            else:
                self.last_alert[key] = now

        return {
            "detected"    : detected,
            "suppressed"  : suppressed,
            "source"      : source,
            "destination" : destination,
            "unique_ports": unique_ports,
            "connections" : connections,
            "scan_rate"   : round(scan_rate, 2),
            "attack_type" : "PortScan",
        }


# ---------------------------------------------------------------------------
# SYNFloodDetector  (DoS focus)
# ---------------------------------------------------------------------------

class SYNFloodDetector:
    """
    Sliding-window SYN-flood / DoS detector.

    Triggers when ALL conditions met in window_seconds:
      - total SYN packets >= minimum_syn_packets
      - number of flows   >= minimum_syn_flows
      - SYN rate          >= minimum_syn_rate  packets/sec
      - ACK/SYN ratio     <= maximum_ack_ratio  (most SYNs unanswered)

    Ported from BSaiCharan-GH/XAI-NIDS ml/live_inference.py
    (completed where source was truncated).
    """

    def __init__(
        self,
        window_seconds=5.0,
        minimum_syn_packets=20,
        minimum_syn_flows=10,
        minimum_syn_rate=10.0,
        maximum_ack_ratio=0.25,
        cooldown_seconds=10.0,
    ):
        self.window_seconds      = float(window_seconds)
        self.minimum_syn_packets = int(minimum_syn_packets)
        self.minimum_syn_flows   = int(minimum_syn_flows)
        self.minimum_syn_rate    = float(minimum_syn_rate)
        self.maximum_ack_ratio   = float(maximum_ack_ratio)
        self.cooldown_seconds    = float(cooldown_seconds)
        self.connections         = defaultdict(deque)
        self.last_alert          = {}

    def process_flow(self, features):
        source      = features.get("src_ip")
        destination = features.get("dst_ip")
        if not source or not destination:
            return {"detected": False}

        # Pull SYN/ACK counts from CIC-IDS 2017 feature names
        syn_count = _to_number(features.get("SYN Flag Count") or features.get("syn_flag_count"), 0)
        ack_count = _to_number(features.get("ACK Flag Count") or features.get("ack_flag_count"), 0)
        total_fwd = _to_number(features.get("Total Fwd Packets") or features.get("total_fwd_packets"), 0)
        if syn_count == 0 and total_fwd > 0:
            syn_count = total_fwd * 0.8   # heuristic when flag counters absent

        now = _capture_timestamp(features.get("capture_ts"))
        key = (str(source), str(destination))
        self.connections[key].append({"time": now, "syn": syn_count, "ack": ack_count})

        cutoff = now - self.window_seconds
        while self.connections[key] and self.connections[key][0]["time"] < cutoff:
            self.connections[key].popleft()

        flows = self.connections[key]
        if not flows:
            return {"detected": False}

        total_syn = sum(f["syn"] for f in flows)
        total_ack = sum(f["ack"] for f in flows)
        elapsed   = max(now - flows[0]["time"], 0.001)
        syn_rate  = total_syn / elapsed
        ack_ratio = (total_ack / total_syn) if total_syn > 0 else 1.0

        detected = (
            total_syn  >= self.minimum_syn_packets and
            len(flows) >= self.minimum_syn_flows   and
            syn_rate   >= self.minimum_syn_rate    and
            ack_ratio  <= self.maximum_ack_ratio
        )

        suppressed = False
        if detected:
            last_alert = self.last_alert.get(key, 0.0)
            if now - last_alert < self.cooldown_seconds:
                suppressed = True
            else:
                self.last_alert[key] = now

        return {
            "detected"   : detected,
            "suppressed" : suppressed,
            "source"     : source,
            "destination": destination,
            "total_syn"  : round(total_syn),
            "total_ack"  : round(total_ack),
            "ack_ratio"  : round(ack_ratio, 3),
            "syn_rate"   : round(syn_rate, 2),
            "attack_type": "DoS_SYNFlood",
        }


# ---------------------------------------------------------------------------
# LiveInferenceEngine  (Phase 4 integration layer)
# ---------------------------------------------------------------------------

class LiveInferenceEngine:
    """
    Integrates ML model prediction with behavioural anomaly detectors.
    Called via CaptureLogger.on_flow_completed hook (see capture_logger.py).

    Design (from XAI-NIDS architecture):
        completed flow dict
            -> classify_flow()         (ML: best trained model)
            -> PortScanDetector        (behavioural: sliding window)
            -> SYNFloodDetector        (behavioural: SYN ratio)
        => final_decision dict  -> DashboardBridge
    """

    def __init__(
        self,
        port_scan_window    = 5.0,
        port_scan_min_ports = 10,
        syn_flood_window    = 5.0,
        syn_flood_min_syn   = 20,
    ):
        self.port_scan_detector = PortScanDetector(
            window_seconds=port_scan_window,
            minimum_unique_ports=port_scan_min_ports,
        )
        self.syn_flood_detector = SYNFloodDetector(
            window_seconds=syn_flood_window,
            minimum_syn_packets=syn_flood_min_syn,
        )
        self._ml_ready = None

    def _ml_is_available(self):
        if self._ml_ready is None:
            try:
                from ml.predict import model_is_ready
                self._ml_ready = model_is_ready()
            except Exception:
                self._ml_ready = False
        return self._ml_ready

    def process_flow(self, flow):
        """
        Process one completed flow dict.

        Parameters
        ----------
        flow : dict
            CIC-IDS 2017 feature names from capture.feature_extractor,
            plus identity fields: src_ip, dst_ip, src_port, dst_port,
            protocol, capture_ts.

        Returns
        -------
        dict with keys consumed by DashboardBridge.update():
            ml_prediction, confidence, behavioural_detection,
            final_decision, detection_reason, is_attack,
            src_ip, dst_ip, src_port, dst_port, protocol, timestamp
        """
        ts = _capture_timestamp(flow.get("capture_ts"))

        # 1. ML classification
        ml_label, confidence, probabilities = "UNKNOWN", 0.0, {}
        if self._ml_is_available():
            try:
                from ml.predict import classify_flow
                r          = classify_flow(flow)
                ml_label   = r.get("label", "UNKNOWN")
                confidence = r.get("confidence", 0.0)
                probabilities = r.get("probabilities", {})
            except Exception:
                ml_label = "MODEL_ERROR"
        else:
            ml_label = "NO_MODEL"

        # 2. Behavioural detection  (always runs, even without a model)
        ps = self.port_scan_detector.process_flow(flow)
        sf = self.syn_flood_detector.process_flow(flow)

        # Detect behavioural threats — suppressed means "alert already sent, don't spam"
        # but the attack is still ongoing. We include it in the result either way.
        ps_detected = ps.get("detected", False)
        sf_detected = sf.get("detected", False)
        ps_suppressed = ps.get("suppressed", False)
        sf_suppressed = sf.get("suppressed", False)

        behavioural = None
        if ps_detected:
            behavioural = "PortScan"        # include suppressed — attack is ongoing
        elif sf_detected:
            behavioural = "DoS_SYNFlood"

        # 3. Final decision  (behavioural overrides ML when triggered)
        if behavioural == "PortScan":
            final_decision = "PortScan"
            reason = "Behavioural PortScan: {} unique ports in {} flows{}".format(
                ps.get("unique_ports", 0), ps.get("connections", 0),
                " [cooldown]" if ps_suppressed else "",
            )
        elif behavioural == "DoS_SYNFlood":
            final_decision = "DoS"
            reason = "Behavioural SYNFlood: {:.0f} SYN, ACK ratio={:.2f}{}".format(
                sf.get("total_syn", 0), sf.get("ack_ratio", 0),
                " [cooldown]" if sf_suppressed else "",
            )
        else:
            final_decision = ml_label
            reason = "ML ({:.1f}% confidence)".format(confidence * 100)

        is_attack = final_decision not in ("BENIGN", "UNKNOWN", "NO_MODEL", "MODEL_ERROR")

        return {
            "timestamp"            : ts,
            "src_ip"               : flow.get("src_ip", ""),
            "dst_ip"               : flow.get("dst_ip", ""),
            "src_port"             : flow.get("src_port", 0),
            "dst_port"             : flow.get("dst_port") or flow.get("Destination Port", 0),
            "protocol"             : flow.get("protocol", 0),
            "ml_prediction"        : ml_label,
            "confidence"           : round(confidence, 4),
            "behavioural_detection": behavioural,
            "final_decision"       : final_decision,
            "detection_reason"     : reason,
            "is_attack"            : is_attack,
            "probabilities"        : probabilities,
        }



# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine = None


def get_engine():
    """Return (lazily creating) the module-level LiveInferenceEngine singleton."""
    global _engine
    if _engine is None:
        _engine = LiveInferenceEngine()
    return _engine
