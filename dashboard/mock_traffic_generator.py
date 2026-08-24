"""
mock_traffic_generator.py  -  Testing utility.
Ported from BSaiCharan-GH/XAI-NIDS dashboard/mock_traffic_generator.py.
Generates synthetic flow dicts and feeds them into the DashboardBridge
to test the dashboard and live inference engine without real network traffic.

Usage:
    python dashboard/mock_traffic_generator.py
    python main.py mock              (via main.py command)
"""

import random
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.dashboard_bridge import bridge_instance
from ml.live_inference import get_engine

# PortScan simulation: 15 unique ports from one source
PORT_SCAN_SEQUENCE = list(range(20, 35))  # 15 unique ports

# SYN flood simulation
SYN_FLOOD_PORTS   = [80, 443, 8080]

BENIGN_SOURCES = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
ATTACK_SOURCE  = "10.0.0.99"
SERVER_IP      = "192.168.1.1"

FEATURE_TEMPLATE = {
    "Flow Duration"            : 1000000,
    "Total Fwd Packets"        : 10,
    "Total Backward Packets"   : 8,
    "Total Length of Fwd Packets": 1400,
    "Total Length of Bwd Packets": 1200,
    "Fwd Packet Length Max"    : 150,
    "Fwd Packet Length Mean"   : 80.0,
    "Fwd Packet Length Std"    : 20.0,
    "Bwd Packet Length Max"    : 120,
    "Bwd Packet Length Mean"   : 70.0,
    "Flow Bytes/s"             : 5000.0,
    "Flow Packets/s"           : 10.0,
    "Flow IAT Mean"            : 100000.0,
    "Flow IAT Std"             : 50000.0,
    "SYN Flag Count"           : 1,
    "ACK Flag Count"           : 8,
    "Destination Port"         : 80,
    "Protocol"                 : 6,
}


def _make_benign_flow(src=None):
    flow = dict(FEATURE_TEMPLATE)
    flow["src_ip"]    = src or random.choice(BENIGN_SOURCES)
    flow["dst_ip"]    = SERVER_IP
    flow["src_port"]  = random.randint(49152, 65535)
    flow["dst_port"]  = random.choice([80, 443])
    flow["protocol"]  = 6
    flow["capture_ts"]= time.time()
    flow["Destination Port"] = flow["dst_port"]
    return flow


def _make_port_scan_flow(port):
    flow = dict(FEATURE_TEMPLATE)
    flow["src_ip"]    = ATTACK_SOURCE
    flow["dst_ip"]    = SERVER_IP
    flow["src_port"]  = random.randint(49152, 65535)
    flow["dst_port"]  = port
    flow["protocol"]  = 6
    flow["capture_ts"]= time.time()
    flow["Total Fwd Packets"] = 1
    flow["SYN Flag Count"]    = 1
    flow["ACK Flag Count"]    = 0
    flow["Destination Port"]  = port
    return flow


def _make_syn_flood_flow(port=80):
    flow = dict(FEATURE_TEMPLATE)
    flow["src_ip"]    = ATTACK_SOURCE
    flow["dst_ip"]    = SERVER_IP
    flow["src_port"]  = random.randint(1024, 65535)
    flow["dst_port"]  = port
    flow["protocol"]  = 6
    flow["capture_ts"]= time.time()
    flow["Total Fwd Packets"] = 50
    flow["SYN Flag Count"]    = 48   # mostly SYN
    flow["ACK Flag Count"]    = 1    # almost no ACK -> SYN flood
    flow["Destination Port"]  = port
    return flow


def run_mock(duration_seconds=60, verbose=True):
    """
    Simulate mixed traffic (benign + port scan + SYN flood).
    Feeds results into DashboardBridge for dashboard testing.
    """
    engine   = get_engine()
    deadline = time.time() + duration_seconds

    print("\n[MOCK] Starting mock traffic generator ({:.0f}s)".format(duration_seconds))
    print("[MOCK] Server: {}  |  Attacker: {}".format(SERVER_IP, ATTACK_SOURCE))
    print("[MOCK] Dashboard bridge: {}".format(bridge_instance._db_path))
    print("[MOCK] Press Ctrl+C to stop.\n")

    flow_count = 0
    try:
        while time.time() < deadline:
            # -- 70% benign
            for _ in range(7):
                flow   = _make_benign_flow()
                result = engine.process_flow(flow)
                bridge_instance.update(result, packet_count=10, active_flows=flow_count)
                flow_count += 1
                if verbose:
                    print("  [BENIGN] {} -> {} | {}".format(
                        flow["src_ip"], flow["dst_ip"], result["ml_prediction"]
                    ))
                time.sleep(0.1)

            # -- 20% port scan (send flows on 15 different ports quickly)
            for port in PORT_SCAN_SEQUENCE:
                flow   = _make_port_scan_flow(port)
                result = engine.process_flow(flow)
                bridge_instance.update(result, packet_count=1, active_flows=flow_count)
                flow_count += 1
                if verbose and result.get("is_attack"):
                    print("  [ALERT] {} | {}: {} -> {}:{}".format(
                        result["final_decision"],
                        result["detection_reason"],
                        flow["src_ip"], flow["dst_ip"], port,
                    ))
                time.sleep(0.05)

            # -- 10% SYN flood
            for _ in range(25):
                flow   = _make_syn_flood_flow()
                result = engine.process_flow(flow)
                bridge_instance.update(result, packet_count=50, active_flows=flow_count)
                flow_count += 1
                if verbose and result.get("is_attack"):
                    print("  [ALERT] {} | {}".format(
                        result["final_decision"], result["detection_reason"]
                    ))
                time.sleep(0.02)

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[MOCK] Stopped by user.")

    print("\n[MOCK] Done. Flows processed: {}".format(flow_count))
    snap = bridge_instance.get_snapshot()
    print("[MOCK] Port scans: {}  DoS events: {}  Alerts: {}".format(
        snap["port_scan_count"], snap["dos_count"], len(snap["alerts"])
    ))


if __name__ == "__main__":
    run_mock(duration_seconds=120, verbose=True)
