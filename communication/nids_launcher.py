"""
nids_launcher.py
----------------
All-in-one launcher for the NIDS server role.

Invoked by:
    python main.py nids

Starts four services in parallel:
  1. UDP discovery beacon  (daemon thread — broadcasts server IP to LAN)
  2. Communication server  (daemon thread — handles client connections)
  3. Packet capture + live detection  (daemon thread — sniffs real traffic)
  4. Streamlit dashboard   (subprocess — runs until Ctrl+C)

Shutdown:
  Ctrl+C stops the Streamlit subprocess and signals all daemon threads to exit.

Design constraints
------------------
- Does NOT replace any existing module (server_core, capture_daemon, etc.)
- Capture interface is auto-detected (best non-loopback LAN interface)
- All components use the existing DashboardBridge / SQLite IPC
"""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Auto-detect best capture interface
# ---------------------------------------------------------------------------

def _best_interface() -> str:
    """
    Return the name of the best LAN interface for capture.
    Preference order: WiFi > Ethernet > first non-loopback.
    Falls back to None (Scapy auto-selects).
    """
    try:
        from capture.sniffer import check_capture_backend
        if not check_capture_backend():
            return None
        # Try to get interface list from Scapy
        from scapy.all import get_if_list, get_if_addr
        preferred_keywords = ["wi-fi", "wifi", "wlan", "ethernet", "eth", "local area"]
        loopback_keywords  = ["loopback", "127.", "npcap loopback"]
        candidates = []
        for iface in get_if_list():
            name_lower = iface.lower()
            if any(k in name_lower for k in loopback_keywords):
                continue
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                    score = next(
                        (i for i, k in enumerate(preferred_keywords) if k in name_lower),
                        len(preferred_keywords),
                    )
                    candidates.append((score, iface))
            except Exception:
                continue
        if candidates:
            candidates.sort()
            return candidates[0][1]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Thread runners
# ---------------------------------------------------------------------------

def _run_comms_server(stop_event: threading.Event) -> None:
    """Run NIDSServer in the current thread (blocks until stop_event is set)."""
    try:
        from communication.server import main as server_main
        # server_main() is blocking — runs until Ctrl+C or process exit
        server_main()
    except Exception as exc:
        print("[NIDS Launcher] Communication server stopped: {}".format(exc))


def _run_capture(iface: str, stop_event: threading.Event) -> None:
    """Run capture + live detection in the current thread."""
    try:
        from capture.capture_daemon import main as capture_main
        argv = ["--live"]
        if iface:
            argv += ["-i", iface]
        capture_main(argv)
    except Exception as exc:
        print("[NIDS Launcher] Capture stopped: {}".format(exc))


# ---------------------------------------------------------------------------
# Main launcher
# ---------------------------------------------------------------------------

def run_nids_server() -> None:
    """Start all NIDS server services. Blocks until Ctrl+C."""
    from communication.utils import get_local_ip
    from communication.discovery import start_beacon

    try:
        from config.network_config import PORT
    except ImportError:
        PORT = 5000

    lan_ip = get_local_ip()
    iface  = _best_interface()

    _print_banner(lan_ip, PORT, iface)

    # ── 1. Discovery beacon ───────────────────────────────────────────────
    start_beacon(lan_ip, PORT)
    print("  [OK] Discovery beacon active — clients will auto-connect")

    # ── 2. Communication server (daemon thread) ───────────────────────────
    stop_event = threading.Event()
    comms_thread = threading.Thread(
        target = _run_comms_server,
        args   = (stop_event,),
        daemon = True,
        name   = "nids-comms-server",
    )
    comms_thread.start()
    time.sleep(0.5)   # let server bind before printing
    print("  [OK] Communication server started on port {}".format(PORT))

    # ── 3. Capture + live detection (daemon thread) ───────────────────────
    capture_thread = threading.Thread(
        target = _run_capture,
        args   = (iface, stop_event),
        daemon = True,
        name   = "nids-capture",
    )
    capture_thread.start()
    time.sleep(0.5)
    print("  [OK] Packet capture + live detection started")

    # ── 4. Streamlit dashboard (subprocess — blocks until Ctrl+C) ─────────
    dashboard_path = str(PROJECT_ROOT / "dashboard" / "dashboard.py")
    print("  [OK] Dashboard starting at http://localhost:8501")
    print()
    print("  All services running. Press Ctrl+C to stop.\n")

    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", dashboard_path,
             "--server.headless", "true"],
            cwd = str(PROJECT_ROOT),
        )
        proc.wait()
    except KeyboardInterrupt:
        print("\n\n  Ctrl+C — shutting down NIDS services...")
    finally:
        stop_event.set()
        try:
            proc.terminate()
        except Exception:
            pass
        print("  Goodbye.\n")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _print_banner(lan_ip: str, port: int, iface: str) -> None:
    print()
    print("=" * 60)
    print("  Intelligent NIDS — Server Mode")
    print("=" * 60)
    print("  LAN IP      : {}".format(lan_ip))
    print("  Comm server : {}:{}".format(lan_ip, port))
    print("  Dashboard   : http://localhost:8501")
    print("  Interface   : {}".format(iface or "auto-detect"))
    print("  Detection   : PortScan + DoS (Behavioural + ML)")
    print("  Discovery   : UDP broadcast → clients auto-find this server")
    print("=" * 60)
    print()
