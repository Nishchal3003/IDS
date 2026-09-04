"""
discovery.py
------------
UDP LAN server-discovery beacon and scanner for Intelligent-NIDS.

SERVER SIDE — call start_beacon() in a daemon thread:
    Broadcasts "NIDS_SERVER:<ip>:<port>" every BEACON_INTERVAL seconds
    on UDP port DISCOVERY_PORT to 255.255.255.255 (LAN broadcast).

CLIENT SIDE — call find_server():
    Listens on DISCOVERY_PORT for up to SCAN_TIMEOUT seconds.
    Returns (ip, port) if a beacon is found, or None if not.

Design constraints
------------------
- LAN only (UDP broadcast stays within subnet — not routable)
- No authentication — beacon carries only IP:port, no secrets
- Thread-safe (beacon runs in daemon thread; find_server() is blocking)
- Zero dependencies beyond stdlib
"""

import socket
import threading
import time

DISCOVERY_PORT   = 47777          # UDP port used for discovery only
BEACON_INTERVAL  = 3.0            # seconds between beacon broadcasts
SCAN_TIMEOUT     = 5.0            # seconds client waits for a beacon
BEACON_PREFIX    = "NIDS_SERVER:" # fixed prefix so we ignore unrelated UDP noise
BROADCAST_ADDR   = "255.255.255.255"


# ---------------------------------------------------------------------------
# Server side: broadcast beacon
# ---------------------------------------------------------------------------

def start_beacon(server_ip: str, server_port: int) -> threading.Thread:
    """
    Start a daemon thread that broadcasts the server's address every
    BEACON_INTERVAL seconds.  Returns the thread (already started).

    Parameters
    ----------
    server_ip   : str  e.g. "192.168.0.105"
    server_port : int  e.g. 5000
    """
    t = threading.Thread(
        target   = _beacon_loop,
        args     = (server_ip, server_port),
        daemon   = True,
        name     = "nids-discovery-beacon",
    )
    t.start()
    return t


def _beacon_loop(server_ip: str, server_port: int) -> None:
    """Broadcast NIDS_SERVER:<ip>:<port> every BEACON_INTERVAL seconds."""
    message = "{}{}: {}".format(BEACON_PREFIX, server_ip, server_port).encode()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            try:
                sock.sendto(message, (BROADCAST_ADDR, DISCOVERY_PORT))
            except OSError:
                pass   # interface may be briefly unavailable
            time.sleep(BEACON_INTERVAL)
    except Exception as exc:
        print("[Discovery] Beacon stopped: {}".format(exc))
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Client side: scan for beacon
# ---------------------------------------------------------------------------

def find_server(timeout: float = SCAN_TIMEOUT) -> tuple:
    """
    Listen for a NIDS server beacon on the LAN.

    Returns
    -------
    (ip: str, port: int)  if a beacon was found within `timeout` seconds.
    None                  if no beacon was heard (server not running / not on LAN).

    Parameters
    ----------
    timeout : float  How many seconds to listen.  Default SCAN_TIMEOUT.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.bind(("", DISCOVERY_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(256)
                message = data.decode(errors="replace").strip()
                if message.startswith(BEACON_PREFIX):
                    payload = message[len(BEACON_PREFIX):]
                    # payload is "ip: port" or "ip:port"
                    payload = payload.replace(" ", "")
                    ip, port_str = payload.rsplit(":", 1)
                    return (ip.strip(), int(port_str.strip()))
            except socket.timeout:
                break
            except (ValueError, IndexError):
                continue  # malformed beacon — ignore
    except OSError as exc:
        # Port already in use or no network — silently fall through
        print("[Discovery] Scan failed ({}). Enter server IP manually.".format(exc))
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return None
