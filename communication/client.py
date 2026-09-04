"""
client.py
---------
Interactive CLI client for the NIDS private communication network.

Run on any machine connected to the same LAN as the server:

    python main.py client
    OR
    python -m communication.client

The client auto-discovers the NIDS server on the LAN via UDP broadcast.
No IP address needs to be typed in normal use.

Menu:
    [1] Send chat message
    [2] Send file
    [3] List peers
    [4] Disconnect and exit
    [5] Security Testing (PortScan / DoS)

All incoming frames are printed to the console in real time.
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from communication.client_core import NIDSClient
from communication.constants import MsgType
from communication.discovery import find_server
from communication.logger import get_logger
from communication.protocol import Frame, build_text_frame
from communication.utils import get_local_ip, sanitise_alias, timestamp_to_str, safe_send

try:
    from config.network_config import PORT
except ImportError:
    PORT = 5000

log = get_logger("client")

# ── ANSI colour codes (work on Windows 10+ via ANSI escape support) ──────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def colour_print(text: str, colour: str = RESET) -> None:
    print(f"{colour}{text}{RESET}")


# ---------------------------------------------------------------------------
# Frame display callback
# ---------------------------------------------------------------------------
def display_frame(frame: Frame) -> None:
    """Pretty-print an incoming frame to the console."""
    ts = timestamp_to_str(frame.timestamp)

    if frame.msg_type == MsgType.BROADCAST:
        sender = frame.extra.get("from", frame.sender)
        # Security test announcements get a distinct marker
        if frame.extra.get("test_type"):
            colour_print(
                f"\n  [{ts}] SECURITY TEST  {sender}: {frame.text}",
                YELLOW,
            )
        else:
            colour_print(
                f"\n  [{ts}] {BOLD}{sender}{RESET}{CYAN}: {frame.text}",
                CYAN,
            )

    elif frame.msg_type == MsgType.WELCOME:
        peers = frame.extra.get("peers", [])
        colour_print(f"\n  [{ts}] SERVER: {frame.text}", GREEN)
        if peers:
            colour_print(f"         Online peers: {', '.join(peers)}", GREEN)

    elif frame.msg_type in (MsgType.PEER_JOIN, MsgType.PEER_LEAVE):
        colour_print(f"\n  [{ts}] ** {frame.text}", YELLOW)

    elif frame.msg_type == MsgType.ACK:
        colour_print(f"\n  [{ts}] [OK] {frame.text}", GREEN)

    elif frame.msg_type == MsgType.ERROR:
        colour_print(f"\n  [{ts}] [ERR] SERVER ERROR: {frame.text}", RED)

    elif frame.msg_type == MsgType.SERVER_FULL:
        colour_print(f"\n  [{ts}] [ERR] {frame.text}", RED)

    elif frame.msg_type in (MsgType.PING, MsgType.PONG):
        pass   # silent keep-alive


def display_disconnected(reason: str) -> None:
    colour_print(f"\n  [!] Disconnected: {reason}", RED)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def print_banner() -> None:
    print(f"""
{CYAN}{'='*60}
  NIDS Private Network Client
  Intelligent Network Intrusion Detection System
{'='*60}{RESET}
""")


def print_menu() -> None:
    print(f"""
{BOLD}  Commands:{RESET}
    {GREEN}[1]{RESET} Send chat message
    {GREEN}[2]{RESET} Send file
    {GREEN}[3]{RESET} List online peers
    {GREEN}[4]{RESET} Disconnect and exit
    {GREEN}[5]{RESET} Security Testing
    {GREEN}[q]{RESET} Disconnect and exit
""")


def get_alias() -> str:
    while True:
        try:
            raw = input(
                f"  {CYAN}Enter your device alias (2-20 alphanumeric chars):{RESET} "
            ).strip()
            return sanitise_alias(raw)
        except ValueError as exc:
            colour_print(f"  Invalid alias: {exc}", RED)


def get_server_address() -> tuple:
    """
    Auto-discover NIDS server via UDP broadcast.
    Falls back to manual IP entry if no server is found within 5 seconds.

    Returns (ip: str, port: int).
    """
    colour_print("\n  Scanning LAN for NIDS server (5 seconds)...", YELLOW)
    result = find_server(timeout=5.0)

    if result:
        ip, port = result
        colour_print(f"  [AUTO] Found NIDS server at {ip}:{port}", GREEN)
        confirm = input(
            f"  {CYAN}Press ENTER to connect, or type a different IP:{RESET} "
        ).strip()
        if confirm:
            ip = confirm
        port_str = input(
            f"  {CYAN}Port [{port}]:{RESET} "
        ).strip()
        port = int(port_str) if port_str.isdigit() else port
        return ip, port

    colour_print("  [!] No server found automatically.", YELLOW)
    colour_print("  Make sure the server is running: python main.py nids", YELLOW)
    local = get_local_ip()
    raw = input(f"  {CYAN}Server IP address [{local}]:{RESET} ").strip()
    ip = raw if raw else local
    port_str = input(f"  {CYAN}Server port [{PORT}]:{RESET} ").strip()
    port = int(port_str) if port_str.isdigit() else PORT
    return ip, port


# ---------------------------------------------------------------------------
# Security testing sub-menu
# ---------------------------------------------------------------------------

def _send_security_test_frame(client: NIDSClient, test_type: str,
                               target: str, status: str) -> None:
    """Broadcast SECURITY_TEST metadata frame (experiment logging only)."""
    try:
        frame = build_text_frame(
            MsgType.SECURITY_TEST,
            client.alias,
            f"{test_type} {status}",
            extra={
                "test_type": test_type,
                "target"   : target,
                "status"   : status,
            },
        )
        safe_send(client._sock, frame)
    except Exception:
        pass   # metadata failure must never abort the test


def _run_portscan(client: NIDSClient, target: str) -> None:
    """Run PortScan test synchronously with live progress output."""
    try:
        from attacks.portscan_test import run_portscan, _is_private, _print_banner
        import argparse
    except ImportError:
        colour_print("  [ERR] attacks/portscan_test.py not found.", RED)
        return

    if not _is_private(target):
        colour_print(f"  [ERR] {target} is not a private/LAN IP. Aborting.", RED)
        return

    colour_print(f"\n  Starting PortScan test -> {target}", YELLOW)
    _send_security_test_frame(client, "PortScan", target, "started")

    try:
        ns = argparse.Namespace(
            target=target, port_from=20, port_to=120,
            rate=200, ports=None,
        )
        _print_banner(ns)
        run_portscan(target=target, port_from=20, port_to=120, rate=200, verbose=True)
    except Exception as exc:
        colour_print(f"  [ERR] PortScan error: {exc}", RED)

    _send_security_test_frame(client, "PortScan", target, "done")
    colour_print("\n  [OK] PortScan complete. Check dashboard for alerts.", GREEN)
    colour_print("       http://localhost:8501", CYAN)


def _run_dos(client: NIDSClient, target: str) -> None:
    """Run DoS test synchronously with live progress output."""
    try:
        from attacks.dos_test import run_dos_test, _is_private, _print_banner
        import argparse
    except ImportError:
        colour_print("  [ERR] attacks/dos_test.py not found.", RED)
        return

    if not _is_private(target):
        colour_print(f"  [ERR] {target} is not a private/LAN IP. Aborting.", RED)
        return

    colour_print(f"\n  Starting DoS test -> {target}:5000", YELLOW)
    _send_security_test_frame(client, "DoS", target, "started")

    try:
        ns = argparse.Namespace(
            target=target, port=5000, rate=150, duration=10,
        )
        _print_banner(ns)
        run_dos_test(target=target, port=5000, rate=150, duration=10, verbose=True)
    except Exception as exc:
        colour_print(f"  [ERR] DoS error: {exc}", RED)

    _send_security_test_frame(client, "DoS", target, "done")
    colour_print("\n  [OK] DoS test complete. Check dashboard for alerts.", GREEN)
    colour_print("       http://localhost:8501", CYAN)


def handle_security_testing(client: NIDSClient, server_ip: str) -> None:
    """Security testing sub-menu. Target defaults to the connected server IP."""
    target = server_ip

    print(f"""
{BOLD}  Security Testing{RESET}
  Target : {CYAN}{target}{RESET}  (NIDS server on the same LAN)
  Note   : Detection comes from REAL PACKETS captured by the server,
           not from this menu selection.

    {GREEN}[a]{RESET} PortScan Test
    {GREEN}[b]{RESET} DoS Test
    {GREEN}[c]{RESET} Both (PortScan then DoS)
    {GREEN}[x]{RESET} Back to main menu
""")
    try:
        choice = input(f"  {BOLD}>{RESET} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice == "a":
        _run_portscan(client, target)
    elif choice == "b":
        _run_dos(client, target)
    elif choice == "c":
        _run_portscan(client, target)
        colour_print("\n  Waiting 5s before DoS test...", YELLOW)
        time.sleep(5)
        _run_dos(client, target)
    elif choice in ("x", ""):
        return
    else:
        colour_print("  Unknown option.", YELLOW)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    """Run the interactive client CLI."""
    print_banner()

    alias = get_alias()
    server_ip, server_port = get_server_address()

    client = NIDSClient(
        alias=alias,
        server_host=server_ip,
        server_port=server_port,
        on_frame=display_frame,
        on_disconnected=display_disconnected,
    )

    colour_print(f"\n  Connecting to {server_ip}:{server_port} ...", YELLOW)
    if not client.connect():
        colour_print("  Failed to connect. Exiting.", RED)
        sys.exit(1)

    colour_print("  Connection established!\n", GREEN)

    # ── Main interaction loop ─────────────────────────────────────────────
    while client.is_connected():
        print_menu()
        try:
            choice = input(f"  {BOLD}>{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("4", "q"):
            break

        elif choice == "1":
            try:
                msg = input(f"  {CYAN}Message:{RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if msg:
                client.send_chat(msg)
            else:
                colour_print("  Empty message ignored.", YELLOW)

        elif choice == "2":
            try:
                path = input(f"  {CYAN}File path:{RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if path:
                colour_print("  Sending file...", YELLOW)
                ok = client.send_file(path)
                if ok:
                    colour_print("  [OK] File sent successfully.", GREEN)
                else:
                    colour_print("  [ERR] File transfer failed.", RED)
            else:
                colour_print("  No path given.", YELLOW)

        elif choice == "3":
            peers = client.peers
            if peers:
                colour_print(f"  Online peers ({len(peers)}):", CYAN)
                for p in peers:
                    colour_print(f"    • {p}", CYAN)
            else:
                colour_print("  No other peers online.", YELLOW)

        elif choice == "5":
            handle_security_testing(client, server_ip)

        else:
            colour_print("  Unknown command.", YELLOW)

        # Small delay to let the receive thread print any queued frames
        time.sleep(0.1)

    client.disconnect()
    colour_print("\n  Goodbye!\n", GREEN)


if __name__ == "__main__":
    main()
