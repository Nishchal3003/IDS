"""
client.py
---------
Interactive CLI client for the NIDS private communication network.

Run on any machine connected to the same LAN as the server:

    python -m communication.client
    OR
    python communication/client.py

The CLI provides a simple text menu:
    [1] Send chat message
    [2] Send file
    [3] List peers
    [4] Disconnect

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
from communication.logger import get_logger
from communication.protocol import Frame
from communication.utils import get_local_ip, sanitise_alias, timestamp_to_str

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
        pass   # silent keep-alive – don't clutter the terminal


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


def get_server_ip() -> str:
    local = get_local_ip()
    raw = input(
        f"  {CYAN}Server IP address [{local}]:{RESET} "
    ).strip()
    return raw if raw else local


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    """Run the interactive client CLI."""
    print_banner()

    alias     = get_alias()
    server_ip = get_server_ip()
    server_port_str = input(
        f"  {CYAN}Server port [{PORT}]:{RESET} "
    ).strip()
    server_port = int(server_port_str) if server_port_str.isdigit() else PORT

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

        else:
            colour_print("  Unknown command.", YELLOW)

        # Small delay to let the receive thread print any queued frames
        time.sleep(0.1)

    client.disconnect()
    colour_print("\n  Goodbye!\n", GREEN)


if __name__ == "__main__":
    main()
