"""Interactive CLI client for the NIDS private communication network."""

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
G, Y, R, C, RESET, BOLD = "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[0m", "\033[1m"

def cp(text: str, col: str = RESET) -> None:
    print(f"{col}{text}{RESET}")

def display_frame(frame: Frame) -> None:
    ts = timestamp_to_str(frame.timestamp)
    if frame.msg_type == MsgType.BROADCAST:
        cp(f"\n  [{ts}] {BOLD}{frame.extra.get('from', frame.sender)}{RESET}{C}: {frame.text}", C)
    elif frame.msg_type == MsgType.WELCOME:
        peers = frame.extra.get("peers", [])
        cp(f"\n  [{ts}] SERVER: {frame.text}", G)
        if peers: cp(f"         Online: {', '.join(peers)}", G)
    elif frame.msg_type in (MsgType.PEER_JOIN, MsgType.PEER_LEAVE):
        cp(f"\n  [{ts}] ** {frame.text}", Y)
    elif frame.msg_type == MsgType.ACK:
        cp(f"\n  [{ts}] [OK] {frame.text}", G)
    elif frame.msg_type in (MsgType.ERROR, MsgType.SERVER_FULL):
        cp(f"\n  [{ts}] [ERR] {frame.text}", R)

def display_disconnected(reason: str) -> None:
    cp(f"\n  [!] Disconnected: {reason}", R)

def print_banner() -> None:
    print(f"\n{C}{'='*50}\n  NIDS Private Network Client\n{'='*50}{RESET}\n")

def print_menu() -> None:
    print(f"\n{BOLD}  Commands:{RESET}  {G}[1]{RESET} Chat  {G}[2]{RESET} Send file  {G}[3]{RESET} List peers  {G}[4/q]{RESET} Quit\n")

def main() -> None:
    print_banner()
    while True:
        try:
            alias = sanitise_alias(input(f"  {C}Alias (2-20 chars):{RESET} ").strip())
            break
        except ValueError as e:
            cp(f"  {e}", R)
    local = get_local_ip()
    raw = input(f"  {C}Server IP [{local}]:{RESET} ").strip()
    server_ip = raw or local
    raw_port  = input(f"  {C}Server port [{PORT}]:{RESET} ").strip()
    server_port = int(raw_port) if raw_port.isdigit() else PORT

    client = NIDSClient(alias, server_ip, server_port,
                        on_frame=display_frame, on_disconnected=display_disconnected)
    cp(f"\n  Connecting to {server_ip}:{server_port}...", Y)
    if not client.connect():
        cp("  Failed to connect.", R); sys.exit(1)
    cp("  Connected!\n", G)

    while client.is_connected():
        print_menu()
        try:
            choice = input(f"  {BOLD}>{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if choice in ("4", "q"):
            break
        elif choice == "1":
            try: msg = input(f"  {C}Message:{RESET} ").strip()
            except (EOFError, KeyboardInterrupt): break
            if msg: client.send_chat(msg)
            else: cp("  Empty message ignored.", Y)
        elif choice == "2":
            try: path = input(f"  {C}File path:{RESET} ").strip()
            except (EOFError, KeyboardInterrupt): break
            if path:
                cp("  Sending...", Y)
                cp("  [OK] Sent." if client.send_file(path) else "  [ERR] Failed.", G if client.send_file else R)
            else: cp("  No path given.", Y)
        elif choice == "3":
            ps = client.peers
            cp(f"  Peers ({len(ps)}): {', '.join(ps) if ps else 'none'}", C)
        else:
            cp("  Unknown command.", Y)
        time.sleep(0.1)

    client.disconnect()
    cp("\n  Goodbye!\n", G)

if __name__ == "__main__":
    main()
