"""Core client logic for the Intelligent-NIDS private communication network."""

import math
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from communication.constants import (
    FILE_CHUNK_SIZE, MAX_RECONNECT_TRIES, MsgType, RECONNECT_DELAY, SOCKET_TIMEOUT, USE_TLS,
)
from communication.logger import get_logger
from communication.protocol import Frame, build_file_chunk_frame, build_text_frame, recv_frame
from communication.tls import client_ssl_context
from communication.utils import (
    format_size, get_file_chunks, safe_send, timestamp_to_str, validate_file_for_transfer,
)

log = get_logger("client")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RECEIVED_DIR = PROJECT_ROOT / "received_files" / "client"

FrameCallback      = Callable[[Frame], None]
DisconnectCallback = Callable[[str], None]


class NIDSClient:
    """TCP client for the NIDS private network."""

    def __init__(self, alias: str, server_host: str, server_port: int,
                 on_frame: Optional[FrameCallback] = None,
                 on_disconnected: Optional[DisconnectCallback] = None) -> None:
        self.alias       = alias
        self.server_host = server_host
        self.server_port = server_port
        self.on_frame       = on_frame
        self.on_disconnected = on_disconnected
        self._sock: Optional[socket.socket] = None
        self._alive  = False
        self._peers: list[str] = []
        self._file_ack_event  = threading.Event()
        self._incoming_name:   Optional[str] = None
        self._incoming_chunks: int     = 0
        self._incoming_rcvd:   int     = 0
        self._incoming_buf:    bytearray = bytearray()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        for attempt in range(1, MAX_RECONNECT_TRIES + 1):
            try:
                log.info("Connecting to %s:%s (attempt %d/%d)",
                         self.server_host, self.server_port, attempt, MAX_RECONNECT_TRIES)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)
                sock.connect((self.server_host, self.server_port))
                if USE_TLS:
                    try:
                        sock = client_ssl_context(verify=True).wrap_socket(
                            sock, server_hostname=self.server_host)
                        log.info("TLS handshake OK (verified)")
                    except Exception as e:
                        log.warning("TLS verify failed (%s) — retrying without", e)
                        sock.close()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(SOCKET_TIMEOUT)
                        sock.connect((self.server_host, self.server_port))
                        sock = client_ssl_context(verify=False).wrap_socket(
                            sock, server_hostname=self.server_host)
                self._sock  = sock
                self._alive = True
                self._send_hello()
                threading.Thread(target=self._recv_loop, daemon=True,
                                 name=f"recv-{self.alias}").start()
                log.info("Connected as '%s'", self.alias)
                return True
            except (ConnectionRefusedError, OSError) as e:
                log.warning("Attempt %d failed: %s", attempt, e)
                if attempt < MAX_RECONNECT_TRIES:
                    time.sleep(RECONNECT_DELAY)
        log.error("All %d attempts failed.", MAX_RECONNECT_TRIES)
        return False

    def disconnect(self, reason: str = "user request") -> None:
        if not self._alive:
            return
        self._alive = False
        try:
            self._sock.sendall(build_text_frame(MsgType.DISCONNECT, self.alias, reason))
        except OSError:
            pass
        finally:
            if self._sock: self._sock.close()

    def is_connected(self) -> bool:
        return self._alive

    @property
    def peers(self) -> list[str]:
        return list(self._peers)

    # ── Sending ───────────────────────────────────────────────────────────────

    def send_chat(self, text: str) -> bool:
        if not self._alive:
            log.warning("Not connected"); return False
        ok = safe_send(self._sock, build_text_frame(MsgType.CHAT, self.alias, text))
        if ok: log.info("[CHAT] Me → %s", text)
        return ok

    def send_file(self, path: str) -> bool:
        if not self._alive:
            log.warning("Not connected"); return False
        try:
            fp = validate_file_for_transfer(path)
        except (FileNotFoundError, IsADirectoryError, ValueError) as e:
            log.error("File validation failed: %s", e); return False

        name   = fp.name
        size   = fp.stat().st_size
        chunks = math.ceil(size / FILE_CHUNK_SIZE)
        if not safe_send(self._sock, build_text_frame(
                MsgType.FILE_META, self.alias, "",
                extra={"file_name": name, "file_size": size, "total_chunks": chunks})):
            return False
        log.info("[FILE] Sending '%s' (%s, %d chunks)", name, format_size(size), chunks)
        for idx, chunk in enumerate(get_file_chunks(fp)):
            if not safe_send(self._sock, build_file_chunk_frame(self.alias, chunk, name, idx, chunks)):
                log.error("Chunk %d failed", idx); return False
            self._file_ack_event.clear()
            if not self._file_ack_event.wait(timeout=30):
                log.error("Timeout on FILE_ACK chunk %d", idx); return False
        if not safe_send(self._sock, build_text_frame(MsgType.FILE_DONE, self.alias, name)):
            return False
        log.info("[FILE] Transfer of '%s' done", name)
        return True

    # ── Receive loop ──────────────────────────────────────────────────────────

    def _recv_loop(self) -> None:
        while self._alive:
            try:
                frame = recv_frame(self._sock)
                if frame is None:
                    log.info("Server closed connection"); break
                self._dispatch(frame)
            except (ConnectionError, ValueError) as e:
                log.warning("Recv error: %s", e); break
            except OSError as e:
                if self._alive: log.error("Socket error: %s", e)
                break
        self._alive = False
        if self.on_disconnected:
            self.on_disconnected("Connection lost")

    def _dispatch(self, frame: Frame) -> None:
        {
            MsgType.WELCOME      : self._on_welcome,
            MsgType.PING         : self._on_ping,
            MsgType.PEER_JOIN    : self._on_peer_join,
            MsgType.PEER_LEAVE   : self._on_peer_leave,
            MsgType.FILE_ACK     : lambda f: self._file_ack_event.set(),
            MsgType.FILE_META    : self._on_file_meta,
            MsgType.FILE_CHUNK   : self._on_file_chunk,
            MsgType.FILE_DONE    : self._on_file_done,
            MsgType.FILE_INCOMING: self._on_file_incoming,
            MsgType.DISCONNECT   : lambda f: setattr(self, "_alive", False),
        }.get(frame.msg_type, lambda f: None)(frame)
        if self.on_frame:
            self.on_frame(frame)

    # ── Built-in handlers ─────────────────────────────────────────────────────

    def _on_welcome(self, frame: Frame) -> None:
        self._peers = frame.extra.get("peers", [])
        log.info("WELCOME: %s | Peers: %s", frame.text, self._peers)

    def _on_ping(self, frame: Frame) -> None:
        safe_send(self._sock, build_text_frame(MsgType.PONG, self.alias, ""))

    def _on_peer_join(self, frame: Frame) -> None:
        alias = frame.extra.get("alias", "unknown")
        if alias not in self._peers: self._peers.append(alias)
        print(f"\n  [+] {alias} joined the network")

    def _on_peer_leave(self, frame: Frame) -> None:
        alias = frame.extra.get("alias", "unknown")
        if alias in self._peers: self._peers.remove(alias)
        print(f"\n  [-] {alias} left the network")

    def _on_file_meta(self, frame: Frame) -> None:
        self._incoming_name   = frame.extra.get("file_name", "unknown")
        self._incoming_chunks = frame.extra.get("total_chunks", 0)
        self._incoming_rcvd   = 0
        self._incoming_buf    = bytearray()
        sender = frame.extra.get("from", frame.sender)
        fsize  = frame.extra.get("file_size", 0)
        print(f"\n  [FILE INCOMING] '{self._incoming_name}' ({format_size(fsize)}) from {sender}")

    def _on_file_chunk(self, frame: Frame) -> None:
        if self._incoming_name is None:
            log.warning("FILE_CHUNK without FILE_META"); return
        self._incoming_buf.extend(frame.payload)
        self._incoming_rcvd += 1

    def _on_file_done(self, frame: Frame) -> None:
        if self._incoming_name is None:
            return
        dest = (RECEIVED_DIR / self.alias)
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / self._incoming_name
        out.write_bytes(bytes(self._incoming_buf))
        size = len(self._incoming_buf)
        log.info("[FILE] Saved '%s' (%s) → %s", self._incoming_name, format_size(size), out)
        print(f"\n  [FILE SAVED] '{self._incoming_name}' ({format_size(size)})\n  Path: {out}")
        self._incoming_name = None
        self._incoming_buf  = bytearray()

    def _on_file_incoming(self, frame: Frame) -> None:
        name   = frame.extra.get("file_name", "file")
        size   = frame.extra.get("file_size", 0)
        sender = frame.extra.get("from", frame.sender)
        print(f"\n  [FILE] '{name}' ({format_size(size)}) from {sender} — see received_files/")

    def _send_hello(self) -> None:
        self._sock.sendall(build_text_frame(MsgType.HELLO, self.alias, self.alias))
