"""
client_core.py
--------------
Core client logic for the Intelligent-NIDS private communication network.

Architecture
------------
``NIDSClient`` connects to a ``NIDSServer``, performs the HELLO handshake,
then runs a receive thread so that incoming frames never block the caller.

The caller interacts with the client exclusively through the public API:
    client.send_chat(text)
    client.send_file(path)
    client.disconnect()

All incoming frames are dispatched through a registered callback:
    client.on_frame = my_callback_function

This decouples the network layer from the UI layer (CLI or Streamlit).

Reconnect policy
----------------
If the connection drops unexpectedly, ``NIDSClient`` automatically retries
up to ``MAX_RECONNECT_TRIES`` times with a ``RECONNECT_DELAY`` between each
attempt.  The caller is notified via the ``on_disconnected`` callback.

File transfer
-------------
Files are sent as:
  1. FILE_META frame  →  announces name, size, chunk count
  2. N × FILE_CHUNK frames  →  stop-and-wait (wait for FILE_ACK each time)
  3. FILE_DONE frame  →  signals completion

Received files are written to ``received_files/client/<alias>/``.
"""

import math
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from communication.constants import (
    FILE_CHUNK_SIZE,
    HEARTBEAT_INTERVAL,
    MAX_RECONNECT_TRIES,
    MsgType,
    RECONNECT_DELAY,
    SOCKET_TIMEOUT,
    TRUST_INITIAL,
)
from communication.logger import get_logger
from communication.protocol import (
    Frame,
    build_file_chunk_frame,
    build_frame,
    build_text_frame,
    recv_frame,
)
from communication.utils import (
    format_size,
    get_file_chunks,
    safe_send,
    timestamp_to_str,
    validate_file_for_transfer,
)

log = get_logger("client")

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
RECEIVED_DIR: Path = PROJECT_ROOT / "received_files" / "client"


# ---------------------------------------------------------------------------
# Callback type hints
# ---------------------------------------------------------------------------
FrameCallback      = Callable[[Frame], None]
DisconnectCallback = Callable[[str], None]


# ---------------------------------------------------------------------------
# NIDSClient
# ---------------------------------------------------------------------------
class NIDSClient:
    """
    TCP client for the NIDS private communication network.

    Parameters
    ----------
    alias : str
        Human-readable name for this device.  Must pass
        ``sanitise_alias()`` validation.
    server_host : str
        IP address of the server to connect to.
    server_port : int
        TCP port the server is listening on.
    on_frame : FrameCallback, optional
        Called in the receive thread for every incoming frame.
        Signature: ``callback(frame: Frame) -> None``
    on_disconnected : DisconnectCallback, optional
        Called when the connection is lost (after all reconnect attempts
        have been exhausted).
        Signature: ``callback(reason: str) -> None``

    Usage
    -----
    ::
        client = NIDSClient(
            alias="Laptop-A",
            server_host="192.168.1.10",
            server_port=5000,
        )
        client.on_frame = lambda f: print(f)
        client.connect()
        client.send_chat("Hello network!")
        client.send_file("/path/to/report.pdf")
        client.disconnect()
    """

    def __init__(
        self,
        alias: str,
        server_host: str,
        server_port: int,
        on_frame: Optional[FrameCallback] = None,
        on_disconnected: Optional[DisconnectCallback] = None,
    ) -> None:
        self.alias: str            = alias
        self.server_host: str      = server_host
        self.server_port: int      = server_port
        self.on_frame              = on_frame
        self.on_disconnected       = on_disconnected

        self._sock: Optional[socket.socket] = None
        self._alive: bool          = False
        self._recv_thread: Optional[threading.Thread] = None
        self._peers: list[str]     = []

        # File ACK synchronisation
        self._file_ack_event: threading.Event = threading.Event()

        # For tracking a file being received from server/peers
        self._incoming_file_name: Optional[str]      = None
        self._incoming_total_chunks: int              = 0
        self._incoming_received_chunks: int           = 0
        self._incoming_buffer: bytearray              = bytearray()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def connect(self) -> bool:
        """
        Attempt to connect to the server and perform the HELLO handshake.

        Returns
        -------
        bool
            ``True`` if the connection and handshake were successful.
        """
        for attempt in range(1, MAX_RECONNECT_TRIES + 1):
            try:
                log.info(
                    "Connecting to %s:%s (attempt %d/%d)",
                    self.server_host, self.server_port,
                    attempt, MAX_RECONNECT_TRIES,
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)
                sock.connect((self.server_host, self.server_port))
                self._sock  = sock
                self._alive = True
                self._send_hello()
                self._start_recv_thread()
                log.info("Connected as '%s'", self.alias)
                return True
            except (ConnectionRefusedError, OSError) as exc:
                log.warning(
                    "Connection attempt %d failed: %s", attempt, exc
                )
                if attempt < MAX_RECONNECT_TRIES:
                    time.sleep(RECONNECT_DELAY)

        log.error("All %d connection attempts failed.", MAX_RECONNECT_TRIES)
        return False

    def disconnect(self, reason: str = "user request") -> None:
        """Gracefully close the connection."""
        if not self._alive:
            return
        self._alive = False
        try:
            bye = build_text_frame(MsgType.DISCONNECT, self.alias, reason)
            self._sock.sendall(bye)
        except OSError:
            pass
        finally:
            if self._sock:
                self._sock.close()
            log.info("Disconnected from server (%s)", reason)

    def is_connected(self) -> bool:
        """Return True if the client is currently connected."""
        return self._alive

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------
    def send_chat(self, text: str) -> bool:
        """
        Broadcast a plain-text chat message to all peers via the server.

        Parameters
        ----------
        text : str
            Message body.

        Returns
        -------
        bool
            ``True`` if the frame was dispatched successfully.
        """
        if not self._alive:
            log.warning("Cannot send chat – not connected")
            return False
        frame = build_text_frame(MsgType.CHAT, self.alias, text)
        ok = safe_send(self._sock, frame)
        if ok:
            log.info("[CHAT] Me → broadcast: %s", text)
        return ok

    def send_file(self, path: str) -> bool:
        """
        Send a file to the server (which may relay it to other clients).

        The transfer uses a stop-and-wait protocol:
          FILE_META → (FILE_CHUNK → FILE_ACK) × N → FILE_DONE

        Parameters
        ----------
        path : str
            Path to the file to send.

        Returns
        -------
        bool
            ``True`` if the entire file was transferred without error.
        """
        if not self._alive:
            log.warning("Cannot send file – not connected")
            return False

        try:
            file_path = validate_file_for_transfer(path)
        except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
            log.error("File validation failed: %s", exc)
            return False

        file_name   = file_path.name
        file_size   = file_path.stat().st_size
        total_chunks = math.ceil(file_size / FILE_CHUNK_SIZE)

        # ── FILE_META ────────────────────────────────────────────────────
        meta_frame = build_text_frame(
            MsgType.FILE_META,
            self.alias,
            "",
            extra={
                "file_name"   : file_name,
                "file_size"   : file_size,
                "total_chunks": total_chunks,
            },
        )
        if not safe_send(self._sock, meta_frame):
            return False

        log.info(
            "[FILE] Sending '%s' (%s, %d chunk(s))",
            file_name, format_size(file_size), total_chunks,
        )

        # ── FILE_CHUNKs  (stop-and-wait) ─────────────────────────────────
        for idx, chunk in enumerate(get_file_chunks(file_path)):
            chunk_frame = build_file_chunk_frame(
                sender=self.alias,
                chunk_data=chunk,
                file_name=file_name,
                chunk_index=idx,
                total_chunks=total_chunks,
            )
            if not safe_send(self._sock, chunk_frame):
                log.error("Failed to send chunk %d", idx)
                return False

            # Wait for FILE_ACK
            self._file_ack_event.clear()
            if not self._file_ack_event.wait(timeout=30):
                log.error("Timed out waiting for FILE_ACK on chunk %d", idx)
                return False

        # ── FILE_DONE ────────────────────────────────────────────────────
        done_frame = build_text_frame(MsgType.FILE_DONE, self.alias, file_name)
        if not safe_send(self._sock, done_frame):
            return False

        log.info("[FILE] Transfer of '%s' complete", file_name)
        return True

    # ------------------------------------------------------------------
    # Receive loop (runs in daemon thread)
    # ------------------------------------------------------------------
    def _start_recv_thread(self) -> None:
        self._recv_thread = threading.Thread(
            target=self._recv_loop,
            daemon=True,
            name=f"recv-{self.alias}",
        )
        self._recv_thread.start()

    def _recv_loop(self) -> None:
        """Continuously read frames from the server socket."""
        while self._alive:
            try:
                frame = recv_frame(self._sock)
                if frame is None:
                    log.info("Server closed the connection")
                    break
                self._dispatch(frame)
            except ConnectionError as exc:
                log.warning("Connection lost: %s", exc)
                break
            except ValueError as exc:
                log.error("Protocol error: %s", exc)
                break
            except OSError as exc:
                if self._alive:
                    log.error("Socket error: %s", exc)
                break

        self._alive = False
        if self.on_disconnected:
            self.on_disconnected("Connection to server lost")

    # ------------------------------------------------------------------
    # Frame dispatcher
    # ------------------------------------------------------------------
    def _dispatch(self, frame: Frame) -> None:
        built_in_handlers = {
            MsgType.WELCOME   : self._on_welcome,
            MsgType.PING      : self._on_ping,
            MsgType.PONG      : self._on_pong,
            MsgType.PEER_JOIN : self._on_peer_join,
            MsgType.PEER_LEAVE: self._on_peer_leave,
            MsgType.FILE_ACK  : self._on_file_ack,
            MsgType.FILE_META : self._on_file_meta,
            MsgType.FILE_CHUNK: self._on_file_chunk,
            MsgType.FILE_DONE : self._on_file_done,
            MsgType.DISCONNECT: self._on_server_disconnect,
        }
        handler = built_in_handlers.get(frame.msg_type)
        if handler:
            handler(frame)

        # Always forward to the external callback (UI layer)
        if self.on_frame:
            self.on_frame(frame)

    # ------------------------------------------------------------------
    # Built-in handlers
    # ------------------------------------------------------------------
    def _on_welcome(self, frame: Frame) -> None:
        peers = frame.extra.get("peers", [])
        self._peers = peers
        log.info("WELCOME: %s | Current peers: %s", frame.text, peers)

    def _on_ping(self, frame: Frame) -> None:
        pong = build_text_frame(MsgType.PONG, self.alias, "")
        safe_send(self._sock, pong)
        log.debug("PING → PONG")

    def _on_pong(self, frame: Frame) -> None:
        log.debug("PONG received from server")

    def _on_peer_join(self, frame: Frame) -> None:
        alias = frame.extra.get("alias", "unknown")
        if alias not in self._peers:
            self._peers.append(alias)
        log.info("[NET] %s joined", alias)
        print(f"\n  [+] {alias} joined the network")

    def _on_peer_leave(self, frame: Frame) -> None:
        alias = frame.extra.get("alias", "unknown")
        if alias in self._peers:
            self._peers.remove(alias)
        log.info("[NET] %s left", alias)
        print(f"\n  [-] {alias} left the network")

    def _on_file_ack(self, frame: Frame) -> None:
        """Signal the send_file() loop that a chunk was acknowledged."""
        self._file_ack_event.set()

    def _on_file_meta(self, frame: Frame) -> None:
        self._incoming_file_name     = frame.extra.get("file_name", "unknown")
        self._incoming_total_chunks  = frame.extra.get("total_chunks", 0)
        self._incoming_received_chunks = 0
        self._incoming_buffer        = bytearray()
        log.info(
            "[FILE] Incoming '%s' (%d chunks)",
            self._incoming_file_name, self._incoming_total_chunks,
        )

    def _on_file_chunk(self, frame: Frame) -> None:
        if self._incoming_file_name is None:
            log.warning("Received FILE_CHUNK without FILE_META")
            return
        self._incoming_buffer.extend(frame.payload)
        self._incoming_received_chunks += 1

    def _on_file_done(self, frame: Frame) -> None:
        if self._incoming_file_name is None:
            return
        dest_dir = RECEIVED_DIR / self.alias
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / self._incoming_file_name
        dest.write_bytes(bytes(self._incoming_buffer))
        log.info(
            "[FILE] Saved '%s' (%s)",
            self._incoming_file_name,
            format_size(len(self._incoming_buffer)),
        )
        print(
            f"\n  [FILE] Received: {self._incoming_file_name} "
            f"({format_size(len(self._incoming_buffer))})"
        )
        self._incoming_file_name = None
        self._incoming_buffer    = bytearray()

    def _on_server_disconnect(self, frame: Frame) -> None:
        log.info("Server sent DISCONNECT: %s", frame.text)
        self._alive = False

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------
    def _send_hello(self) -> None:
        hello = build_text_frame(MsgType.HELLO, self.alias, self.alias)
        self._sock.sendall(hello)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    @property
    def peers(self) -> list[str]:
        """Return list of currently known peer aliases."""
        return list(self._peers)
