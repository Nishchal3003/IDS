"""
server_core.py
--------------
Core server logic for the Intelligent-NIDS private communication network.

Architecture
------------
The ``NIDSServer`` class owns exactly one TCP listening socket and
maintains a registry of ``ClientSession`` objects – one per connected
peer.  Each ``ClientSession`` runs in its own daemon thread so that
slow or stalled clients never block the others.

Thread model
~~~~~~~~~~~~
  Main thread  →  accept_loop()  →  spawns  ClientSession.handle()  threads
  Each ClientSession thread  →  recv_frame() loop  →  dispatches by msg_type
  Heartbeat thread  →  periodic PING to every session

Why this design?
  •  Thread-per-client is simple to reason about and sufficient for the
     handful of devices (≤ MAX_CLIENTS) on a LAN.
  •  A shared lock (``_sessions_lock``) guards the sessions dict; no other
     shared mutable state exists.
  •  All socket I/O is encapsulated here; no raw socket calls leak into
     server.py.

File-transfer state
~~~~~~~~~~~~~~~~~~~
A ``FileReceiveState`` dataclass tracks in-progress downloads per session.
This prevents partial writes if two transfers happen simultaneously.
"""

import math
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from communication.constants import (
    HEARTBEAT_INTERVAL,
    MAX_CLIENTS,
    MAX_FILE_SIZE,
    MsgType,
    SOCKET_TIMEOUT,
    TRUST_INITIAL,
    USE_TLS,
    FILE_CHUNK_SIZE,
)
from communication.logger import get_logger
from communication.protocol import (
    Frame, build_text_frame, build_frame, recv_frame, build_file_chunk_frame,
)
from communication.tls import certs_exist, server_ssl_context
from communication.utils import (
    format_size,
    get_file_chunks,
    safe_send,
    timestamp_to_str,
    validate_file_for_transfer,
)

log = get_logger("server")

# Received files are saved here
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
RECEIVED_DIR: Path = PROJECT_ROOT / "received_files" / "server"


# ---------------------------------------------------------------------------
# File receive state
# ---------------------------------------------------------------------------
@dataclass
class FileReceiveState:
    """Tracks an in-progress file download from one client."""
    file_name: str
    total_chunks: int
    received_chunks: int = 0
    buffer: bytearray = field(default_factory=bytearray)

    @property
    def is_complete(self) -> bool:
        return self.received_chunks >= self.total_chunks


# ---------------------------------------------------------------------------
# Client session
# ---------------------------------------------------------------------------
class ClientSession:
    """
    Manages the lifecycle of a single connected client.

    One instance is created per accepted connection.  ``handle()`` is
    intended to run in a dedicated daemon thread.

    Attributes
    ----------
    alias       : str       – human-readable device name supplied at HELLO
    address     : tuple     – (ip, port) of the remote socket
    trust_score : int       – 0-100 IDS-managed trust level
    connected_at: float     – Unix epoch of connection time
    """

    def __init__(
        self,
        conn: socket.socket,
        address: tuple,
        server: "NIDSServer",
    ) -> None:
        self._conn: socket.socket = conn
        self.address: tuple       = address
        self._server: "NIDSServer" = server

        self.alias: str           = f"unknown@{address[0]}"
        self.trust_score: int     = TRUST_INITIAL
        self.connected_at: float  = time.time()

        self._file_state: Optional[FileReceiveState] = None
        self._alive: bool = True

        log.info("New session object for %s:%s", *address)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def send(self, data: bytes) -> bool:
        """Send pre-built frame bytes to this client."""
        if not self._alive:
            return False
        return safe_send(self._conn, data)

    def disconnect(self, reason: str = "server request") -> None:
        """Gracefully close this session."""
        if not self._alive:
            return
        self._alive = False
        try:
            bye = build_text_frame(MsgType.DISCONNECT, "server", reason)
            self._conn.sendall(bye)
        except OSError:
            pass
        finally:
            self._conn.close()
            log.info("Session %s disconnected (%s)", self.alias, reason)

    def handle(self) -> None:
        """
        Main receive loop.  Runs in its own thread.

        Reads frames one-by-one, dispatches to the appropriate handler,
        and cleans up the session when the loop exits.
        """
        self._conn.settimeout(SOCKET_TIMEOUT)
        try:
            while self._alive:
                frame = recv_frame(self._conn)
                if frame is None:
                    log.info("%s closed connection", self.alias)
                    break
                self._dispatch(frame)
        except ConnectionError as exc:
            log.warning("Connection error for %s: %s", self.alias, exc)
        except ValueError as exc:
            log.error("Protocol error from %s: %s", self.alias, exc)
        except OSError as exc:
            if self._alive:          # ignore errors during intentional shutdown
                log.error("Socket error for %s: %s", self.alias, exc)
        finally:
            self._alive = False
            self._server.remove_session(self)

    # ------------------------------------------------------------------
    # Frame dispatcher
    # ------------------------------------------------------------------
    def _dispatch(self, frame: Frame) -> None:
        handlers = {
            MsgType.HELLO     : self._handle_hello,
            MsgType.PING      : self._handle_ping,
            MsgType.PONG      : self._handle_pong,
            MsgType.CHAT      : self._handle_chat,
            MsgType.FILE_META : self._handle_file_meta,
            MsgType.FILE_CHUNK: self._handle_file_chunk,
            MsgType.FILE_DONE : self._handle_file_done,
            MsgType.DISCONNECT: self._handle_disconnect,
        }
        handler = handlers.get(frame.msg_type)
        if handler:
            handler(frame)
        else:
            log.warning(
                "%s sent unhandled msg_type: %s",
                self.alias, frame.msg_type
            )

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------
    def _handle_hello(self, frame: Frame) -> None:
        requested_alias = frame.text.strip() or f"device-{self.address[0]}"
        # Ensure alias is unique across sessions
        existing = [s.alias for s in self._server.sessions.values()]
        if requested_alias in existing:
            requested_alias = f"{requested_alias}-{self.address[1]}"
        self.alias = requested_alias
        log.info("HELLO from %s (%s:%s)", self.alias, *self.address)

        # Acknowledge with WELCOME + peer list
        peers = [
            s.alias
            for s in self._server.sessions.values()
            if s is not self
        ]
        welcome = build_text_frame(
            MsgType.WELCOME,
            "server",
            f"Welcome to NIDS-Net, {self.alias}!",
            extra={"peers": peers},
        )
        self.send(welcome)

        # Notify all other clients about the newcomer
        join_notice = build_text_frame(
            MsgType.PEER_JOIN,
            "server",
            f"{self.alias} joined the network",
            extra={"alias": self.alias, "ip": self.address[0]},
        )
        self._server.broadcast(join_notice, exclude=self)

    def _handle_ping(self, frame: Frame) -> None:
        pong = build_text_frame(MsgType.PONG, "server", "")
        self.send(pong)

    def _handle_pong(self, frame: Frame) -> None:
        log.debug("PONG from %s", self.alias)

    def _handle_chat(self, frame: Frame) -> None:
        text = frame.text
        log.info("[CHAT] %s → broadcast: %s", self.alias, text)
        relay = build_text_frame(
            MsgType.BROADCAST,
            self.alias,
            text,
            extra={"from": self.alias, "time": timestamp_to_str(frame.timestamp)},
        )
        self._server.broadcast(relay, exclude=None)   # echo back to sender too

    def _handle_file_meta(self, frame: Frame) -> None:
        file_name   = frame.extra.get("file_name", "unknown")
        file_size   = frame.extra.get("file_size", 0)
        total_chunks = frame.extra.get("total_chunks", 0)
        log.info(
            "[FILE] %s → sending '%s' (%s, %d chunks)",
            self.alias, file_name, format_size(file_size), total_chunks,
        )
        self._file_state = FileReceiveState(
            file_name=file_name,
            total_chunks=total_chunks,
        )
        ack = build_text_frame(MsgType.ACK, "server", "FILE_META received")
        self.send(ack)

    def _handle_file_chunk(self, frame: Frame) -> None:
        if self._file_state is None:
            log.warning("%s sent FILE_CHUNK without FILE_META", self.alias)
            return
        self._file_state.buffer.extend(frame.payload)
        self._file_state.received_chunks += 1
        # Acknowledge every chunk (simple stop-and-wait)
        ack = build_text_frame(
            MsgType.FILE_ACK,
            "server",
            str(frame.extra.get("chunk_index", -1)),
        )
        self.send(ack)

    def _handle_file_done(self, frame: Frame) -> None:
        if self._file_state is None:
            log.warning("%s sent FILE_DONE without FILE_META", self.alias)
            return
        state = self._file_state
        self._file_state = None   # clear early so re-entrant calls are safe

        file_data = bytes(state.buffer)
        file_size = len(file_data)

        # 1. Save on server ─────────────────────────────────────────────
        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        dest = RECEIVED_DIR / state.file_name
        dest.write_bytes(file_data)
        log.info(
            "[FILE] Saved '%s' (%s) from %s → relaying to %d peer(s)",
            state.file_name, format_size(file_size), self.alias,
            len(self._server.sessions) - 1,
        )

        # Acknowledge receipt to the sender
        self.send(build_text_frame(
            MsgType.ACK, "server", f"File '{state.file_name}' received"
        ))

        # 2. Relay to all other sessions ────────────────────────────────
        other_sessions = [
            s for s in self._server.sessions.values() if s is not self
        ]
        if not other_sessions:
            return

        # Split peers into TCP vs browser (BrowserSession has _browser_key)
        tcp_peers     = [s for s in other_sessions if not hasattr(s, "_is_browser")]
        browser_peers = [s for s in other_sessions if hasattr(s, "_is_browser")]

        total_chunks = math.ceil(file_size / FILE_CHUNK_SIZE) or 1

        # ── TCP clients: use FILE_META → FILE_CHUNK × N → FILE_DONE ────
        if tcp_peers:
            meta_frame = build_text_frame(
                MsgType.FILE_META, self.alias, state.file_name,
                extra={
                    "file_name"   : state.file_name,
                    "file_size"   : file_size,
                    "total_chunks": total_chunks,
                    "from"        : self.alias,
                },
            )
            for s in tcp_peers:
                s.send(meta_frame)

            for chunk_idx in range(total_chunks):
                start = chunk_idx * FILE_CHUNK_SIZE
                end   = start + FILE_CHUNK_SIZE
                chunk_frame = build_file_chunk_frame(
                    self.alias,
                    file_data[start:end],
                    file_name=state.file_name,
                    chunk_index=chunk_idx,
                    total_chunks=total_chunks,
                )
                for s in tcp_peers:
                    s.send(chunk_frame)

            done_frame = build_text_frame(
                MsgType.FILE_DONE, self.alias, state.file_name
            )
            for s in tcp_peers:
                s.send(done_frame)

        # ── Browser clients: single FILE_INCOMING frame (base64 payload)
        if browser_peers:
            import base64 as _b64
            incoming_frame = build_frame(
                MsgType.FILE_INCOMING, self.alias,
                _b64.b64encode(file_data),
                extra={
                    "file_name": state.file_name,
                    "file_size": file_size,
                    "from"     : self.alias,
                },
            )
            for s in browser_peers:
                s.send(incoming_frame)

        # 3. Notify all peers (including sender) in chat
        notify = build_text_frame(
            MsgType.BROADCAST, "server",
            f"{self.alias} shared '{state.file_name}' ({format_size(file_size)}) — available to all peers",
            extra={"from": "server", "time": timestamp_to_str(time.time())},
        )
        self._server.broadcast(notify)
        log.info("[FILE] Relay of '%s' complete.", state.file_name)

    def _handle_disconnect(self, frame: Frame) -> None:
        log.info("%s sent DISCONNECT: %s", self.alias, frame.text)
        self._alive = False


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
class NIDSServer:
    """
    Multi-client TCP server for the NIDS private communication network.

    Usage
    -----
    ::
        server = NIDSServer(host="0.0.0.0", port=5000)
        server.start()          # blocks until KeyboardInterrupt / stop()
    """

    def __init__(self, host: str, port: int) -> None:
        self._host: str  = host
        self._port: int  = port
        self._server_sock: Optional[socket.socket] = None
        self._running: bool = False

        # TLS context — created once if certs are available
        self._ssl_ctx = None
        if USE_TLS:
            if certs_exist():
                self._ssl_ctx = server_ssl_context()
                log.info("TLS enabled — all TCP connections will be encrypted")
            else:
                log.warning(
                    "USE_TLS=True but certs not found. "
                    "Run: python -m communication.generate_certs"
                )

        # sessions dict:  conn_fileno → ClientSession (or BrowserSession)
        # BrowserSessions use negative keys (e.g. -1, -2, ...) so they
        # never collide with real OS file descriptors (always >= 0).
        self._sessions: dict[int, ClientSession] = {}
        self._sessions_lock: threading.Lock = threading.Lock()
        self._browser_session_counter: int = 0  # decrements for each browser session

    # ------------------------------------------------------------------
    # Public read-only view of sessions
    # ------------------------------------------------------------------
    @property
    def sessions(self) -> dict[int, "ClientSession"]:
        """Return a snapshot of active sessions (thread-safe)."""
        with self._sessions_lock:
            return dict(self._sessions)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """
        Bind the server socket and enter the accept loop.

        This method blocks the calling thread.  Call it from your
        main thread and handle ``KeyboardInterrupt`` there.
        """
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self._host, self._port))
        self._server_sock.listen(MAX_CLIENTS)
        self._server_sock.settimeout(1.0)
        self._running = True

        log.info(
            "NIDS Server listening on %s:%s (max %d clients) | TLS: %s",
            self._host, self._port, MAX_CLIENTS,
            "ON" if self._ssl_ctx else "OFF",
        )
        print(f"\n{'='*60}")
        print(f"  NIDS Private Network Server")
        print(f"  TCP  (Python clients) : {self._host}:{self._port}  |  TLS: {'ON' if self._ssl_ctx else 'OFF'}")
        print(f"  Max clients           : {MAX_CLIENTS}")
        print(f"  Press Ctrl+C to stop")
        print(f"{'='*60}\n")

        # Start heartbeat thread
        hb = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="heartbeat"
        )
        hb.start()

        self._accept_loop()

    def stop(self) -> None:
        """Signal the server to stop accepting new connections."""
        log.info("Server stop requested")
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Accept loop
    # ------------------------------------------------------------------
    def _accept_loop(self) -> None:
        """Block and accept incoming connections until stopped."""
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except socket.timeout:
                continue   # socket was closed by stop()

            with self._sessions_lock:
                if len(self._sessions) >= MAX_CLIENTS:
                    log.warning(
                        "Rejecting %s:%s – server full (%d/%d)",
                        *addr, len(self._sessions), MAX_CLIENTS,
                    )
                    try:
                        full_msg = build_text_frame(
                            MsgType.SERVER_FULL, "server",
                            "Server is full. Try again later."
                        )
                        conn.sendall(full_msg)
                    finally:
                        conn.close()
                    continue

                session = ClientSession(conn, addr, self)
                self._sessions[conn.fileno()] = session

            # Wrap with TLS AFTER the session is created so that the
            # handshake happens in the session thread, not the accept thread.
            if self._ssl_ctx:
                try:
                    tls_conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                    session._conn = tls_conn   # replace the raw socket
                except Exception as exc:
                    log.error("TLS handshake failed for %s:%s — %s", *addr, exc)
                    with self._sessions_lock:
                        self._sessions.pop(conn.fileno(), None)
                    conn.close()
                    continue

            thread = threading.Thread(
                target=session.handle,
                daemon=True,
                name=f"session-{addr[0]}-{addr[1]}",
            )
            thread.start()
            log.info("Accepted connection from %s:%s", *addr)

    # ------------------------------------------------------------------
    # Broadcast
    # ------------------------------------------------------------------
    def broadcast(
        self,
        data: bytes,
        exclude: Optional["ClientSession"] = None,
    ) -> None:
        """
        Send *data* to every connected client, optionally excluding one.

        Parameters
        ----------
        data : bytes
            Pre-built frame bytes.
        exclude : ClientSession | None
            If provided, this session will NOT receive the broadcast.
        """
        with self._sessions_lock:
            targets = list(self._sessions.values())
        for session in targets:
            if session is not exclude:
                session.send(data)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------
    def remove_session(self, session: "ClientSession") -> None:
        """Remove a disconnected session and notify remaining peers."""
        fd = getattr(session, "_browser_key", None)
        if fd is None:
            fd = session._conn.fileno()
        with self._sessions_lock:
            self._sessions.pop(fd, None)

        leave_notice = build_text_frame(
            MsgType.PEER_LEAVE,
            "server",
            f"{session.alias} left the network",
            extra={"alias": session.alias},
        )
        self.broadcast(leave_notice)
        log.info(
            "Session removed: %s | Active clients: %d",
            session.alias, len(self._sessions),
        )

    def register_browser_session(self, session: "ClientSession") -> int:
        """
        Register a BrowserSession in the shared session registry.

        Browser sessions use negative integer keys so they never clash
        with real OS file descriptors (which are always >= 0).

        Parameters
        ----------
        session : BrowserSession
            The session object to register.

        Returns
        -------
        int
            The unique negative key assigned to this session.
        """
        with self._sessions_lock:
            self._browser_session_counter -= 1
            key = self._browser_session_counter
            session._browser_key = key
            self._sessions[key] = session
        log.info("Browser session registered: key=%d  alias=%s", key, session.alias)
        return key

    def unregister_browser_session(self, session: "ClientSession") -> None:
        """Remove a BrowserSession and broadcast PEER_LEAVE."""
        self.remove_session(session)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------
    def _heartbeat_loop(self) -> None:
        """Send PING to every client every HEARTBEAT_INTERVAL seconds."""
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            ping = build_text_frame(MsgType.PING, "server", "")
            with self._sessions_lock:
                targets = list(self._sessions.values())
            for session in targets:
                session.send(ping)
            if targets:
                log.debug("Heartbeat sent to %d client(s)", len(targets))

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def status(self) -> dict:
        """Return a dict of current server state (for dashboard use)."""
        with self._sessions_lock:
            peers = [
                {
                    "alias"      : s.alias,
                    "ip"         : s.address[0],
                    "port"       : s.address[1],
                    "trust_score": s.trust_score,
                    "connected_at": timestamp_to_str(s.connected_at),
                }
                for s in self._sessions.values()
            ]
        return {
            "host"         : self._host,
            "port"         : self._port,
            "client_count" : len(peers),
            "clients"      : peers,
        }
