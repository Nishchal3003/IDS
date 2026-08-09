"""Core server logic for the Intelligent-NIDS private communication network."""

import base64
import math
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from communication.constants import (
    FILE_CHUNK_SIZE, HEARTBEAT_INTERVAL, MAX_CLIENTS, MAX_FILE_SIZE,
    MsgType, SOCKET_TIMEOUT, TRUST_INITIAL, USE_TLS,
)
from communication.logger import get_logger
from communication.protocol import (
    Frame, build_frame, build_file_chunk_frame, build_text_frame,
    recv_frame,
)
from communication.security import certs_exist, server_ssl_context
from communication.utils import (
    format_size, get_file_chunks, get_local_ip, is_lan_peer,
    safe_send, timestamp_to_str, validate_file_for_transfer,
)

log = get_logger("server")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RECEIVED_DIR = PROJECT_ROOT / "received_files" / "server"


@dataclass
class FileReceiveState:
    file_name: str
    total_chunks: int
    received_chunks: int = 0
    buffer: bytearray = field(default_factory=bytearray)

    @property
    def is_complete(self) -> bool:
        return self.received_chunks >= self.total_chunks


class ClientSession:
    """Manages one connected TCP client in its own daemon thread."""

    def __init__(self, conn: socket.socket, address: tuple, server: "NIDSServer") -> None:
        self._conn   = conn
        self.address = address
        self._server = server
        self.alias        = f"unknown@{address[0]}"
        self.trust_score  = TRUST_INITIAL
        self.connected_at = time.time()
        self._file_state: Optional[FileReceiveState] = None
        self._alive = True
        log.info("New session for %s:%s", *address)

    def send(self, data: bytes) -> bool:
        return safe_send(self._conn, data) if self._alive else False

    def disconnect(self, reason: str = "server request") -> None:
        if not self._alive:
            return
        self._alive = False
        try:
            self._conn.sendall(build_text_frame(MsgType.DISCONNECT, "server", reason))
        except OSError:
            pass
        finally:
            self._conn.close()
            log.info("Session %s disconnected (%s)", self.alias, reason)

    def handle(self) -> None:
        """Main receive loop — runs in a dedicated daemon thread."""
        self._conn.settimeout(SOCKET_TIMEOUT)
        try:
            while self._alive:
                frame = recv_frame(self._conn)
                if frame is None:
                    log.info("%s closed connection", self.alias); break
                self._dispatch(frame)
        except ConnectionError as e:
            log.warning("Connection error for %s: %s", self.alias, e)
        except ValueError as e:
            log.error("Protocol error from %s: %s", self.alias, e)
        except OSError as e:
            if self._alive:
                log.error("Socket error for %s: %s", self.alias, e)
        finally:
            self._alive = False
            self._server.remove_session(self)

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
        h = handlers.get(frame.msg_type)
        if h:
            h(frame)
        else:
            log.warning("%s sent unhandled msg_type: %s", self.alias, frame.msg_type)

    def _handle_hello(self, frame: Frame) -> None:
        alias = frame.text.strip() or f"device-{self.address[0]}"
        existing = [s.alias for s in self._server.sessions.values()]
        if alias in existing:
            alias = f"{alias}-{self.address[1]}"
        self.alias = alias
        log.info("HELLO from %s (%s:%s)", self.alias, *self.address)
        peers = [s.alias for s in self._server.sessions.values() if s is not self]
        self.send(build_text_frame(MsgType.WELCOME, "server",
                                   f"Welcome to NIDS-Net, {self.alias}!",
                                   extra={"peers": peers}))
        self._server.broadcast(
            build_text_frame(MsgType.PEER_JOIN, "server", f"{self.alias} joined the network",
                             extra={"alias": self.alias, "ip": self.address[0]}),
            exclude=self)

    def _handle_ping(self, frame: Frame) -> None:
        self.send(build_text_frame(MsgType.PONG, "server", ""))

    def _handle_pong(self, frame: Frame) -> None:
        log.debug("PONG from %s", self.alias)

    def _handle_chat(self, frame: Frame) -> None:
        log.info("[CHAT] %s → broadcast: %s", self.alias, frame.text)
        self._server.broadcast(build_text_frame(
            MsgType.BROADCAST, self.alias, frame.text,
            extra={"from": self.alias, "time": timestamp_to_str(frame.timestamp)}))

    def _handle_file_meta(self, frame: Frame) -> None:
        name   = frame.extra.get("file_name", "unknown")
        size   = frame.extra.get("file_size", 0)
        chunks = frame.extra.get("total_chunks", 0)
        log.info("[FILE] %s → '%s' (%s, %d chunks)", self.alias, name, format_size(size), chunks)
        self._file_state = FileReceiveState(file_name=name, total_chunks=chunks)
        self.send(build_text_frame(MsgType.ACK, "server", "FILE_META received"))

    def _handle_file_chunk(self, frame: Frame) -> None:
        if self._file_state is None:
            log.warning("%s sent FILE_CHUNK without FILE_META", self.alias); return
        self._file_state.buffer.extend(frame.payload)
        self._file_state.received_chunks += 1
        self.send(build_text_frame(MsgType.FILE_ACK, "server",
                                   str(frame.extra.get("chunk_index", -1))))

    def _handle_file_done(self, frame: Frame) -> None:
        if self._file_state is None:
            log.warning("%s sent FILE_DONE without FILE_META", self.alias); return
        state, self._file_state = self._file_state, None
        data = bytes(state.buffer)
        size = len(data)

        # Save to server
        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        try:
            (RECEIVED_DIR / state.file_name).write_bytes(data)
        except OSError as e:
            log.error("[FILE] Could not save '%s': %s", state.file_name, e)
            self.send(build_text_frame(MsgType.ACK, "server", f"ERROR: {e}")); return

        log.info("[FILE] Saved '%s' (%s) from %s", state.file_name, format_size(size), self.alias)
        self.send(build_text_frame(MsgType.ACK, "server",
                                   f"File '{state.file_name}' received ({format_size(size)}) -- relaying"))

        others = [s for s in self._server.sessions.values() if s is not self]
        if not others:
            self._server.broadcast(build_text_frame(
                MsgType.BROADCAST, "server",
                f"{self.alias} shared '{state.file_name}' — no other peers online",
                extra={"from": "server", "time": timestamp_to_str(time.time())}))
            return

        tcp_peers     = [s for s in others if not hasattr(s, "_is_browser")]
        browser_peers = [s for s in others if hasattr(s, "_is_browser")]
        total_chunks  = math.ceil(size / FILE_CHUNK_SIZE) or 1

        def _relay():
            if tcp_peers:
                meta = build_text_frame(
                    MsgType.FILE_META, self.alias, state.file_name,
                    extra={"file_name": state.file_name, "file_size": size,
                           "total_chunks": total_chunks, "from": self.alias})
                for s in list(tcp_peers):
                    try: s.send(meta)
                    except Exception as e: log.warning("[FILE] META→%s failed: %s", s.alias, e)
                for i in range(total_chunks):
                    chunk_frame = build_file_chunk_frame(
                        self.alias, data[i*FILE_CHUNK_SIZE:(i+1)*FILE_CHUNK_SIZE],
                        state.file_name, i, total_chunks)
                    for s in list(tcp_peers):
                        try: s.send(chunk_frame)
                        except Exception as e: log.warning("[FILE] CHUNK%d→%s: %s", i, s.alias, e)
                done = build_text_frame(MsgType.FILE_DONE, self.alias, state.file_name)
                for s in list(tcp_peers):
                    try: s.send(done)
                    except Exception as e: log.warning("[FILE] DONE→%s: %s", s.alias, e)
            if browser_peers:
                incoming = build_frame(
                    MsgType.FILE_INCOMING, self.alias, base64.b64encode(data),
                    extra={"file_name": state.file_name, "file_size": size, "from": self.alias})
                for s in list(browser_peers):
                    try: s.send(incoming)
                    except Exception as e: log.warning("[FILE] INCOMING→%s: %s", getattr(s,"alias","?"), e)
            log.info("[FILE] Relay '%s' done. TCP=%d Browser=%d", state.file_name, len(tcp_peers), len(browser_peers))

        threading.Thread(target=_relay, daemon=True, name=f"relay-{state.file_name[:16]}").start()
        self._server.broadcast(build_text_frame(
            MsgType.BROADCAST, "server",
            f"{self.alias} shared '{state.file_name}' ({format_size(size)}) — available to all",
            extra={"from": "server", "time": timestamp_to_str(time.time())}))

    def _handle_disconnect(self, frame: Frame) -> None:
        log.info("%s sent DISCONNECT: %s", self.alias, frame.text)
        self._alive = False


class NIDSServer:
    """Multi-client TCP server for the NIDS private network."""

    def __init__(self, host: str, port: int) -> None:
        self._host, self._port = host, port
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._local_ip = get_local_ip()
        try:
            from config.network_config import LAN_ONLY_MODE
            self._lan_only = LAN_ONLY_MODE
        except ImportError:
            self._lan_only = True
        self._ssl_ctx = None
        if USE_TLS:
            if certs_exist():
                self._ssl_ctx = server_ssl_context()
                log.info("TLS enabled")
            else:
                log.warning("USE_TLS=True but certs not found. Run: python -m communication.generate_certs")
        # BrowserSessions get negative keys to avoid collision with TCP file descriptors
        self._sessions: dict[int, ClientSession] = {}
        self._sessions_lock = threading.Lock()
        self._browser_session_counter = 0

    @property
    def sessions(self) -> dict[int, "ClientSession"]:
        with self._sessions_lock:
            return dict(self._sessions)

    def start(self) -> None:
        """Bind socket, print banner, start heartbeat, enter accept loop (blocks)."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self._host, self._port))
        self._server_sock.listen(128)   # generous backlog; MAX_CLIENTS limits active sessions
        self._server_sock.settimeout(1.0)
        self._running = True
        tls_s = "ON" if self._ssl_ctx else "OFF"
        lan_s = "ENABLED" if self._lan_only else "DISABLED"
        log.info("NIDS Server on %s:%s | max=%d | TLS=%s | LAN-only=%s",
                 self._host, self._port, MAX_CLIENTS, tls_s, lan_s)
        print(f"\n{'='*55}")
        print(f"  NIDS Server  |  TCP: {self._host}:{self._port}  |  TLS: {tls_s}")
        print(f"  LAN IP: {self._local_ip}  |  Max clients: {MAX_CLIENTS}  |  LAN-only: {lan_s}")
        print(f"  Press Ctrl+C to stop\n{'='*55}\n")
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        self._accept_loop()

    def stop(self) -> None:
        self._running = False
        try:
            if self._server_sock: self._server_sock.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            ip = addr[0]
            if self._lan_only and not is_lan_peer(ip, self._local_ip):
                log.warning("Rejecting %s — not on LAN", ip)
                try:
                    conn.sendall(build_text_frame(MsgType.ERROR, "server",
                                                  "Rejected: LAN-only server."))
                except OSError:
                    pass
                conn.close(); continue

            with self._sessions_lock:
                if len(self._sessions) >= MAX_CLIENTS:
                    n = len(self._sessions)
                    log.warning("Rejecting %s — server full (%d/%d)", ip, n, MAX_CLIENTS)
                    try:
                        conn.sendall(build_text_frame(
                            MsgType.SERVER_FULL, "server",
                            f"Server full ({n}/{MAX_CLIENTS}). Try later."))
                    finally:
                        conn.close()
                    continue
                session = ClientSession(conn, addr, self)
                self._sessions[conn.fileno()] = session

            if self._ssl_ctx:
                try:
                    tls_conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                    session._conn = tls_conn
                except Exception as e:
                    log.error("TLS handshake failed for %s: %s", ip, e)
                    with self._sessions_lock:
                        self._sessions.pop(conn.fileno(), None)
                    conn.close(); continue

            threading.Thread(target=session.handle, daemon=True,
                             name=f"session-{ip}").start()
            log.info("Accepted %s:%s", *addr)

    def broadcast(self, data: bytes, exclude: Optional["ClientSession"] = None) -> None:
        with self._sessions_lock:
            targets = list(self._sessions.values())
        for s in targets:
            if s is not exclude:
                s.send(data)

    def remove_session(self, session: "ClientSession") -> None:
        fd = getattr(session, "_browser_key", None) or session._conn.fileno()
        with self._sessions_lock:
            self._sessions.pop(fd, None)
        self.broadcast(build_text_frame(MsgType.PEER_LEAVE, "server",
                                        f"{session.alias} left",
                                        extra={"alias": session.alias}))
        log.info("Session removed: %s | Active: %d", session.alias, len(self._sessions))

    def register_browser_session(self, session: "ClientSession") -> int:
        with self._sessions_lock:
            self._browser_session_counter -= 1
            key = self._browser_session_counter
            session._browser_key = key
            self._sessions[key] = session
        log.info("Browser registered: key=%d alias=%s", key, session.alias)
        return key

    def unregister_browser_session(self, session: "ClientSession") -> None:
        self.remove_session(session)

    def _heartbeat_loop(self) -> None:
        ping = build_text_frame(MsgType.PING, "server", "")
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            with self._sessions_lock:
                targets = list(self._sessions.values())
            for s in targets:
                s.send(ping)

    def status(self) -> dict:
        with self._sessions_lock:
            peers = [{"alias": s.alias, "ip": s.address[0], "port": s.address[1],
                      "trust": s.trust_score, "since": timestamp_to_str(s.connected_at)}
                     for s in self._sessions.values()]
        return {"host": self._host, "port": self._port, "clients": len(peers), "peers": peers}
