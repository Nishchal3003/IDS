"""WebSocket bridge connecting browser clients to NIDSServer."""

import asyncio
import base64
import json
import math
import threading
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from communication.constants import (
    ENCODING, FILE_CHUNK_SIZE, MAX_CLIENTS, MAX_FILE_SIZE, MsgType, TRUST_INITIAL,
)
from communication.logger import get_logger
from communication.protocol import (
    build_file_chunk_frame, build_frame, build_text_frame, decode_frame_bytes,
)
from communication.security import certs_exist, server_ssl_context, verify_auth_token
from communication.utils import format_size, is_lan_peer, timestamp_to_str

if TYPE_CHECKING:
    from communication.server_core import NIDSServer

log = get_logger("ws_bridge")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RECEIVED_DIR = PROJECT_ROOT / "received_files" / "browser"


def _frame_to_json(frame) -> Optional[dict]:
    """Convert a NIDS Frame to a JSON-serialisable dict for the browser."""
    mt = frame.msg_type
    if mt == MsgType.BROADCAST:
        return {"type": "BROADCAST", "from": frame.extra.get("from", frame.sender),
                "text": frame.text, "time": frame.extra.get("time", timestamp_to_str(frame.timestamp))}
    if mt == MsgType.WELCOME:
        return {"type": "WELCOME", "message": frame.text, "peers": frame.extra.get("peers", [])}
    if mt == MsgType.PEER_JOIN:
        return {"type": "PEER_JOIN",  "alias": frame.extra.get("alias", frame.sender), "message": frame.text}
    if mt == MsgType.PEER_LEAVE:
        return {"type": "PEER_LEAVE", "alias": frame.extra.get("alias", frame.sender), "message": frame.text}
    if mt == MsgType.ACK:         return {"type": "ACK",        "message": frame.text}
    if mt == MsgType.ERROR:       return {"type": "ERROR",       "message": frame.text}
    if mt == MsgType.SERVER_FULL: return {"type": "SERVER_FULL", "message": frame.text}
    if mt == MsgType.DISCONNECT:  return {"type": "DISCONNECT",  "message": frame.text}
    if mt == MsgType.PING:        return {"type": "PING"}
    if mt == MsgType.PEER_LIST:   return {"type": "PEER_LIST",   "peers": frame.extra.get("peers", [])}
    if mt == MsgType.FILE_INCOMING:
        return {"type": "FILE_INCOMING", "from": frame.extra.get("from", frame.sender),
                "filename": frame.extra.get("file_name", "file"),
                "size": frame.extra.get("file_size", 0),
                "data": frame.payload.decode("ascii")}
    return None


class BrowserSession:
    """One browser client connected via WebSocket. Mirrors ClientSession interface."""

    def __init__(self, websocket, server: "NIDSServer", loop: asyncio.AbstractEventLoop) -> None:
        self._ws, self._server, self._loop = websocket, server, loop
        self._browser_key: int = 0
        self._is_browser: bool = True
        self.alias        = f"browser@{websocket.remote_address[0]}"
        self.address      = websocket.remote_address
        self.trust_score  = TRUST_INITIAL
        self.connected_at = time.time()
        self._alive       = True

    def send(self, data: bytes) -> bool:
        if not self._alive:
            return False
        frame = decode_frame_bytes(data)
        if frame is None:
            return False
        payload = _frame_to_json(frame)
        if payload is None:
            return True  # silently ignore irrelevant frames
        js = json.dumps(payload)
        try:
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is self._loop:
                self._loop.create_task(self._ws.send(js))
            else:
                asyncio.run_coroutine_threadsafe(self._ws.send(js), self._loop).result(timeout=5)
            return True
        except Exception as e:
            log.warning("BrowserSession.send failed for %s: %s", self.alias, e)
            self._alive = False
            return False

    def disconnect(self, reason: str = "server request") -> None:
        if not self._alive:
            return
        self._alive = False
        try:
            asyncio.run_coroutine_threadsafe(
                self._ws.send(json.dumps({"type": "DISCONNECT", "message": reason})),
                self._loop).result(timeout=2)
        except Exception:
            pass
        asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)

    async def _handle_hello(self, data: dict) -> None:
        alias = "".join(c for c in data.get("alias", "browser-user").strip()
                        if c.isalnum() or c in "-_")[:20] or "browser-user"
        existing = [s.alias for s in self._server.sessions.values()]
        if alias in existing:
            alias = f"{alias}-{self.address[1]}"
        self.alias = alias

        try:
            from config.network_config import NETWORK_PSK
        except ImportError:
            NETWORK_PSK = ""
        if NETWORK_PSK and not verify_auth_token(NETWORK_PSK, alias, data.get("auth_token", "")):
            log.warning("Browser auth FAILED for '%s' from %s", alias, self.address[0])
            await self._ws.send(json.dumps({"type": "ERROR",
                                            "message": "Authentication failed. Wrong network password.",
                                            "pre_login": True}))
            self._alive = False
            return

        n = len(self._server.sessions)
        if n >= MAX_CLIENTS:
            log.warning("[WS] Server full (%d/%d), rejecting %s", n, MAX_CLIENTS, alias)
            await self._ws.send(json.dumps({"type": "SERVER_FULL",
                                            "message": f"Server full ({n}/{MAX_CLIENTS}). Try later.",
                                            "pre_login": True}))
            self._alive = False
            return

        self._server.register_browser_session(self)
        log.info("Browser HELLO from %s (%s)", self.alias, self.address[0])
        peers = [s.alias for s in self._server.sessions.values() if s is not self]
        await self._ws.send(json.dumps({"type": "WELCOME",
                                        "message": f"Welcome to NIDS-Net, {self.alias}!",
                                        "peers": peers}))
        self._server.broadcast(
            build_text_frame(MsgType.PEER_JOIN, "server", f"{self.alias} joined",
                             extra={"alias": self.alias, "ip": self.address[0]}),
            exclude=self)

    async def _handle_chat(self, data: dict) -> None:
        text = data.get("text", "").strip()
        if not text:
            return
        ts = timestamp_to_str(time.time())
        self._server.broadcast(
            build_text_frame(MsgType.BROADCAST, self.alias, text,
                             extra={"from": self.alias, "time": ts}), exclude=self)
        await self._ws.send(json.dumps({"type": "BROADCAST", "from": self.alias, "text": text, "time": ts}))

    async def _handle_file(self, data: dict) -> None:
        filename = data.get("filename", "upload")
        b64data  = data.get("data", "")
        try:
            raw = base64.b64decode(b64data)
        except Exception as e:
            await self._ws.send(json.dumps({"type": "ERROR", "message": f"Bad file data: {e}"})); return
        if len(raw) > MAX_FILE_SIZE:
            await self._ws.send(json.dumps({"type": "ERROR",
                                            "message": f"File too large ({format_size(len(raw))}). Limit: {format_size(MAX_FILE_SIZE)}"}))
            return

        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        (RECEIVED_DIR / filename).write_bytes(raw)
        size         = len(raw)
        total_chunks = math.ceil(size / FILE_CHUNK_SIZE) or 1
        log.info("[FILE] Browser %s → '%s' (%s)", self.alias, filename, format_size(size))
        await self._ws.send(json.dumps({"type": "ACK",
                                        "message": f"'{filename}' received ({format_size(size)}) — relaying"}))

        others        = [s for s in self._server.sessions.values() if s is not self]
        tcp_peers     = [s for s in others if not hasattr(s, "_is_browser")]
        browser_peers = [s for s in others if hasattr(s, "_is_browser")]

        if tcp_peers:
            frames = [build_text_frame(MsgType.FILE_META, self.alias, filename,
                                       extra={"file_name": filename, "file_size": size,
                                              "total_chunks": total_chunks, "from": self.alias})]
            for i in range(total_chunks):
                frames.append(build_file_chunk_frame(self.alias, raw[i*FILE_CHUNK_SIZE:(i+1)*FILE_CHUNK_SIZE],
                                                     filename, i, total_chunks))
            frames.append(build_text_frame(MsgType.FILE_DONE, self.alias, filename))

            def _relay_tcp():
                for f in frames:
                    for p in list(tcp_peers):
                        try: p.send(f)
                        except Exception as e: log.warning("[FILE] TCP→%s: %s", p.alias, e)

            await asyncio.get_event_loop().run_in_executor(None, _relay_tcp)

        if browser_peers:
            incoming = build_frame(MsgType.FILE_INCOMING, self.alias, b64data.encode("ascii"),
                                   extra={"file_name": filename, "file_size": size, "from": self.alias})
            for s in browser_peers:
                try: s.send(incoming)
                except Exception as e: log.warning("[FILE] Browser→%s: %s", getattr(s,"alias","?"), e)

        ts = timestamp_to_str(time.time())
        notice_text = f"{self.alias} shared '{filename}' ({format_size(size)}) — available to all"
        self._server.broadcast(
            build_text_frame(MsgType.BROADCAST, "server", notice_text,
                             extra={"from": "server", "time": ts}), exclude=self)
        await self._ws.send(json.dumps({"type": "BROADCAST", "from": "server", "text": notice_text, "time": ts}))

    async def _handle_list_peers(self) -> None:
        peers = [s.alias for s in self._server.sessions.values() if s is not self]
        await self._ws.send(json.dumps({"type": "PEER_LIST", "peers": peers}))

    async def run(self) -> None:
        """Async receive loop. Session is only registered after successful HELLO."""
        _registered = False
        try:
            async for raw_msg in self._ws:
                if not self._alive:
                    break
                try:
                    data = json.loads(raw_msg)
                except json.JSONDecodeError:
                    log.warning("Malformed JSON from %s", self.alias); continue
                t = data.get("type", "").upper()
                if   t == "HELLO":      await self._handle_hello(data); _registered = self._alive and bool(self._browser_key)
                elif t == "CHAT":       await self._handle_chat(data)
                elif t == "FILE":       await self._handle_file(data)
                elif t == "LIST_PEERS": await self._handle_list_peers()
                elif t == "DISCONNECT": self._alive = False; break
                elif t == "PONG":       pass
                else: log.warning("Unknown msg_type: %s", t)
        except Exception as e:
            log.warning("BrowserSession %s error: %s", self.alias, e)
        finally:
            self._alive = False
            if _registered:
                self._server.unregister_browser_session(self)
            log.info("Browser session closed: %s", self.alias)


def start_ws_server(server: "NIDSServer", host: str, port: int) -> None:
    """Start the WebSocket server in a background daemon thread (WSS if certs present)."""
    try:
        import websockets
    except ImportError:
        log.error("websockets not installed. Run: pip install websockets"); return

    ssl_ctx = None
    if certs_exist():
        try:
            ssl_ctx = server_ssl_context()
            log.info("WebSocket server will use WSS")
        except Exception as e:
            log.warning("WSS failed, falling back to plain WS: %s", e)
    else:
        log.warning("No TLS certs — WebSocket using plain ws://. Run: python -m communication.generate_certs")

    async def _handler(websocket):
        ip = websocket.remote_address[0]
        if server._lan_only and not is_lan_peer(ip, server._local_ip):
            log.warning("[WS] Rejecting %s — not on LAN", ip)
            try:
                await websocket.send(json.dumps({"type": "ERROR",
                                                 "message": "Rejected: LAN-only server.",
                                                 "lan_reject": True}))
            except Exception:
                pass
            await websocket.close(1008, "LAN-only"); return
        await BrowserSession(websocket, server, asyncio.get_event_loop()).run()

    async def _serve():
        async with websockets.serve(_handler, host, port, ssl=ssl_ctx,
                                    max_size=None, ping_interval=20, ping_timeout=60):
            await asyncio.Future()

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try: loop.run_until_complete(_serve())
        except Exception as e: log.error("WebSocket server error: %s", e)

    threading.Thread(target=_thread, daemon=True, name="ws-server").start()
    log.info("%s server started (port %d)", "WSS" if ssl_ctx else "WS", port)
