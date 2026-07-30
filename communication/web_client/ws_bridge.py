"""
ws_bridge.py
------------
WebSocket bridge that connects browser clients to the NIDSServer session
registry, enabling real-time bidirectional communication without any
client-side installation.

Architecture
------------
::

    Browser (any device)
        |
        | WebSocket (ws://server-ip:8081)
        |
    BrowserSession  ←──────────────────────── NIDSServer._sessions
        |                                          |
        | bridge: JSON ↔ NIDS Frame               | broadcast() / remove_session()
        |                                          |
    WebSocket handler (asyncio)        ClientSession threads (threading)

BrowserSession
~~~~~~~~~~~~~~
Mimics the ``ClientSession`` interface so ``NIDSServer.broadcast()`` can
send frames to browser clients exactly as it does to TCP clients.

When ``broadcast()`` calls ``session.send(raw_bytes)``, BrowserSession:
  1. Decodes the NIDS binary frame with ``decode_frame_bytes()``.
  2. Converts the Frame to a JSON dict.
  3. Schedules ``websocket.send(json)`` on the asyncio event loop.

Browser → Server JSON protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    {"type": "HELLO",      "alias": "MyPhone"}
    {"type": "CHAT",       "text": "Hello!"}
    {"type": "FILE",       "filename": "notes.pdf", "data": "<base64>", "size": 12345}
    {"type": "LIST_PEERS"}
    {"type": "DISCONNECT"}

Server → Browser JSON protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    {"type": "WELCOME",      "message": "...", "peers": [...]}
    {"type": "BROADCAST",    "from": "Alice",  "text": "...", "time": "10:30:00"}
    {"type": "PEER_JOIN",    "alias": "Bob",   "message": "Bob joined"}
    {"type": "PEER_LEAVE",   "alias": "Bob",   "message": "Bob left"}
    {"type": "ACK",          "message": "File received"}
    {"type": "PEER_LIST",    "peers": [...]}
    {"type": "ERROR",        "message": "..."}
    {"type": "DISCONNECT",   "message": "reason"}
    {"type": "FILE_INCOMING","from": "Alice", "filename": "doc.pdf",
                             "data": "<base64>", "size": 12345}
"""

import asyncio
import base64
import json
import threading
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from communication.constants import (
    ENCODING,
    MAX_FILE_SIZE,
    MsgType,
    TRUST_INITIAL,
    WS_PORT,
)
from communication.logger import get_logger
from communication.protocol import decode_frame_bytes, build_text_frame
from communication.utils import format_size, timestamp_to_str

if TYPE_CHECKING:
    from communication.server_core import NIDSServer

log = get_logger("ws_bridge")

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
RECEIVED_DIR: Path = PROJECT_ROOT / "received_files" / "browser"


# ---------------------------------------------------------------------------
# Helper: Frame → JSON dict for the browser
# ---------------------------------------------------------------------------
def _frame_to_browser_json(frame) -> Optional[dict]:
    """Convert a decoded NIDS Frame to a JSON-serialisable dict."""
    if frame.msg_type == MsgType.BROADCAST:
        return {
            "type" : "BROADCAST",
            "from" : frame.extra.get("from", frame.sender),
            "text" : frame.text,
            "time" : frame.extra.get("time", timestamp_to_str(frame.timestamp)),
        }
    if frame.msg_type == MsgType.WELCOME:
        return {
            "type"    : "WELCOME",
            "message" : frame.text,
            "peers"   : frame.extra.get("peers", []),
        }
    if frame.msg_type == MsgType.PEER_JOIN:
        return {
            "type"    : "PEER_JOIN",
            "alias"   : frame.extra.get("alias", frame.sender),
            "message" : frame.text,
        }
    if frame.msg_type == MsgType.PEER_LEAVE:
        return {
            "type"    : "PEER_LEAVE",
            "alias"   : frame.extra.get("alias", frame.sender),
            "message" : frame.text,
        }
    if frame.msg_type == MsgType.ACK:
        return {"type": "ACK", "message": frame.text}
    if frame.msg_type == MsgType.ERROR:
        return {"type": "ERROR", "message": frame.text}
    if frame.msg_type == MsgType.SERVER_FULL:
        return {"type": "ERROR", "message": frame.text}
    if frame.msg_type == MsgType.DISCONNECT:
        return {"type": "DISCONNECT", "message": frame.text}
    if frame.msg_type == MsgType.PING:
        return {"type": "PING"}
    if frame.msg_type == MsgType.PEER_LIST:
        return {"type": "PEER_LIST", "peers": frame.extra.get("peers", [])}
    # All other frame types are silently dropped (not relevant to browser)
    return None


# ---------------------------------------------------------------------------
# BrowserSession
# ---------------------------------------------------------------------------
class BrowserSession:
    """
    Represents one browser client connected via WebSocket.

    This class mirrors the ``ClientSession`` interface so it can be
    registered in ``NIDSServer._sessions`` and participate in broadcasts.

    Parameters
    ----------
    websocket :
        The ``websockets`` WebSocket connection object.
    server : NIDSServer
        Reference to the shared server instance.
    loop : asyncio.AbstractEventLoop
        The asyncio event loop running in the WebSocket thread.
    """

    def __init__(self, websocket, server: "NIDSServer", loop: asyncio.AbstractEventLoop) -> None:
        self._ws        = websocket
        self._server    = server
        self._loop      = loop
        self._browser_key: int = 0   # set by register_browser_session()

        # Mirrors ClientSession public attributes
        self.alias: str          = f"browser@{websocket.remote_address[0]}"
        self.address: tuple      = websocket.remote_address
        self.trust_score: int    = TRUST_INITIAL
        self.connected_at: float = time.time()
        self._alive: bool        = True

    # ------------------------------------------------------------------
    # ClientSession-compatible interface
    # ------------------------------------------------------------------
    def send(self, data: bytes) -> bool:
        """
        Receive a NIDS binary frame, decode it, convert to JSON, and
        forward to the browser over WebSocket.
        """
        if not self._alive:
            return False
        frame = decode_frame_bytes(data)
        if frame is None:
            return False
        payload = _frame_to_browser_json(frame)
        if payload is None:
            return True   # silently ignore irrelevant frame types
        json_str = json.dumps(payload)
        try:
            # Detect whether we are being called from WITHIN the asyncio
            # event loop (e.g. from _handle_chat → server.broadcast()) or
            # from an external thread (TCP session thread, heartbeat thread).
            #
            # If we're on the same loop and call .result() we would deadlock
            # because .result() blocks the very loop it's waiting on.
            try:
                running_loop = asyncio.get_running_loop()
            except RuntimeError:
                running_loop = None

            if running_loop is self._loop:
                # Same event loop — schedule as a fire-and-forget task.
                self._loop.create_task(self._ws.send(json_str))
            else:
                # External thread — safe to block.
                asyncio.run_coroutine_threadsafe(
                    self._ws.send(json_str), self._loop
                ).result(timeout=5)
            return True
        except Exception as exc:
            log.warning("BrowserSession.send failed for %s: %s", self.alias, exc)
            self._alive = False
            return False

    def disconnect(self, reason: str = "server request") -> None:
        """Close the WebSocket connection."""
        if not self._alive:
            return
        self._alive = False
        msg = json.dumps({"type": "DISCONNECT", "message": reason})
        try:
            asyncio.run_coroutine_threadsafe(
                self._ws.send(msg), self._loop
            ).result(timeout=2)
        except Exception:
            pass
        asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)

    # ------------------------------------------------------------------
    # Incoming message handlers (called from asyncio context)
    # ------------------------------------------------------------------
    async def _handle_hello(self, data: dict) -> None:
        alias = data.get("alias", "browser-user").strip()
        # Sanitise: keep only safe chars
        alias = "".join(c for c in alias if c.isalnum() or c in "-_")[:20] or "browser-user"
        # Ensure uniqueness
        existing = [s.alias for s in self._server.sessions.values()]
        if alias in existing:
            alias = f"{alias}-{self.address[1]}"
        self.alias = alias
        log.info("Browser HELLO from %s (%s)", self.alias, self.address[0])

        peers = [s.alias for s in self._server.sessions.values() if s is not self]
        welcome = json.dumps({
            "type"    : "WELCOME",
            "message" : f"Welcome to NIDS-Net, {self.alias}!",
            "peers"   : peers,
        })
        await self._ws.send(welcome)

        # Notify existing clients
        join_frame = build_text_frame(
            MsgType.PEER_JOIN, "server",
            f"{self.alias} joined the network",
            extra={"alias": self.alias, "ip": self.address[0]},
        )
        self._server.broadcast(join_frame, exclude=self)

    async def _handle_chat(self, data: dict) -> None:
        text = data.get("text", "").strip()
        if not text:
            return
        log.info("[CHAT] %s (browser) -> broadcast: %s", self.alias, text)
        ts = timestamp_to_str(time.time())
        relay = build_text_frame(
            MsgType.BROADCAST, self.alias, text,
            extra={
                "from" : self.alias,
                "time" : ts,
            },
        )
        # Broadcast to everyone EXCEPT self (avoids the event-loop deadlock
        # where send() is called from within the same asyncio loop).
        self._server.broadcast(relay, exclude=self)
        # Echo the message back to self directly with await (safe, no deadlock).
        echo = {"type": "BROADCAST", "from": self.alias, "text": text, "time": ts}
        await self._ws.send(json.dumps(echo))

    async def _handle_file(self, data: dict) -> None:
        filename = data.get("filename", "upload")
        b64data  = data.get("data", "")
        try:
            raw = base64.b64decode(b64data)
        except Exception as exc:
            await self._ws.send(json.dumps({"type": "ERROR", "message": f"Bad file data: {exc}"}))
            return

        if len(raw) > MAX_FILE_SIZE:
            await self._ws.send(json.dumps({
                "type": "ERROR",
                "message": f"File too large ({format_size(len(raw))}). Limit: {format_size(MAX_FILE_SIZE)}",
            }))
            return

        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        dest = RECEIVED_DIR / filename
        dest.write_bytes(raw)
        log.info("[FILE] Browser %s sent '%s' (%s)", self.alias, filename, format_size(len(raw)))

        # ACK back to sender
        await self._ws.send(json.dumps({
            "type"   : "ACK",
            "message": f"File '{filename}' received ({format_size(len(raw))})",
        }))

        # Notify other clients that a file was uploaded
        notice = build_text_frame(
            MsgType.BROADCAST, "server",
            f"{self.alias} uploaded '{filename}' ({format_size(len(raw))})",
            extra={"from": "server", "time": timestamp_to_str(time.time())},
        )
        self._server.broadcast(notice, exclude=self)

    async def _handle_list_peers(self) -> None:
        peers = [s.alias for s in self._server.sessions.values() if s is not self]
        await self._ws.send(json.dumps({"type": "PEER_LIST", "peers": peers}))

    async def _handle_disconnect(self) -> None:
        log.info("Browser %s requested disconnect", self.alias)
        self._alive = False

    # ------------------------------------------------------------------
    # Main async receive loop
    # ------------------------------------------------------------------
    async def run(self) -> None:
        """Async receive loop. Runs until the WebSocket closes."""
        self._server.register_browser_session(self)
        try:
            async for raw_msg in self._ws:
                if not self._alive:
                    break
                try:
                    data = json.loads(raw_msg)
                except json.JSONDecodeError:
                    log.warning("Malformed JSON from browser %s", self.alias)
                    continue

                msg_type = data.get("type", "").upper()

                if msg_type == "HELLO":
                    await self._handle_hello(data)
                elif msg_type == "CHAT":
                    await self._handle_chat(data)
                elif msg_type == "FILE":
                    await self._handle_file(data)
                elif msg_type == "LIST_PEERS":
                    await self._handle_list_peers()
                elif msg_type == "DISCONNECT":
                    await self._handle_disconnect()
                    break
                elif msg_type == "PONG":
                    pass  # valid keep-alive reply, no action needed
                else:
                    log.warning("Unknown browser msg_type: %s", msg_type)

        except Exception as exc:
            log.warning("BrowserSession %s error: %s", self.alias, exc)
        finally:
            self._alive = False
            self._server.unregister_browser_session(self)
            log.info("Browser session closed: %s", self.alias)


# ---------------------------------------------------------------------------
# WebSocket server runner
# ---------------------------------------------------------------------------
def start_ws_server(server: "NIDSServer", host: str, port: int) -> None:
    """
    Start the WebSocket server in a background daemon thread.

    This function is non-blocking — it starts a new thread that owns
    an asyncio event loop and runs the ``websockets.serve()`` loop.

    Parameters
    ----------
    server : NIDSServer
        The shared server instance (for session registration).
    host : str
        Interface to bind (e.g. ``"0.0.0.0"``).
    port : int
        WebSocket port (e.g. ``8081``).
    """
    try:
        import websockets
    except ImportError:
        log.error(
            "websockets package not installed. "
            "Run: pip install websockets"
        )
        return

    async def _handler(websocket):
        session = BrowserSession(websocket, server, asyncio.get_event_loop())
        await session.run()

    async def _serve():
        log.info("WebSocket server starting on %s:%d", host, port)
        async with websockets.serve(_handler, host, port):
            await asyncio.Future()  # run forever

    def _thread_main():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_serve())
        except Exception as exc:
            log.error("WebSocket server error: %s", exc)

    thread = threading.Thread(target=_thread_main, daemon=True, name="ws-server")
    thread.start()
    log.info("WebSocket server thread started (port %d)", port)
