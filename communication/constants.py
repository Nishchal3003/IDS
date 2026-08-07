"""
constants.py
------------
Protocol-level constants and message type enumerations for the
Intelligent-NIDS private communication network.

These values are shared between server and client so that both sides
speak the exact same wire protocol.  Never hard-code these strings or
numbers anywhere else in the codebase.

Design rationale
----------------
Using an Enum for message types gives us:
  • Type-safety  – comparisons always use the same canonical string.
  • IDE support  – auto-complete and refactoring tools work correctly.
  • Single source of truth – add a new message type here once; it is
    automatically available everywhere.
"""

from enum import Enum


# ---------------------------------------------------------------------------
# Network defaults  (can be overridden by config/network_config.py)
# ---------------------------------------------------------------------------
DEFAULT_HOST: str = "0.0.0.0"        # bind to all interfaces on the server
DEFAULT_PORT: int = 5000              # primary TCP port (TLS)
WEB_PORT: int     = 8080             # HTTP port — serves the browser client UI
WS_PORT: int      = 8081             # WebSocket port — browser real-time comms
BUFFER_SIZE: int  = 4096             # socket recv buffer  (bytes)
ENCODING: str     = "utf-8"          # text encoding for all messages
MAX_CLIENTS: int  = 5                # max simultaneous clients (TCP + browser combined)
USE_TLS: bool     = True             # enable TLS on the TCP socket layer


# ---------------------------------------------------------------------------
# Timeouts  (seconds)
# ---------------------------------------------------------------------------
SOCKET_TIMEOUT: float     = 300.0    # idle connection timeout (5 min - allows large file relay)
RECONNECT_DELAY: float    = 3.0      # seconds between reconnect attempts
MAX_RECONNECT_TRIES: int  = 5        # max automatic reconnect attempts
HEARTBEAT_INTERVAL: float = 10.0     # seconds between keep-alive pings

# ---------------------------------------------------------------------------
# File transfer
# ---------------------------------------------------------------------------
FILE_CHUNK_SIZE: int    = 65536      # 64 KB per file chunk
MAX_FILE_SIZE: int      = 104857600  # 100 MB hard limit
FILE_TRANSFER_TIMEOUT: int = 300     # seconds to wait for file transfer to complete

# ---------------------------------------------------------------------------
# Wire-protocol delimiters
# ---------------------------------------------------------------------------
# Every message frame is:
#   <HEADER_PREFIX><json_header>\n<payload_bytes>
# The header carries msg_type, sender, timestamp, payload_length, etc.
HEADER_PREFIX: str  = "NIDS::"      # magic prefix – filters stray traffic
HEADER_DELIM: str   = "\n"          # separates JSON header from payload


# ---------------------------------------------------------------------------
# Message types  (the msg_type field inside every JSON header)
# ---------------------------------------------------------------------------
class MsgType(str, Enum):
    """Canonical message type identifiers for the NIDS wire protocol."""

    # Handshake / session control
    HELLO       = "HELLO"        # client → server  : first message, announces alias
    WELCOME     = "WELCOME"      # server → client  : connection accepted + peer list
    DISCONNECT  = "DISCONNECT"   # either direction : graceful bye

    # Heartbeat
    PING        = "PING"         # either direction : keep-alive probe
    PONG        = "PONG"         # reply to PING

    # Chat
    CHAT        = "CHAT"         # plain text message
    BROADCAST   = "BROADCAST"    # server relays a CHAT to all clients

    # File transfer
    FILE_META   = "FILE_META"    # sender announces file name + size
    FILE_CHUNK  = "FILE_CHUNK"   # one chunk of file bytes  (base64 encoded)
    FILE_ACK    = "FILE_ACK"     # receiver acknowledges a chunk
    FILE_DONE   = "FILE_DONE"    # sender signals end of file transfer
    FILE_ERROR  = "FILE_ERROR"   # either side reports a transfer failure
    FILE_INCOMING = "FILE_INCOMING"  # server relays a complete file to a peer

    # Device / peer management
    PEER_LIST   = "PEER_LIST"    # server → client  : current online peers
    PEER_JOIN   = "PEER_JOIN"    # server → all     : new client connected
    PEER_LEAVE  = "PEER_LEAVE"   # server → all     : client disconnected

    # System / error
    ERROR       = "ERROR"        # server reports an error to the client
    SERVER_FULL = "SERVER_FULL"  # server is at MAX_CLIENTS capacity
    ACK         = "ACK"          # generic acknowledgement


# ---------------------------------------------------------------------------
# Trust-score thresholds  (used later by the IDS trust engine)
# ---------------------------------------------------------------------------
TRUST_INITIAL: int    = 100
TRUST_WARNING: int    = 70
TRUST_HIGH_RISK: int  = 40
TRUST_BLOCKED: int    = 20
