"""Protocol constants and message-type enum for Intelligent-NIDS."""

from enum import Enum

# Network defaults
DEFAULT_HOST: str = "0.0.0.0"
DEFAULT_PORT: int = 5000
WEB_PORT: int     = 8080
WS_PORT: int      = 8081
BUFFER_SIZE: int  = 4096
ENCODING: str     = "utf-8"
MAX_CLIENTS: int  = 5
USE_TLS: bool     = True

# Timeouts (seconds)
SOCKET_TIMEOUT: float     = 300.0
RECONNECT_DELAY: float    = 3.0
MAX_RECONNECT_TRIES: int  = 5
HEARTBEAT_INTERVAL: float = 10.0

# File transfer
FILE_CHUNK_SIZE: int       = 65536       # 64 KB
MAX_FILE_SIZE: int         = 104857600   # 100 MB
FILE_TRANSFER_TIMEOUT: int = 300

# Wire-protocol: NIDS::<json_header>\n<payload_bytes>
HEADER_PREFIX: str = "NIDS::"
HEADER_DELIM: str  = "\n"

class MsgType(str, Enum):
    """Wire-protocol message types."""
    # Session
    HELLO       = "HELLO"
    WELCOME     = "WELCOME"
    DISCONNECT  = "DISCONNECT"
    # Heartbeat
    PING        = "PING"
    PONG        = "PONG"
    # Chat
    CHAT        = "CHAT"
    BROADCAST   = "BROADCAST"
    # File transfer
    FILE_META     = "FILE_META"
    FILE_CHUNK    = "FILE_CHUNK"
    FILE_ACK      = "FILE_ACK"
    FILE_DONE     = "FILE_DONE"
    FILE_ERROR    = "FILE_ERROR"
    FILE_INCOMING = "FILE_INCOMING"
    # Peer management
    PEER_LIST  = "PEER_LIST"
    PEER_JOIN  = "PEER_JOIN"
    PEER_LEAVE = "PEER_LEAVE"
    # System
    ERROR       = "ERROR"
    SERVER_FULL = "SERVER_FULL"
    ACK         = "ACK"

# Trust-score thresholds
TRUST_INITIAL: int   = 100
TRUST_WARNING: int   = 70
TRUST_HIGH_RISK: int = 40
TRUST_BLOCKED: int   = 20
