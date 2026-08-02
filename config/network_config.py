"""
config/network_config.py
------------------------
Central network configuration for the Intelligent-NIDS project.

All modules import from here.  Change values here only — never
hard-code IPs, ports, or sizes anywhere else.
"""

# ── Server binding ────────────────────────────────────────────────────────────
HOST: str    = "0.0.0.0"    # Bind to all interfaces  (server side)
PORT: int    = 5000          # Primary TCP port  (TLS encrypted)
WEB_PORT: int  = 8080         # HTTP port  (kept for internal redirect)
WS_PORT: int   = 8081         # WS port   (kept for reference)
HTTPS_PORT: int = 8443        # HTTPS port – serves browser client UI (TLS)
WSS_PORT: int   = 8444        # WSS port  – browser WebSocket over TLS

# ── Security ──────────────────────────────────────────────────────────────────
USE_TLS: bool = True         # Enable TLS on TCP sockets (requires certs/)

# ── Security — Authentication & Integrity ─────────────────────────────────────
# Set NETWORK_PSK to a non-empty string to require a password to join.
# Leave empty ("") to disable auth (open network, backward compatible).
NETWORK_PSK: str   = "nids-secure-2026"   # Pre-shared key for HMAC auth
HMAC_ALGORITHM: str = "sha256"             # Algorithm used for auth + integrity



# ── Protocol ──────────────────────────────────────────────────────────────────
BUFFER_SIZE: int = 4096    # Socket recv buffer in bytes
ENCODING: str    = "utf-8" # Text encoding for all messages

# ── Timeouts ──────────────────────────────────────────────────────────────────
SOCKET_TIMEOUT: float     = 60.0    # Seconds before idle socket is closed
RECONNECT_DELAY: float    = 3.0     # Seconds between reconnect attempts
MAX_RECONNECT_TRIES: int  = 5       # Maximum automatic reconnect attempts
HEARTBEAT_INTERVAL: float = 10.0    # Seconds between server PING messages

# ── Capacity ──────────────────────────────────────────────────────────────────
MAX_CLIENTS: int = 10      # Maximum simultaneous client connections

# ── File transfer ─────────────────────────────────────────────────────────────
FILE_CHUNK_SIZE: int = 65536        # 64 KB per chunk
MAX_FILE_SIZE: int   = 104857600    # 100 MB hard limit

# ── Phase 2: Packet Capture ───────────────────────────────────────────────────
CAPTURE_INTERFACE: str   = ""       # "" = auto-detect active interface
FLOW_TIMEOUT: float      = 120.0    # Seconds before idle flow is expired
ACTIVITY_TIMEOUT: float  = 5.0      # Seconds threshold for active/idle splits
CAPTURE_CSV_DIR: str     = "datasets/captures"   # output directory
CAPTURE_BPF_FILTER: str  = "ip"     # BPF filter: "ip" = all IPv4 traffic
MAX_FLOWS: int           = 100_000  # Max simultaneous flows tracked in memory