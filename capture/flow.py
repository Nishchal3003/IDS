"""
flow.py
-------
The Flow dataclass accumulates all raw per-packet statistics during the
lifetime of a single network conversation (5-tuple: src_ip, src_port,
dst_ip, dst_port, protocol).

A Flow is created when the first packet of a conversation is seen and
updated with every subsequent packet until the flow is expired
(TCP FIN/RST, or idle timeout).  Feature extraction then converts the
accumulated raw data into the 78-column CIC-IDS 2017 feature vector.

Design notes
------------
• All timestamps are stored as float seconds (from packet.time).
• Payload lengths (fwd/bwd_pkt_lens) exclude IP + transport headers —
  they represent the actual data bytes sent.
• Header lengths are per-packet (IP + TCP/UDP header size in bytes).
• TCP flags are stored as raw integers (bitmask); the feature extractor
  counts individual bits across all packets.
• forward direction = direction of the FIRST packet seen in the flow.
"""

import time
from dataclasses import dataclass, field
from typing import List


@dataclass
class Flow:
    """
    Accumulates per-packet statistics for one network flow.

    Parameters supplied at construction
    ------------------------------------
    flow_id      : canonical 5-tuple string key
    src_ip       : source IP of the first (forward-direction) packet
    dst_ip       : destination IP
    src_port     : source port (0 for ICMP)
    dst_port     : destination port (0 for ICMP)
    protocol     : IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    start_time   : timestamp of the first packet (float seconds)
    """

    # ── Identity ──────────────────────────────────────────────────────────
    flow_id  : str
    src_ip   : str
    dst_ip   : str
    src_port : int
    dst_port : int
    protocol : int
    start_time: float

    # ── Running timestamps ────────────────────────────────────────────────
    last_seen: float = field(default=0.0)

    # ── Forward packet data (src → dst) ──────────────────────────────────
    fwd_timestamps  : List[float] = field(default_factory=list)
    fwd_pkt_lens    : List[int]   = field(default_factory=list)  # payload bytes
    fwd_header_lens : List[int]   = field(default_factory=list)  # IP+TCP/UDP header bytes
    fwd_flags       : List[int]   = field(default_factory=list)  # TCP flag int per pkt

    # ── Backward packet data (dst → src) ─────────────────────────────────
    bwd_timestamps  : List[float] = field(default_factory=list)
    bwd_pkt_lens    : List[int]   = field(default_factory=list)
    bwd_header_lens : List[int]   = field(default_factory=list)
    bwd_flags       : List[int]   = field(default_factory=list)

    # ── TCP window sizes (first packet only) ─────────────────────────────
    fwd_init_win_bytes: int = -1   # -1 = not yet seen / non-TCP
    bwd_init_win_bytes: int = -1

    # ── Bulk transfer tracking ────────────────────────────────────────────
    # "Bulk" = a run of consecutive packets with payload in the same direction
    fwd_bulk_state_count       : int   = 0
    fwd_bulk_size_total        : int   = 0
    fwd_bulk_packet_count      : int   = 0
    fwd_bulk_duration          : float = 0.0
    fwd_bulk_start_helper      : float = 0.0
    fwd_bulk_packet_count_helper: int  = 0
    fwd_bulk_size_helper       : int   = 0

    bwd_bulk_state_count       : int   = 0
    bwd_bulk_size_total        : int   = 0
    bwd_bulk_packet_count      : int   = 0
    bwd_bulk_duration          : float = 0.0
    bwd_bulk_start_helper      : float = 0.0
    bwd_bulk_packet_count_helper: int  = 0
    bwd_bulk_size_helper       : int   = 0

    # ── Active / Idle period tracking ─────────────────────────────────────
    # Active period = consecutive packets with gaps < ACTIVITY_TIMEOUT
    # Idle period   = gap between active periods
    active_start    : float      = 0.0
    last_active_ts  : float      = 0.0
    active_times    : List[float] = field(default_factory=list)
    idle_times      : List[float] = field(default_factory=list)

    # ── Flow state flags ──────────────────────────────────────────────────
    is_finished: bool = False   # set when FIN/RST seen (TCP) or timed out

    # ── Subflow counter ───────────────────────────────────────────────────
    # A subflow starts after a gap; simple version: = 1 + number of idle periods
    subflow_count: int = 1

    # ── Number of fwd packets that actually carried data (payload > 0) ───
    act_data_pkt_fwd: int = 0

    # ── Smallest payload seen in fwd direction ────────────────────────────
    min_seg_size_fwd: int = 0

    def __post_init__(self) -> None:
        self.last_seen      = self.start_time
        self.last_active_ts = self.start_time
        self.active_start   = self.start_time

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------
    @property
    def total_packets(self) -> int:
        return len(self.fwd_pkt_lens) + len(self.bwd_pkt_lens)

    @property
    def duration_us(self) -> int:
        """Flow duration in microseconds (as in CIC-IDS 2017)."""
        return int((self.last_seen - self.start_time) * 1_000_000)

    @property
    def duration_s(self) -> float:
        return self.last_seen - self.start_time

    @property
    def all_pkt_lens(self) -> List[int]:
        return self.fwd_pkt_lens + self.bwd_pkt_lens

    def __repr__(self) -> str:
        return (
            f"Flow({self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} "
            f"proto={self.protocol} pkts={self.total_packets})"
        )
