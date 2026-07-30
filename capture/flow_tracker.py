"""
flow_tracker.py
---------------
Manages the registry of all active network flows.

Responsibilities
----------------
1. Create a new Flow when the first packet of a conversation arrives.
2. Update the matching Flow with every subsequent packet.
3. Expire flows that have been idle longer than FLOW_TIMEOUT.
4. Expire TCP flows immediately on FIN or RST.
5. Push completed flows to a queue for feature extraction.

Thread safety
-------------
``FlowTracker`` is accessed from two threads:
  • The Scapy callback thread (adds packets via ``add_packet()``)
  • The expiry thread (calls ``_expire_old_flows()`` periodically)

A single ``threading.Lock`` guards ``self._flows``.  The design keeps the
lock held for the minimum possible time to avoid blocking the sniffer.

Bidirectional flow keying
--------------------------
The 5-tuple key is always stored in a canonical order so that packets
travelling in both directions hash to the same Flow:

    key = (min(src,dst)_ip, min_port, max(src,dst)_ip, max_port, proto)

The first packet's source address is stored on the Flow as ``src_ip``
to know which direction is "forward".
"""

import queue
import threading
import time
from typing import Dict, Optional, Tuple

from capture.constants import (
    ACTIVITY_TIMEOUT,
    FLOW_TIMEOUT,
    MAX_FLOWS,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    TCP_FIN,
    TCP_RST,
)
from capture.flow import Flow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flow_key(src_ip: str, dst_ip: str,
              src_port: int, dst_port: int,
              proto: int) -> str:
    """
    Build a canonical bidirectional flow key string.

    The lower-IP side always comes first.  For equal IPs, the lower port
    comes first.  This ensures both directions map to the same key.
    """
    if (src_ip, src_port) < (dst_ip, dst_port):
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"


def _is_forward(flow: Flow, src_ip: str, src_port: int) -> bool:
    """Return True if (src_ip, src_port) matches the flow's forward direction."""
    return flow.src_ip == src_ip and flow.src_port == src_port


# ---------------------------------------------------------------------------
# FlowTracker
# ---------------------------------------------------------------------------

class FlowTracker:
    """
    Thread-safe registry of active network flows.

    Parameters
    ----------
    completed_queue : queue.Queue
        Push completed Flow objects here; the CaptureLogger consumes them.
    flow_timeout : float
        Seconds of inactivity before a flow is expired (default FLOW_TIMEOUT).
    """

    def __init__(
        self,
        completed_queue: queue.Queue,
        flow_timeout: float = FLOW_TIMEOUT,
    ) -> None:
        self._flows: Dict[str, Flow] = {}
        self._lock  = threading.Lock()
        self._completed_queue = completed_queue
        self._flow_timeout    = flow_timeout

        self._pkts_seen   = 0   # total packets processed (for stats)
        self._flows_total = 0   # total flows completed  (for stats)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_packet(
        self,
        src_ip:    str,
        dst_ip:    str,
        src_port:  int,
        dst_port:  int,
        proto:     int,
        pkt_len:   int,         # payload bytes (excluding IP+TCP/UDP header)
        header_len:int,         # IP + TCP/UDP header bytes
        flags:     int,         # TCP flags int (0 for UDP/ICMP)
        timestamp: float,       # packet.time (float seconds)
        win_size:  int = -1,    # TCP window size (-1 if not TCP)
    ) -> None:
        """
        Process one captured packet and update (or create) its flow.

        This method is called from the Scapy sniffer callback thread and
        must return as fast as possible.
        """
        self._pkts_seen += 1
        key = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        with self._lock:
            if key not in self._flows:
                # New flow
                if len(self._flows) >= MAX_FLOWS:
                    self._evict_oldest()
                flow = Flow(
                    flow_id    = key,
                    src_ip     = src_ip,
                    dst_ip     = dst_ip,
                    src_port   = src_port,
                    dst_port   = dst_port,
                    protocol   = proto,
                    start_time = timestamp,
                )
                self._flows[key] = flow
            else:
                flow = self._flows[key]

            flow.last_seen = timestamp
            forward = _is_forward(flow, src_ip, src_port)

            # ── Active / Idle tracking ────────────────────────────────
            if flow.last_active_ts > 0:
                gap = timestamp - flow.last_active_ts
                if gap > ACTIVITY_TIMEOUT:
                    # End of active period
                    active_dur = flow.last_active_ts - flow.active_start
                    if active_dur > 0:
                        flow.active_times.append(active_dur)
                    flow.idle_times.append(gap)
                    flow.subflow_count += 1
                    flow.active_start = timestamp
            flow.last_active_ts = timestamp

            # ── Accumulate per-direction stats ────────────────────────
            if forward:
                flow.fwd_timestamps.append(timestamp)
                flow.fwd_pkt_lens.append(pkt_len)
                flow.fwd_header_lens.append(header_len)
                flow.fwd_flags.append(flags)
                if win_size >= 0 and flow.fwd_init_win_bytes < 0:
                    flow.fwd_init_win_bytes = win_size
                if pkt_len > 0:
                    flow.act_data_pkt_fwd += 1
                    if flow.min_seg_size_fwd == 0 or pkt_len < flow.min_seg_size_fwd:
                        flow.min_seg_size_fwd = pkt_len
            else:
                flow.bwd_timestamps.append(timestamp)
                flow.bwd_pkt_lens.append(pkt_len)
                flow.bwd_header_lens.append(header_len)
                flow.bwd_flags.append(flags)
                if win_size >= 0 and flow.bwd_init_win_bytes < 0:
                    flow.bwd_init_win_bytes = win_size

            # ── TCP flow termination on FIN or RST ────────────────────
            if proto == PROTO_TCP and (flags & TCP_FIN or flags & TCP_RST):
                flow.is_finished = True
                self._complete_flow(key, flow)

    def expire_idle_flows(self) -> int:
        """
        Expire and flush all flows idle longer than ``flow_timeout``.

        Returns the number of flows expired.
        Called periodically from a background thread.
        """
        now     = time.time()
        expired = []

        with self._lock:
            for key, flow in list(self._flows.items()):
                if now - flow.last_seen > self._flow_timeout:
                    expired.append((key, flow))

        for key, flow in expired:
            with self._lock:
                self._complete_flow(key, flow)

        return len(expired)

    def flush_all(self) -> int:
        """
        Force-complete all remaining active flows.

        Called on Ctrl+C / shutdown to ensure no data is lost.
        """
        with self._lock:
            keys = list(self._flows.keys())

        for key in keys:
            with self._lock:
                flow = self._flows.get(key)
                if flow:
                    self._complete_flow(key, flow)

        return len(keys)

    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    @property
    def stats(self) -> dict:
        return {
            "active_flows"    : self.active_flow_count,
            "completed_flows" : self._flows_total,
            "packets_seen"    : self._pkts_seen,
        }

    # ------------------------------------------------------------------
    # Private helpers (must be called with lock held)
    # ------------------------------------------------------------------

    def _complete_flow(self, key: str, flow: Flow) -> None:
        """Remove flow from registry and enqueue for feature extraction."""
        self._flows.pop(key, None)
        self._flows_total += 1
        # Update the final active period
        final_active = flow.last_seen - flow.active_start
        if final_active > 0:
            flow.active_times.append(final_active)
        self._completed_queue.put(flow)

    def _evict_oldest(self) -> None:
        """Evict the oldest flow when the registry is full."""
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].start_time)
        self._complete_flow(oldest_key, self._flows[oldest_key])
