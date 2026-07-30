"""
sniffer.py
----------
Wraps Scapy's packet capture loop and feeds parsed packet fields into
the FlowTracker.

Architecture
------------
Scapy runs ``sniff()`` in the calling thread (blocking).  The sniffer is
therefore started in a dedicated daemon thread by the capture daemon.

For each captured IP packet:
  1. Extract 5-tuple + metadata (length, flags, window, header size).
  2. Call ``flow_tracker.add_packet()`` — fast, lock-guarded.

Non-IP packets (ARP, 802.11 management, etc.) are silently skipped.

Npcap requirement
-----------------
Raw packet capture on Windows requires Npcap (free).
Download: https://npcap.com/#download
Install with "WinPcap API-compatible Mode" checked.

The sniffer checks for Npcap at startup and prints a clear error if it
is missing rather than crashing silently.
"""

import threading
import time
from typing import Callable, Optional

from capture.constants import (
    DEFAULT_FILTER,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
)
from capture.flow_tracker import FlowTracker

# Scapy layers — imported lazily inside start() to avoid slow startup
# when the module is imported but capture is not being used.


# ---------------------------------------------------------------------------
# Npcap / libpcap check
# ---------------------------------------------------------------------------

def check_capture_backend() -> bool:
    """
    Return True if a packet-capture backend (Npcap / WinPcap / libpcap)
    is available.  Print a helpful error and return False if not.
    """
    try:
        from scapy.all import conf
        if not conf.use_pcap:
            _print_npcap_instructions()
            return False
        return True
    except Exception as exc:
        print(f"[ERROR] Scapy import failed: {exc}")
        return False


def _print_npcap_instructions() -> None:
    print()
    print("=" * 64)
    print("  NPCAP NOT FOUND")
    print("=" * 64)
    print("  Raw packet capture on Windows requires Npcap.")
    print()
    print("  Install it in 2 minutes:")
    print("    1. Go to:  https://npcap.com/#download")
    print("    2. Download the latest Npcap installer (.exe)")
    print("    3. Run installer — check 'WinPcap API-compatible Mode'")
    print("    4. Restart this terminal")
    print("    5. Run:  python main.py capture")
    print()
    print("  Npcap is free, open-source, and safe.")
    print("=" * 64)
    print()


# ---------------------------------------------------------------------------
# Interface listing
# ---------------------------------------------------------------------------

def list_interfaces() -> list[dict]:
    """
    Return a list of available network interfaces with readable names.
    Each entry: {'name': str, 'description': str, 'guid': str}
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        raw = get_windows_if_list()
        return [
            {
                "name"       : iface.get("name", "?"),
                "description": iface.get("description", ""),
                "guid"       : iface.get("guid", ""),
                "mac"        : iface.get("mac", ""),
                "ipv4"       : iface.get("ips", [""])[0] if iface.get("ips") else "",
            }
            for iface in raw
        ]
    except Exception:
        try:
            from scapy.all import get_if_list
            return [{"name": n, "description": n, "guid": ""} for n in get_if_list()]
        except Exception as exc:
            print(f"[ERROR] Cannot list interfaces: {exc}")
            return []


def print_interfaces() -> None:
    """Print a formatted table of available interfaces."""
    ifaces = list_interfaces()
    if not ifaces:
        print("  No interfaces found.")
        return
    print()
    print(f"  {'#':<4} {'Name':<35} {'IP':<18} Description")
    print("  " + "-" * 80)
    for i, iface in enumerate(ifaces):
        name = iface['name'][:33]
        ip   = iface.get('ipv4', '')[:16]
        desc = iface['description'][:35]
        print(f"  {i:<4} {name:<35} {ip:<18} {desc}")
    print()


# ---------------------------------------------------------------------------
# Packet parser
# ---------------------------------------------------------------------------

def _parse_packet(pkt, flow_tracker: FlowTracker) -> None:
    """
    Extract fields from one Scapy packet and send to FlowTracker.

    Handles TCP, UDP, ICMP over IPv4.  All other packets are silently
    dropped (e.g. IPv6, ARP).
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if IP not in pkt:
            return

        ip = pkt[IP]
        src_ip  = ip.src
        dst_ip  = ip.dst
        proto   = ip.proto
        ip_hlen = ip.ihl * 4   # IP header length in bytes
        ts      = float(pkt.time)

        src_port  = 0
        dst_port  = 0
        tcp_flags = 0
        win_size  = -1
        transport_hlen = 0
        payload_len    = 0

        if proto == PROTO_TCP and TCP in pkt:
            tcp          = pkt[TCP]
            src_port     = tcp.sport
            dst_port     = tcp.dport
            tcp_flags    = int(tcp.flags)
            win_size     = tcp.window
            transport_hlen = tcp.dataofs * 4
            payload_len  = len(pkt[TCP].payload)

        elif proto == PROTO_UDP and UDP in pkt:
            udp          = pkt[UDP]
            src_port     = udp.sport
            dst_port     = udp.dport
            transport_hlen = 8   # UDP header is always 8 bytes
            payload_len  = len(pkt[UDP].payload)

        elif proto == PROTO_ICMP and ICMP in pkt:
            transport_hlen = 8
            payload_len  = len(pkt[ICMP].payload)

        else:
            return   # unsupported protocol

        total_header = ip_hlen + transport_hlen

        flow_tracker.add_packet(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            src_port   = src_port,
            dst_port   = dst_port,
            proto      = proto,
            pkt_len    = payload_len,
            header_len = total_header,
            flags      = tcp_flags,
            timestamp  = ts,
            win_size   = win_size,
        )

    except Exception:
        pass   # never crash the sniffer on a malformed packet


# ---------------------------------------------------------------------------
# Sniffer class
# ---------------------------------------------------------------------------

class PacketSniffer:
    """
    Wraps Scapy's ``sniff()`` in a daemon thread.

    Parameters
    ----------
    flow_tracker : FlowTracker
        All captured packets are sent here.
    interface : str | None
        Network interface to sniff on.  ``None`` = Scapy picks the default.
    bpf_filter : str
        BPF capture filter (default: ``"ip"`` — all IPv4 traffic).
    on_packet_cb : callable | None
        Optional additional callback called after every packet (for stats).
    """

    def __init__(
        self,
        flow_tracker : FlowTracker,
        interface    : Optional[str] = None,
        bpf_filter   : str = DEFAULT_FILTER,
        on_packet_cb : Optional[Callable] = None,
    ) -> None:
        self._tracker     = flow_tracker
        self._interface   = interface
        self._filter      = bpf_filter
        self._on_pkt      = on_packet_cb
        self._running     = False
        self._thread: Optional[threading.Thread] = None
        self._pkts_seen   = 0

    def start(self) -> None:
        """Start the sniffer in a background daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target   = self._sniff_loop,
            daemon   = True,
            name     = "packet-sniffer",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the sniffer to stop (best effort — Scapy may finish current batch)."""
        self._running = False

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def packets_seen(self) -> int:
        return self._pkts_seen

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sniff_loop(self) -> None:
        from scapy.all import sniff

        def _cb(pkt):
            self._pkts_seen += 1
            _parse_packet(pkt, self._tracker)
            if self._on_pkt:
                self._on_pkt(pkt)

        kwargs: dict = {
            "prn"    : _cb,
            "store"  : False,
            "filter" : self._filter,
        }
        if self._interface:
            kwargs["iface"] = self._interface

        while self._running:
            try:
                # Use count=0 (infinite) with stop_filter for clean exit
                sniff(
                    **kwargs,
                    stop_filter = lambda _: not self._running,
                )
            except Exception as exc:
                print(f"[SNIFFER ERROR] {exc}")
                time.sleep(2)   # brief pause before retry
