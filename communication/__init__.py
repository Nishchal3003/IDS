"""
communication/__init__.py
-------------------------
Public API surface for the communication package.

Import only the symbols that external modules (dashboard, capture, etc.)
genuinely need.  Internal helpers stay private.
"""

from communication.client_core import NIDSClient
from communication.constants import MsgType
from communication.logger import get_logger
from communication.protocol import Frame, build_frame, build_text_frame, recv_frame
from communication.server_core import NIDSServer
from communication.utils import get_local_ip, safe_send

__all__ = [
    "NIDSServer",
    "NIDSClient",
    "Frame",
    "MsgType",
    "build_frame",
    "build_text_frame",
    "recv_frame",
    "get_local_ip",
    "safe_send",
    "get_logger",
]
