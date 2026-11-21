"""
WFX Phantom Detector - GitHub Webhook Receiver
Real-time detection of wfx-loot campaign probes and payloads.
"""
from .detector import WFXDetector
from .server import create_app

__version__ = "1.0.0"
__all__ = ["WFXDetector", "create_app"]
