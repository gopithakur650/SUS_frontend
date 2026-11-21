from enum import Enum
from typing import Dict, Any


class SeverityLevel(str, Enum):
    """
    Standard severity classifications for 5G misconfiguration findings.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Metadata mapping to help frontend and reports format risk consistently
SEVERITY_METADATA: Dict[SeverityLevel, Dict[str, Any]] = {
    SeverityLevel.CRITICAL: {
        "weight": 10,
        "color": "#ef4444",      # Tailwind red-500
        "badge_bg": "rgba(239, 68, 68, 0.15)",
        "description": "Immediate threat: allows full network function takeover, eavesdropping, or subscriber impersonation."
    },
    SeverityLevel.HIGH: {
        "weight": 7,
        "color": "#f97316",      # Tailwind orange-500
        "badge_bg": "rgba(249, 115, 22, 0.15)",
        "description": "Severe vulnerability: weak crypto, unauthorized NF registration, or missing authentication checks."
    },
    SeverityLevel.MEDIUM: {
        "weight": 4,
        "color": "#eab308",      # Tailwind yellow-500
        "badge_bg": "rgba(234, 179, 8, 0.15)",
        "description": "Moderate issue: permissive timeouts, non-standard port exposures, or incomplete logging."
    },
    SeverityLevel.LOW: {
        "weight": 1,
        "color": "#06b6d4",      # Tailwind cyan-500
        "badge_bg": "rgba(6, 182, 212, 0.15)",
        "description": "Minor hardening issue: informational deviation from 3GPP security best practice guidelines."
    }
}


def get_severity_weight(severity: str) -> int:
    """Returns numerical weight for sorting and computing risk posture score."""
    try:
        level = SeverityLevel(severity.upper())
        return SEVERITY_METADATA[level]["weight"]
    except (ValueError, KeyError):
        return 0
