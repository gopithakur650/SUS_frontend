"""
5G Core Integrations Module (Future Extension Point).

This module is reserved for direct integrations with real 5G Core implementations:
1. Open5GS (https://open5gs.org/)
2. free5GC (https://free5gc.org/)

Architectural Design:
--------------------
Future integrations should implement adapters conforming to the base configuration
import pipeline without altering the core Scanner, Analyzer, or Rules modules.

Planned pipeline workflow:
  [Open5GS Config Importer / free5GC Config Importer / Manual File Upload]
                                |
                                v
                [Standardized Config Dict Pipeline]
                                |
                                v
                       [SUSignal Analyzer]

Current Status: Stub reserved for Phase 2 integration. No dependencies or deployments required.
"""

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class Base5GCoreAdapter(ABC):
    """
    Abstract adapter interface for importing and normalizing 5G Core configuration
    files from specific distributions (Open5GS, free5GC, etc.) into the SUSignal scanner.
    """

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Name of the 5G Core platform (e.g. 'Open5GS', 'free5GC')."""
        pass

    @abstractmethod
    def load_configuration(self, source_path_or_data: Any) -> Dict[str, Any]:
        """
        Normalize platform-specific configs into standard dictionary format
        suitable for scanner.analyzer.analyze_configuration.
        """
        pass


class Open5GSAdapter(Base5GCoreAdapter):
    """
    Adapter for Open5GS YAML configuration files (e.g., /etc/open5gs/*.yaml).
    Parses Open5GS configuration files and formats them into the standard dictionary schema.
    """

    @property
    def platform_name(self) -> str:
        return "Open5GS"

    def load_configuration(self, source_path_or_data: Any) -> Dict[str, Any]:
        from ..scanner.parser import parse_configuration
        import os

        if isinstance(source_path_or_data, str) and os.path.exists(source_path_or_data):
            with open(source_path_or_data, "r", encoding="utf-8") as f:
                content = f.read()
            return parse_configuration(content, filename=os.path.basename(source_path_or_data))
        elif isinstance(source_path_or_data, str):
            return parse_configuration(source_path_or_data, filename="open5gs_config.yaml")
        elif isinstance(source_path_or_data, dict):
            return source_path_or_data
        else:
            raise ValueError(f"Unsupported source format for Open5GS adapter: {type(source_path_or_data)}")


class Free5GCAdapter(Base5GCoreAdapter):
    """
    Adapter for free5GC YAML configuration files or Kubernetes ConfigMaps.
    Parses free5GC configuration structure and normalizes into the standard dictionary schema.
    """

    @property
    def platform_name(self) -> str:
        return "free5GC"

    def load_configuration(self, source_path_or_data: Any) -> Dict[str, Any]:
        from ..scanner.parser import parse_configuration
        import os

        if isinstance(source_path_or_data, str) and os.path.exists(source_path_or_data):
            with open(source_path_or_data, "r", encoding="utf-8") as f:
                content = f.read()
            return parse_configuration(content, filename=os.path.basename(source_path_or_data))
        elif isinstance(source_path_or_data, str):
            return parse_configuration(source_path_or_data, filename="free5gc_config.yaml")
        elif isinstance(source_path_or_data, dict):
            return source_path_or_data
        else:
            raise ValueError(f"Unsupported source format for free5GC adapter: {type(source_path_or_data)}")
