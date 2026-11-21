import json
import yaml
from typing import Dict, Any, Tuple, Optional


class ConfigurationParseError(Exception):
    """Raised when configuration content cannot be parsed as valid YAML or JSON."""
    pass


def parse_configuration(raw_content: str, filename: str = "") -> Dict[str, Any]:
    """
    Parses configuration string into a Python dictionary.
    Supports both YAML (.yaml, .yml) and JSON (.json).
    
    Raises:
        ConfigurationParseError: If syntax is invalid, empty, or not a mapping/object.
    """
    if not raw_content or not raw_content.strip():
        raise ConfigurationParseError("Configuration file is empty.")

    lower_name = filename.lower()
    parsed_data = None
    parse_errors = []

    # If filename hints at JSON, or starts with '{', attempt JSON first
    if lower_name.endswith(".json"):
        try:
            parsed_data = json.loads(raw_content)
        except Exception as e:
            parse_errors.append(f"JSON error: {str(e)}")

    # Otherwise (or if JSON failed), attempt YAML parser (YAML is a superset of JSON)
    if parsed_data is None:
        try:
            parsed_data = yaml.safe_load(raw_content)
        except yaml.YAMLError as e:
            parse_errors.append(f"YAML error: {str(e)}")

    # Fallback to JSON if not yet attempted
    if parsed_data is None and not lower_name.endswith(".json"):
        try:
            parsed_data = json.loads(raw_content)
        except Exception as e:
            parse_errors.append(f"JSON error: {str(e)}")

    if parsed_data is None:
        err_detail = " | ".join(parse_errors) if parse_errors else "Unrecognized format"
        raise ConfigurationParseError(f"Failed to parse file as valid YAML or JSON: {err_detail}")

    if not isinstance(parsed_data, dict):
        raise ConfigurationParseError(
            f"Configuration root must be a key-value mapping (dictionary or JSON object), got {type(parsed_data).__name__}."
        )

    return parsed_data


def detect_network_function_type(data: Dict[str, Any], filename: str = "") -> str:
    """
    Heuristically identifies which 5G Network Function (AMF, SMF, UPF, etc.)
    the configuration represents based on filename and top-level key signatures.
    """
    fname = filename.lower()
    
    # 1. Filename matching
    for nf in ["amf", "smf", "upf", "nrf", "ausf", "udm"]:
        if nf in fname:
            return nf.upper()

    # 2. Check top-level dictionary keys
    data_keys_lower = [str(k).lower() for k in data.keys()]
    for nf in ["amf", "smf", "upf", "nrf", "ausf", "udm"]:
        if nf in data_keys_lower:
            return nf.upper()

    # 3. Subkey and signature heuristics
    keys_str = " ".join(data_keys_lower)
    if "amf" in keys_str or "guami" in keys_str or "tai" in keys_str:
        return "AMF"
    if "smf" in keys_str or "dnn" in keys_str:
        return "SMF"
    if "upf" in keys_str or "gtpu" in keys_str or "pfcp" in keys_str:
        return "UPF"
    if "nrf" in keys_str or "discovery" in keys_str:
        return "NRF"
    if "ausf" in keys_str or "strict_snn_validation" in keys_str:
        return "AUSF"
    if "udm" in keys_str or "subscription" in keys_str or "suci" in keys_str:
        return "UDM"

    return "GENERIC_NF"
