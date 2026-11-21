"""
Modular Security Rules Engine for 5G Core Network Functions (3GPP TS 33.501).

Each rule defines:
- rule_id: Unique rule identifier (e.g., 5GS-AMF-001)
- title: Short description of the misconfiguration
- target_nf: Applicable Network Function (AMF, SMF, UPF, NRF, AUSF, UDM, or ALL)
- severity: SeverityLevel (CRITICAL, HIGH, MEDIUM, LOW)
- category: Security domain (Encryption, Transport, Access Control, Hardening)
- description: Detailed risk explanation
- remediation: Prescriptive fix recommendation
- evaluator: Callable[[dict], bool] (Returns True if misconfiguration detected)
"""

from typing import List, Dict, Any, Callable, Optional
from .risk import SeverityLevel


class SecurityRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        target_nf: str,
        severity: SeverityLevel,
        category: str,
        description: str,
        remediation: str,
        evaluator: Callable[[Dict[str, Any]], bool]
    ):
        self.rule_id = rule_id
        self.title = title
        self.target_nf = target_nf
        self.severity = severity
        self.category = category
        self.description = description
        self.remediation = remediation
        self.evaluator = evaluator

    def check(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Executes rule against parsed config.
        Returns a finding dictionary if a misconfiguration is detected, else None.
        """
        try:
            is_violation = self.evaluator(config)
            if is_violation:
                return {
                    "rule_id": self.rule_id,
                    "title": self.title,
                    "target_nf": self.target_nf,
                    "severity": self.severity.value,
                    "category": self.category,
                    "description": self.description,
                    "remediation": self.remediation
                }
        except Exception:
            # Defensive execution: individual rule errors should not crash the entire scan
            return None
        return None


# Helper traversal functions for nested dicts
def _get_nested(d: Dict[str, Any], *keys, default=None):
    """
    Search for nested keys in dictionary.
    Also transparently searches within top-level NF blocks (e.g. d['amf']['sbi']).
    """
    def _find_in_dict(target: Dict[str, Any], path):
        cur = target
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                return default
        return cur

    # First attempt: search directly from root
    val = _find_in_dict(d, keys)
    if val is not default:
        return val

    # Second attempt: search within any top-level sub-dictionary (e.g. amf, smf, upf, configuration)
    for root_key, sub_dict in d.items():
        if isinstance(sub_dict, dict):
            val = _find_in_dict(sub_dict, keys)
            if val is not default:
                return val

    return default


# =====================================================================
# Rule Evaluator Functions
# =====================================================================

def _rule_null_encryption(config: Dict[str, Any]) -> bool:
    """Flag if NEA0 / null ciphering is prioritized as preferred or the only cipher."""
    ciphers = _get_nested(config, "security", "ciphering_order", default=[])
    if isinstance(ciphers, list) and len(ciphers) > 0:
        first_cipher = str(ciphers[0]).upper()
        if "NEA0" in first_cipher:
            return True
        if all("NEA0" in str(c).upper() for c in ciphers):
            return True
        return False

    config_str = str(config).lower()
    if "null_encryption: true" in config_str:
        return True
    return False


def _rule_null_integrity(config: Dict[str, Any]) -> bool:
    """Flag if NIA0 / null integrity is permitted or prioritized for NAS."""
    integ = _get_nested(config, "security", "integrity_order", default=[])
    if isinstance(integ, list) and len(integ) > 0:
        first_alg = str(integ[0]).upper()
        if "NIA0" in first_alg:
            return True
        if any("NIA0" in str(alg).upper() for alg in integ):
            return True
    return False


def _rule_plaintext_sbi(config: Dict[str, Any]) -> bool:
    """Flag if Service Based Interface (SBI) uses unencrypted HTTP/1.1 instead of HTTPS."""
    scheme = _get_nested(config, "sbi", "scheme", default="")
    tls = _get_nested(config, "sbi", "tls", default=None)
    
    if str(scheme).lower() == "http":
        return True
    if isinstance(tls, dict) and tls.get("enabled") is False:
        return True
    if tls is False or str(tls).lower() == "disabled":
        return True
    
    tls_root = _get_nested(config, "tls", "enabled", default=None)
    if tls_root is False:
        return True
        
    return False


def _rule_wildcard_bind(config: Dict[str, Any]) -> bool:
    """Flag if binding service endpoints directly to wildcard 0.0.0.0."""
    addresses_to_check = [
        _get_nested(config, "sbi", "addr"),
        _get_nested(config, "sbi", "server", "addr"),
        _get_nested(config, "bind_addr"),
        _get_nested(config, "ngap", "addr"),
        _get_nested(config, "ngap", "server", "addr"),
    ]
    for addr in addresses_to_check:
        if addr and str(addr).strip() == "0.0.0.0":
            return True
    return False


def _rule_missing_mtls_nrf(config: Dict[str, Any]) -> bool:
    """Flag if NRF mutual TLS client validation is explicitly disabled."""
    mtls = _get_nested(config, "nrf", "client_auth", default=None)
    if mtls is not None and (mtls is False or str(mtls).lower() in ["disabled", "none", "optional"]):
        return True
    return False


def _rule_deprecated_tls(config: Dict[str, Any]) -> bool:
    """Flag if TLS version is lower than TLS 1.2 (e.g. 1.0 or 1.1)."""
    min_ver = _get_nested(config, "sbi", "tls", "min_version") or _get_nested(config, "tls", "min_version")
    if min_ver:
        ver_str = str(min_ver).lower().replace("v", "").replace("tls", "").strip()
        if ver_str in ["1.0", "1.1", "1", "10", "11"]:
            return True
    return False


def _rule_snn_validation(config: Dict[str, Any]) -> bool:
    """Flag if AUSF Serving Network Name (SNN) strict validation is disabled."""
    snn = _get_nested(config, "strict_snn_validation", default=None)
    if snn is False or str(snn).lower() in ["false", "disabled", "no"]:
        return True
    return False


def _rule_oauth2_sbi(config: Dict[str, Any]) -> bool:
    """Flag if OAuth 2.0 authorization for SBI is disabled in NRF."""
    oauth2 = _get_nested(config, "sbi", "oauth2", default=None)
    if isinstance(oauth2, dict) and oauth2.get("enabled") is False:
        return True
    if oauth2 is False or str(oauth2).lower() in ["false", "disabled"]:
        return True
    oauth2_direct = _get_nested(config, "oauth2", "enabled", default=None)
    if oauth2_direct is False:
        return True
    return False


def _rule_unauthenticated_registration(config: Dict[str, Any]) -> bool:
    """Flag if unauthenticated NF registration is allowed in NRF."""
    allow_unauth = _get_nested(config, "registration", "allow_unauthenticated", default=None)
    verify_cert = _get_nested(config, "registration", "verify_cert_identity", default=None)
    if allow_unauth is True or str(allow_unauth).lower() == "true":
        return True
    if verify_cert is False or str(verify_cert).lower() == "false":
        return True
    return False


def _rule_suci_null_scheme(config: Dict[str, Any]) -> bool:
    """Flag if UDM permits SUCI Null-Scheme de-concealment."""
    allow_null = _get_nested(config, "suci", "allow_null_scheme", default=None)
    if allow_null is True or str(allow_null).lower() == "true":
        return True
    return False


def _rule_hardcoded_credentials(config: Dict[str, Any]) -> bool:
    """Flag if hardcoded/default plaintext credentials are found in database URI."""
    db_uri = _get_nested(config, "db_uri", default="")
    if not db_uri:
        db_uri = _get_nested(config, "database", "uri", default="")
    if db_uri:
        uri_lower = str(db_uri).lower()
        if "admin:admin" in uri_lower or "root:root" in uri_lower:
            return True
        if "@" in uri_lower and ":" in uri_lower.split("@")[0]:
            cred_part = uri_lower.split("@")[0]
            if not ("${" in cred_part or "$vault" in cred_part or "vault" in cred_part):
                return True
    return False


def _rule_weak_crypto_key(config: Dict[str, Any]) -> bool:
    """Flag if static, zero, or test cryptographic keys are used in UDM."""
    sample_key = _get_nested(config, "crypto", "sample_key", default="")
    if not sample_key:
        sample_key = _get_nested(config, "crypto", "key", default="")
    if sample_key:
        key_str = str(sample_key).strip().lower()
        if key_str in [
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "12345678901234567890123456789012",
            "test", "default"
        ] or set(key_str) == {"0"}:
            return True
    return False


def _rule_wildcard_pfcp_gtpu(config: Dict[str, Any]) -> bool:
    """Flag if PFCP or GTP-U interface is bound to wildcard 0.0.0.0."""
    pfcp_addr = _get_nested(config, "pfcp", "addr") or _get_nested(config, "pfcp", "server", "addr")
    gtpu_addr = _get_nested(config, "gtpu", "addr") or _get_nested(config, "gtpu", "server", "addr")
    for addr in [pfcp_addr, gtpu_addr]:
        if addr and str(addr).strip() == "0.0.0.0":
            return True
    return False


def _rule_disabled_ipsec(config: Dict[str, Any]) -> bool:
    """Flag if IPsec protection for control/user plane interface is explicitly disabled."""
    ipsec = _get_nested(config, "ipsec", "enabled", default=None)
    if ipsec is False or str(ipsec).lower() in ["false", "disabled"]:
        return True
    return False


def _rule_unauthenticated_metrics(config: Dict[str, Any]) -> bool:
    """Flag if metrics endpoint lacks authentication or binds to wildcard 0.0.0.0."""
    auth_req = _get_nested(config, "metrics", "auth_required", default=None)
    metrics_addr = _get_nested(config, "metrics", "addr", default="")
    if auth_req is False or str(auth_req).lower() == "false":
        return True
    if str(metrics_addr).strip() == "0.0.0.0" and auth_req is not True:
        return True
    return False


def _rule_unprotected_oam(config: Dict[str, Any]) -> bool:
    """Flag if OAM interface is exposed on wildcard 0.0.0.0 without TLS encryption."""
    oam_addr = _get_nested(config, "oam", "addr", default="")
    if str(oam_addr).strip() == "0.0.0.0":
        oam_tls = _get_nested(config, "oam", "tls", default=None)
        if oam_tls is None or oam_tls is False:
            return True
        if isinstance(oam_tls, dict) and oam_tls.get("enabled") is False:
            return True
    return False


# =====================================================================
# 3GPP Security Rule Registry
# =====================================================================

RULE_REGISTRY: List[SecurityRule] = [
    SecurityRule(
        rule_id="5GS-CRYP-001",
        title="Null Ciphering Enabled (NEA0)",
        target_nf="AMF",
        severity=SeverityLevel.CRITICAL,
        category="Cryptographic Protection",
        description="The AMF prioritizes NEA0 (null ciphering) as its preferred cipher or the only cipher, allowing non-emergency NAS traffic to be transmitted in plaintext without confidentiality protection (3GPP TS 33.501 Section 6.7).",
        remediation="Remove NEA0 from ciphering_order in the security block or ensure it is not prioritized above NEA1/NEA2/NEA3. Enforce NEA1 (128-EEA1/SNOW 3G), NEA2 (128-EEA2/AES), or NEA3 (128-EEA3/ZUC).",
        evaluator=_rule_null_encryption
    ),
    SecurityRule(
        rule_id="5GS-CRYP-005",
        title="Null Integrity Protection Enabled (NIA0)",
        target_nf="AMF",
        severity=SeverityLevel.CRITICAL,
        category="Cryptographic Protection",
        description="The AMF allows or prioritizes NIA0 (null integrity) for NAS signaling. 3GPP TS 33.501 Section 5.1.1 strictly mandates integrity protection for all normal NAS messages. NIA0 is only permitted for unauthenticated emergency sessions.",
        remediation="Remove NIA0 from the integrity_order configuration. Enforce NIA1 (128-EIA1), NIA2 (128-EIA2/AES-CMAC), or NIA3 (128-EIA3/ZUC).",
        evaluator=_rule_null_integrity
    ),
    SecurityRule(
        rule_id="5GS-SBI-002",
        title="Insecure HTTP Scheme on Service Based Interface",
        target_nf="ALL",
        severity=SeverityLevel.HIGH,
        category="Transport Security",
        description="Network Function SBI endpoints are configured with unencrypted 'http' scheme instead of 'https', exposing inter-NF API traffic to sniffing and MITM attacks (3GPP TS 33.501 Section 13.1).",
        remediation="Change sbi.scheme to 'https' and supply valid TLS server certificates, private keys, and trusted CA bundles.",
        evaluator=_rule_plaintext_sbi
    ),
    SecurityRule(
        rule_id="5GS-NET-003",
        title="Wildcard Service Address Binding (0.0.0.0)",
        target_nf="ALL",
        severity=SeverityLevel.MEDIUM,
        category="Network Hardening",
        description="The Network Function binds service listening interfaces to wildcard 0.0.0.0, potentially exposing control plane interfaces across unintended networks or management planes.",
        remediation="Bind service endpoints to specific dedicated internal network slice interfaces or isolated loopback addresses.",
        evaluator=_rule_wildcard_bind
    ),
    SecurityRule(
        rule_id="5GS-AUTH-004",
        title="Disabled Mutual TLS (mTLS) for NF Authentication",
        target_nf="NRF",
        severity=SeverityLevel.HIGH,
        category="Authentication & Access Control",
        description="Client certificate authentication is disabled on the NRF. Rogues or compromised Network Functions can register themselves without cryptographic proof of identity.",
        remediation="Set nrf.client_auth to 'required' and configure mutual TLS (mTLS) trust anchor verification.",
        evaluator=_rule_missing_mtls_nrf
    ),
    SecurityRule(
        rule_id="5GS-TLS-006",
        title="Insecure / Deprecated TLS Protocol Version",
        target_nf="ALL",
        severity=SeverityLevel.HIGH,
        category="Transport Security",
        description="TLS minimum protocol version is configured below TLS 1.2 (e.g. TLS 1.0 or 1.1). 3GPP TS 33.501 Section 13.1 mandates TLS 1.2 or TLS 1.3 with secure cipher suites for all SBI communications.",
        remediation="Set tls.min_version to '1.2' or '1.3' and disable deprecated SSLv3, TLS 1.0, and TLS 1.1 protocols.",
        evaluator=_rule_deprecated_tls
    ),
    SecurityRule(
        rule_id="5GS-AUTH-007",
        title="Disabled Serving Network Name (SNN) Validation",
        target_nf="AUSF",
        severity=SeverityLevel.HIGH,
        category="Authentication & Access Control",
        description="Strict Serving Network Name (SNN) validation is disabled in the AUSF. According to 3GPP TS 33.501 Section 6.1.3.2, the AUSF must verify that the serving network is authorized to serve the subscriber to prevent roaming fraud and false base station spoofing.",
        remediation="Set strict_snn_validation to true and maintain an explicit PLMN allowlist in the AUSF configuration.",
        evaluator=_rule_snn_validation
    ),
    SecurityRule(
        rule_id="5GS-AUTH-008",
        title="Disabled OAuth 2.0 Authorization for SBI",
        target_nf="NRF",
        severity=SeverityLevel.HIGH,
        category="Authentication & Access Control",
        description="OAuth 2.0 token-based authorization is disabled in the NRF. According to 3GPP TS 33.501 Section 13.4.1, the NRF must act as the authorization server issuing access tokens to enforce fine-grained inter-NF service access.",
        remediation="Set sbi.oauth2.enabled to true and enforce strict JWT token validation across all consumer NFs.",
        evaluator=_rule_oauth2_sbi
    ),
    SecurityRule(
        rule_id="5GS-REG-009",
        title="Unauthenticated Network Function Registration",
        target_nf="NRF",
        severity=SeverityLevel.CRITICAL,
        category="Authentication & Access Control",
        description="The NRF permits unauthenticated NF registration or disables certificate identity validation. An attacker can register rogue NFs, hijack subscriber sessions, and redirect control plane traffic (3GPP TS 33.501 Section 13.3).",
        remediation="Set registration.allow_unauthenticated to false and registration.verify_cert_identity to true with mTLS validation.",
        evaluator=_rule_unauthenticated_registration
    ),
    SecurityRule(
        rule_id="5GS-PRIV-010",
        title="SUCI Null-Scheme De-anonymization Enabled",
        target_nf="UDM",
        severity=SeverityLevel.CRITICAL,
        category="Subscriber Privacy",
        description="The UDM allows the SUCI Null-Scheme, permitting plaintext SUPI (IMSI) transmission across the radio and core interfaces. This completely eliminates 5G subscriber identity privacy and enables IMSI catcher / eavesdropping attacks (3GPP TS 33.501 Section 6.12).",
        remediation="Set suci.allow_null_scheme to false and enforce Profile A or Profile B public key encryption for SUCI de-concealment.",
        evaluator=_rule_suci_null_scheme
    ),
    SecurityRule(
        rule_id="5GS-CRED-011",
        title="Plaintext / Default Database Credentials in Configuration",
        target_nf="ALL",
        severity=SeverityLevel.HIGH,
        category="Credential Management",
        description="Default or hardcoded plaintext credentials (such as admin:admin) were detected in the database connection string. Storing credentials in configuration files exposes 5G subscriber subscription data to unauthorized inspection.",
        remediation="Store database credentials in environment variables or a secure vault (e.g. ${VAULT_DB_PASSWORD}) and enable TLS for database connections.",
        evaluator=_rule_hardcoded_credentials
    ),
    SecurityRule(
        rule_id="5GS-KEY-012",
        title="Insecure / Default Static Cryptographic Key",
        target_nf="UDM",
        severity=SeverityLevel.CRITICAL,
        category="Cryptographic Protection",
        description="A static, all-zero, or default cryptographic key was detected in the UDM configuration. Static keys allow attackers to forge 5G authentication vectors (RAND, AUTN, XRES*, K_AUSF) and compromise all subscriber sessions (3GPP TS 33.501 Section 6.1).",
        remediation="Integrate with a Hardware Security Module (HSM) or use cryptographically secure unique random keys for operator secret keys (K, OPc).",
        evaluator=_rule_weak_crypto_key
    ),
    SecurityRule(
        rule_id="5GS-NET-013",
        title="Wildcard Binding on Control / User Plane Interfaces (PFCP & GTP-U)",
        target_nf="ALL",
        severity=SeverityLevel.HIGH,
        category="Network Hardening",
        description="Packet Forwarding Control Protocol (PFCP - N4) or GTP-U (N3/N9 user plane) is bound to wildcard 0.0.0.0, exposing core routing endpoints to untrusted or external networks (3GPP TS 29.244 / TS 33.501 Section 9).",
        remediation="Bind PFCP and GTP-U listening sockets to dedicated, isolated internal network slice interfaces.",
        evaluator=_rule_wildcard_pfcp_gtpu
    ),
    SecurityRule(
        rule_id="5GS-ENC-014",
        title="Unencrypted Control / User Plane Interface (Disabled IPsec)",
        target_nf="ALL",
        severity=SeverityLevel.MEDIUM,
        category="Transport Security",
        description="IPsec encryption is explicitly disabled for the N3 or N4 interface. Where physical network layer security cannot be guaranteed, 3GPP TS 33.501 Section 9 recommends IPsec with ESP encryption to safeguard user data.",
        remediation="Enable IPsec with IKEv2 and ESP confidentiality and integrity protection across inter-NF interfaces.",
        evaluator=_rule_disabled_ipsec
    ),
    SecurityRule(
        rule_id="5GS-MON-015",
        title="Unauthenticated Operational Metrics Exposure",
        target_nf="ALL",
        severity=SeverityLevel.MEDIUM,
        category="Network Hardening",
        description="Operational metrics or Prometheus endpoints are exposed without authentication or bound to wildcard 0.0.0.0, leaking internal network function load, topology, and subscriber session metrics.",
        remediation="Enable authentication for metrics endpoints (auth_required: true) and bind them to isolated internal management networks.",
        evaluator=_rule_unauthenticated_metrics
    ),
    SecurityRule(
        rule_id="5GS-MGMT-016",
        title="Unencrypted OAM Interface Exposed on Wildcard Address",
        target_nf="ALL",
        severity=SeverityLevel.HIGH,
        category="Network Hardening",
        description="Operations, Administration, and Maintenance (OAM) management interface is bound to wildcard 0.0.0.0 without TLS encryption, exposing administrative controls to network sniffing and unauthorized tampering (3GPP TS 33.501 Section 13.1).",
        remediation="Bind OAM interface to localhost or an isolated management VLAN and enable TLS encryption.",
        evaluator=_rule_unprotected_oam
    )
]


def get_all_rules() -> List[SecurityRule]:
    """Retrieve all registered security rules."""
    return RULE_REGISTRY

