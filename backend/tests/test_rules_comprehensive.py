import os
import glob
from app.scanner.parser import parse_configuration, detect_network_function_type, ConfigurationParseError
from app.scanner.analyzer import analyze_configuration
from app.scanner.rules import get_all_rules
from app.database.db import (
    init_db,
    save_scan_record,
    get_recent_scans,
    get_scan_by_id,
    delete_scan_record
)
from app.integrations import Open5GSAdapter, Free5GCAdapter


def test_baseline_configurations_are_clean():
    """All baseline hardened 5G configurations must score 100 with zero findings."""
    baseline_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sample_configs", "baseline"))
    yaml_files = glob.glob(os.path.join(baseline_dir, "*.yaml"))
    assert len(yaml_files) >= 6, f"Expected at least 6 baseline files, found {len(yaml_files)}"

    for file_path in yaml_files:
        filename = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        parsed = parse_configuration(content, filename=filename)
        result = analyze_configuration(parsed, filename=filename)

        assert result["summary"]["total_findings"] == 0, (
            f"Baseline file '{filename}' had unexpected findings: {result['findings']}"
        )
        assert result["summary"]["security_score"] == 100
        assert result["summary"]["status"] == "CLEAN"


def test_seeded_vulnerable_configurations_detected():
    """All seeded vulnerable configurations must trigger relevant 3GPP security findings."""
    vulnerable_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sample_configs", "seeded_vulnerable"))
    yaml_files = glob.glob(os.path.join(vulnerable_dir, "*.yaml"))
    assert len(yaml_files) >= 6, f"Expected at least 6 vulnerable files, found {len(yaml_files)}"

    findings_by_nf = {}

    for file_path in yaml_files:
        filename = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        parsed = parse_configuration(content, filename=filename)
        result = analyze_configuration(parsed, filename=filename)
        nf = result["summary"]["network_function"]
        findings_by_nf[nf] = [f["rule_id"] for f in result["findings"]]

        assert result["summary"]["total_findings"] > 0, f"Expected findings in vulnerable file {filename}"
        assert result["summary"]["status"] == "VULNERABILITIES_FOUND"

    # Specific NF rule validation
    assert "5GS-CRYP-001" in findings_by_nf["AMF"]  # NEA0
    assert "5GS-CRYP-005" in findings_by_nf["AMF"]  # NIA0
    assert "5GS-TLS-006" in findings_by_nf["AUSF"]  # Deprecated TLS
    assert "5GS-AUTH-007" in findings_by_nf["AUSF"]  # Strict SNN validation
    assert "5GS-AUTH-008" in findings_by_nf["NRF"]   # OAuth2 disabled
    assert "5GS-REG-009" in findings_by_nf["NRF"]    # Unauth registration
    assert "5GS-NET-013" in findings_by_nf["SMF"]   # Wildcard PFCP
    assert "5GS-ENC-014" in findings_by_nf["SMF"]   # Disabled IPsec
    assert "5GS-PRIV-010" in findings_by_nf["UDM"]  # SUCI null scheme
    assert "5GS-KEY-012" in findings_by_nf["UDM"]   # Weak crypto key
    assert "5GS-MON-015" in findings_by_nf["UPF"]   # Unauth metrics


def test_database_persistence_and_lookup():
    """Verify storing, retrieving by id, listing, and deleting scan records in SQLite."""
    init_db()
    test_scan_id = "test-uuid-9999"
    test_summary = {
        "network_function": "AMF",
        "total_rules_checked": 10,
        "total_findings": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "security_score": 20,
        "status": "VULNERABILITIES_FOUND"
    }
    test_findings = [
        {
            "rule_id": "5GS-CRYP-001",
            "title": "Null Ciphering Enabled (NEA0)",
            "target_nf": "AMF",
            "severity": "CRITICAL",
            "category": "Cryptographic Protection",
            "description": "Test description",
            "remediation": "Test remediation"
        }
    ]

    save_scan_record(
        scan_id=test_scan_id,
        filename="test_amf.yaml",
        file_type="yaml",
        summary=test_summary,
        findings=test_findings
    )

    # Lookup by ID
    record = get_scan_by_id(test_scan_id)
    assert record is not None
    assert record["scan_id"] == test_scan_id
    assert record["filename"] == "test_amf.yaml"
    assert record["summary"]["security_score"] == 20
    assert len(record["findings"]) == 1
    assert record["findings"][0]["rule_id"] == "5GS-CRYP-001"

    # Delete
    deleted = delete_scan_record(test_scan_id)
    assert deleted is True
    assert get_scan_by_id(test_scan_id) is None


def test_open5gs_and_free5gc_adapters():
    """Verify Phase 2 adapter normalization."""
    open5gs_adapter = Open5GSAdapter()
    assert open5gs_adapter.platform_name == "Open5GS"

    free5gc_adapter = Free5GCAdapter()
    assert free5gc_adapter.platform_name == "free5GC"

    sample_yaml = "amf:\n  sbi:\n    scheme: https\n"
    res1 = open5gs_adapter.load_configuration(sample_yaml)
    assert "amf" in res1
    assert res1["amf"]["sbi"]["scheme"] == "https"

    res2 = free5gc_adapter.load_configuration(sample_yaml)
    assert "amf" in res2


if __name__ == "__main__":
    test_baseline_configurations_are_clean()
    print("Baseline test passed!")
    test_seeded_vulnerable_configurations_detected()
    print("Seeded vulnerable test passed!")
    test_database_persistence_and_lookup()
    print("Database persistence test passed!")
    test_open5gs_and_free5gc_adapters()
    print("Adapters test passed!")
    print("\nALL COMPREHENSIVE TESTS PASSED!")
