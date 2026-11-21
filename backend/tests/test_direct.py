import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanner.parser import parse_configuration
from app.scanner.analyzer import analyze_configuration
from app.scanner.rules import get_all_rules
from app.scanner.risk import SeverityLevel
from app.database.db import init_db, save_scan_record, get_recent_scans

def run():
    print("1. Initializing DB...")
    init_db()

    print("2. Parsing vulnerable AMF YAML...")
    sample_path = os.path.join(os.path.dirname(__file__), "..", "sample_configs", "amf_vulnerable.yaml")
    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()

    cfg = parse_configuration(content, "amf_vulnerable.yaml")
    assert isinstance(cfg, dict)
    print("   Parsed successfully! Top keys:", list(cfg.keys()))

    print("3. Analyzing with rule engine...")
    res = analyze_configuration(cfg, "amf_vulnerable.yaml")
    summary = res["summary"]
    findings = res["findings"]
    print("   Summary:", summary)
    print("   Findings count:", len(findings))
    assert summary["critical"] >= 1
    assert summary["total_findings"] >= 3

    print("4. Testing Hardened AMF YAML...")
    hardened_path = os.path.join(os.path.dirname(__file__), "..", "sample_configs", "amf_hardened.yaml")
    with open(hardened_path, "r", encoding="utf-8") as f:
        hardened_content = f.read()
    h_cfg = parse_configuration(hardened_content, "amf_hardened.yaml")
    h_res = analyze_configuration(h_cfg, "amf_hardened.yaml")
    print("   Hardened Summary:", h_res["summary"])

    print("5. Testing SMF JSON...")
    smf_path = os.path.join(os.path.dirname(__file__), "..", "sample_configs", "smf_sample.json")
    with open(smf_path, "r", encoding="utf-8") as f:
        smf_content = f.read()
    smf_cfg = parse_configuration(smf_content, "smf_sample.json")
    smf_res = analyze_configuration(smf_cfg, "smf_sample.json")
    print("   SMF JSON Summary:", smf_res["summary"])

    print("6. Saving to SQLite DB...")
    save_scan_record(
        scan_id="test-scan-001",
        filename="amf_vulnerable.yaml",
        file_type="yaml",
        summary=summary,
        findings=findings
    )

    recent = get_recent_scans(limit=5)
    print("   Recent scans in DB:", len(recent))
    assert len(recent) >= 1

    print("\n>>> ALL DIRECT MODULE TESTS COMPLETED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run()
