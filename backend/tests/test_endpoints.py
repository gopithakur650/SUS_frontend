import io
import asyncio
from fastapi import UploadFile
from app.routes.scanner import upload_and_scan_configuration, list_recent_scans
from app.main import health_check
from app.database.db import init_db


async def run_tests():
    print("--> Initializing SQLite Database...")
    init_db()

    print("--> Testing GET /api/health...")
    health = await health_check()
    print("    Health Response:", health)
    assert health["status"] == "healthy"
    assert health["modules"]["scanner"] == "online"

    print("--> Testing POST /api/scan/upload with Vulnerable AMF YAML...")
    with open("sample_configs/amf_vulnerable.yaml", "rb") as f:
        content = f.read()
    file_obj = UploadFile(filename="amf_vulnerable.yaml", file=io.BytesIO(content))
    vuln_res = await upload_and_scan_configuration(file=file_obj)
    print("    Summary:", vuln_res["summary"])
    assert vuln_res["status"] == "success"
    assert vuln_res["summary"]["critical"] > 0
    assert len(vuln_res["findings"]) > 0

    print("--> Testing POST /api/scan/upload with Hardened AMF YAML...")
    with open("sample_configs/amf_hardened.yaml", "rb") as f:
        content = f.read()
    file_obj = UploadFile(filename="amf_hardened.yaml", file=io.BytesIO(content))
    hardened_res = await upload_and_scan_configuration(file=file_obj)
    print("    Summary:", hardened_res["summary"])
    assert hardened_res["status"] == "success"

    print("--> Testing POST /api/scan/upload with SMF JSON...")
    with open("sample_configs/smf_sample.json", "rb") as f:
        content = f.read()
    file_obj = UploadFile(filename="smf_sample.json", file=io.BytesIO(content))
    smf_res = await upload_and_scan_configuration(file=file_obj)
    print("    Summary:", smf_res["summary"])
    assert smf_res["status"] == "success"
    assert smf_res["file_type"] == "json"

    print("--> Testing GET /api/scan/history...")
    history = await list_recent_scans()
    print(f"    Total scans recorded in SQLite: {history['count']}")
    assert history["count"] >= 3

    print("\n=======================================================")
    print("    ALL SUSIGNAL API & MODULE TESTS PASSED (100%)")
    print("=======================================================")


if __name__ == "__main__":
    asyncio.run(run_tests())
