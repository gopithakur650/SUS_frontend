import subprocess
import time
import urllib.request
import urllib.error
import json
import os
import sys

def run_live_test():
    server_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print(f"--> Starting Uvicorn FastAPI server in {server_dir}...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=server_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        # Wait up to 10 seconds for server startup
        health_ok = False
        for attempt in range(15):
            time.sleep(1)
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=2) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode())
                        print("    [+] Health Check Succeeded:", data)
                        health_ok = True
                        break
            except Exception:
                continue

        if not health_ok:
            proc.terminate()
            stdout_data, stderr_data = proc.communicate(timeout=2)
            print("Uvicorn STDOUT:", stdout_data.decode(errors="ignore"))
            print("Uvicorn STDERR:", stderr_data.decode(errors="ignore"))
            raise RuntimeError("FastAPI server failed to respond to /api/health")

        # Now test POST /api/scan/upload using multipart/form-data (YAML)
        print("--> Testing live POST /api/scan/upload with multipart YAML...")
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        sample_path = os.path.join(server_dir, "sample_configs", "amf_vulnerable.yaml")
        with open(sample_path, "rb") as f:
            file_bytes = f.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="amf_vulnerable.yaml"\r\n'
            f"Content-Type: text/yaml\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/scan/upload",
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=5) as resp:
            print("    [+] Upload HTTP Status (YAML):", resp.status)
            res_json = json.loads(resp.read().decode())
            print("    [+] Scan Result Status:", res_json.get("status"))
            print("    [+] Summary:", res_json.get("summary"))
            assert res_json.get("status") == "success"
            assert res_json["summary"]["critical"] >= 1
            assert len(res_json["findings"]) >= 3

        # Test POST /api/scan/upload using JSON configuration
        print("--> Testing live POST /api/scan/upload with multipart JSON...")
        json_sample_path = os.path.join(server_dir, "sample_configs", "smf_sample.json")
        with open(json_sample_path, "rb") as f:
            json_file_bytes = f.read()

        json_body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="smf_sample.json"\r\n'
            f"Content-Type: application/json\r\n\r\n"
        ).encode("utf-8") + json_file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        json_req = urllib.request.Request(
            "http://127.0.0.1:8000/api/scan/upload",
            data=json_body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}"
            },
            method="POST"
        )

        with urllib.request.urlopen(json_req, timeout=5) as resp:
            print("    [+] Upload HTTP Status (JSON):", resp.status)
            json_res = json.loads(resp.read().decode())
            print("    [+] SMF Findings Count:", len(json_res.get("findings", [])))
            assert json_res.get("status") == "success"
            assert json_res.get("file_type") == "json"

        # Test GET /api/scan/history
        print("--> Testing live GET /api/scan/history...")
        with urllib.request.urlopen("http://127.0.0.1:8000/api/scan/history", timeout=5) as resp:
            hist_json = json.loads(resp.read().decode())
            print("    [+] History HTTP Status:", resp.status)
            print("    [+] Recorded Scans in DB:", hist_json.get("count"))
            assert hist_json.get("count") >= 1

        print("\n=======================================================")
        print("  FULL LIVE SUSIGNAL SERVER & UPLOAD VERIFICATION PASSED!")
        print("=======================================================")

    finally:
        print("--> Terminating Uvicorn subprocess...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    run_live_test()
