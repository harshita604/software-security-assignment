import os
import requests
import pytest

API_URL = "http://127.0.0.1:8000"
RESOURCE_URL = "http://127.0.0.1:8001"
PROCESSING_URL = "http://127.0.0.1:8002"


def login(username, password):
    r = requests.post(f"{API_URL}/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.json()["access_token"]

def test_admin_privileged_access():
    """Privileged action is allowed for admin and denied for ordinary users."""
    alice_token = login("alice", "alice123")
    admin_token = login("admin", "admin123")
    
    # Alice should be blocked (HTTP 403)
    res_alice = requests.get(f"{API_URL}/admin/audit-logs", headers={"Auth": f"Bearer {alice_token}"})
    assert res_alice.status_code == 403
    
    # Admin should succeed (HTTP 200)
    res_admin = requests.get(f"{API_URL}/admin/audit-logs", headers={"Auth": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200

def test_mitigated_cwe_862_authorization_enforced():
    """Complete Mediation: Alice cannot access Bob's dataset."""
    alice_token = login("alice", "alice123")
    res = requests.get(
        f"{RESOURCE_URL}/records/ds_bob_1", 
        headers={"Auth": f"Bearer {alice_token}"}
    )
    assert res.status_code == 403, "Security Violation: Unauthorized cross-tenant read allowed"
    print("\n[+] Gate 3: CWE-862 mitigated — Cross-tenant access blocked with HTTP 403")

def test_mitigated_cwe_22_path_traversal_blocked():
    """Processing Service rejects filenames containing directory traversal sequences."""
    payload = {
        "dataset_id": "ds_alice_1",
        "output_filename": "../traversal_attack.txt",
        "task_token": "dummy_token"
    }
    res = requests.post(f"{PROCESSING_URL}/job/export", json=payload)
    assert res.status_code == 400
    assert not os.path.exists("./traversal_attack.txt")
    print("\n[+] Gate 3: CWE-22 mitigated — Path traversal attempt rejected with HTTP 400")

def test_mitigated_cwe_918_ssrf_blocked():
    """Application API blocks requests targeting loopback or internal networks."""
    alice_token = login("alice", "alice123")
    res = requests.post(
        f"{API_URL}/datasets/import-remote", 
        json={"url": f"{RESOURCE_URL}/internal/status"},
        headers={"Auth": f"Bearer {alice_token}"}
    )
    assert res.status_code == 403
    print("\n[+] Gate 3: CWE-918 mitigated — Internal IP / Loopback SSRF blocked with HTTP 403")

def test_mitigated_composition_confused_deputy_blocked():
    """Alice cannot use the export pipeline to process Bob's dataset."""
    alice_token = login("alice", "alice123")
    res = requests.post(
        f"{API_URL}/datasets/ds_bob_1/export",
        json={"output_filename": "alice_export.md"},
        headers={"Auth": f"Bearer {alice_token}"}
    )
    assert res.status_code == 403
    print("\n[+] Gate 3: Composition flaw mitigated — Confused deputy blocked with HTTP 403")

def test_legitimate_flow_succeeds():
    """Confirms legitimate multi-tier functionality works end-to-end."""
    alice_token = login("alice", "alice123")
    res = requests.post(
        f"{API_URL}/datasets/ds_alice_1/export",
        json={"output_filename": "alice_valid_report.md"},
        headers={"Auth": f"Bearer {alice_token}"}
    )
    assert res.status_code == 200, res.text
    export_id = res.json()["export_id"]
    
    # Verify export artifact can be retrieved
    res_get = requests.get(f"{RESOURCE_URL}/exports/{export_id}")
    assert res_get.status_code == 200
    assert "Sensitive Biomarker A" in res_get.json()["content"]
    print("\n[+] Functional flow confirmed — Alice successfully exported her own data")

if __name__ == "__main__":
    test_admin_privileged_access()
    test_mitigated_cwe_862_authorization_enforced()
    test_mitigated_cwe_22_path_traversal_blocked()
    test_mitigated_cwe_918_ssrf_blocked()
    test_mitigated_composition_confused_deputy_blocked()
    test_legitimate_flow_succeeds()