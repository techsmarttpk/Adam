import httpx
import time
import threading
import uvicorn
import os

from adam.api.main import app

def run_server():
    os.environ["SYSMON_PATH"] = "dummy_sysmon.evtx"
    os.environ["PROCMON_PATH"] = "dummy_procmon.csv"
    os.environ["NETWORK_PATH"] = "dummy_network.ek"
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="error")

def wait_for_completion(session_id):
    while True:
        resp = httpx.get(f"http://127.0.0.1:8001/sessions/{session_id}")
        data = resp.json()
        status = data.get("metadata", {}).get("status")
        if status in ["COMPLETED", "FAILED", "ABORTED", "PARTIAL"]:
            return data
        time.sleep(1)

def run_test():
    print("Starting API server...")
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(3)
    
    file1_content = b"MALWARE_A_CONTENT_HASH_SEED_1"
    file2_content = b"MALWARE_B_CONTENT_HASH_SEED_2"
    
    print("\n--- Test 1: Uploading File A ---")
    resp1 = httpx.post("http://127.0.0.1:8001/sessions/simulate", files={"file": ("fileA.exe", file1_content)})
    sess1 = resp1.json()["session_id"]
    print(f"Session 1: {sess1}")
    data1 = wait_for_completion(sess1)
    m1 = data1["metadata"]["metrics"]
    print(f"Events: {m1['semantic_events']}, Decisions: {m1['decisions_total']}, Executed: {m1['decisions_executed']}, Mutations: {m1['mutations_applied']}")
    
    print("\n--- Test 2: Uploading File A (Again) ---")
    resp2 = httpx.post("http://127.0.0.1:8001/sessions/simulate", files={"file": ("fileA.exe", file1_content)})
    sess2 = resp2.json()["session_id"]
    print(f"Session 2: {sess2}")
    data2 = wait_for_completion(sess2)
    m2 = data2["metadata"]["metrics"]
    print(f"Events: {m2['semantic_events']}, Decisions: {m2['decisions_total']}, Executed: {m2['decisions_executed']}, Mutations: {m2['mutations_applied']}")
    
    print("\n--- Test 3: Uploading File B (Different File) ---")
    resp3 = httpx.post("http://127.0.0.1:8001/sessions/simulate", files={"file": ("fileB.exe", file2_content)})
    sess3 = resp3.json()["session_id"]
    print(f"Session 3: {sess3}")
    data3 = wait_for_completion(sess3)
    m3 = data3["metadata"]["metrics"]
    print(f"Events: {m3['semantic_events']}, Decisions: {m3['decisions_total']}, Executed: {m3['decisions_executed']}, Mutations: {m3['mutations_applied']}")
    
    print("\n--- Determinism Verification ---")
    if m1 == m2:
        print("PASS: Session 1 and 2 (same file) have IDENTICAL metrics.")
    else:
        print("FAIL: Session 1 and 2 differ!")
        
    if m1 != m3:
        print("PASS: Session 1 and 3 (different files) have DIFFERENT metrics.")
    else:
        print("FAIL: Session 1 and 3 have identical metrics!")

if __name__ == "__main__":
    run_test()
