# rate_limit_flood.py
import requests
import time

TARGET = "http://localhost:5000/api/v1"

print("Flooding /security/strength (limite : 60 req/min)...")
for i in range(70):
    resp = requests.post(f"{TARGET}/security/strength", json={"password": "test123"})
    if resp.status_code == 429:
        print(f"[{i}] RATE LIMITED ! retry_after={resp.json().get('retry_after')}s")
        break
    else:
        print(f"[{i}] OK → score={resp.json().get('score')}")
    time.sleep(0.05)