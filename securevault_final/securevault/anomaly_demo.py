# anomaly_demo.py
import requests
import time

TARGET = "http://localhost:5000/api/v1"

# 1. Créer un compte
requests.post(f"{TARGET}/auth/register", json={
    "username": "alice",
    "auth_hash": "d" * 64,
    "salt_hex": "e" * 64,
    "kdf": "pbkdf2",
    "blob": ""
})

# 2. Simuler 10 connexions normales (heure de bureau, Maroc)
# Ces connexions alimentent le modèle Isolation Forest
print("Simulation de 10 connexions normales (Maroc, heures bureau)...")
for i in range(10):
    requests.post(f"{TARGET}/auth/login",
        json={"username": "alice", "auth_hash": "d" * 64},
        headers={"CF-IPCountry": "MA", "User-Agent": "Mozilla/5.0"}
    )
    time.sleep(0.1)

# 3. Connexion anormale : 3h du matin, Russie, pas de User-Agent
print("\nConnexion ANORMALE (Russie, 3h du matin, no UA)...")
resp = requests.post(f"{TARGET}/auth/login",
    json={"username": "alice", "auth_hash": "d" * 64},
    headers={"CF-IPCountry": "RU", "User-Agent": ""}
)
result = resp.json()
print(f"Session risk : {result.get('session_risk')}")

# 4. Appel direct à l'API anomalie avec features simulées
# (simule une connexion à 3h du matin)
token = result.get("token", "")
anomaly_resp = requests.post(f"{TARGET}/ai/anomaly",
    json={"hour": 3, "dow": 6, "country": "RU", "ua_hash": 0},
    headers={"Authorization": f"Bearer {token}"}
)
print(f"\nIA Anomalie : {anomaly_resp.json()}")