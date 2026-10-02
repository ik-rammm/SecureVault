# jwt_attack.py
import requests

TARGET = "http://localhost:5000/api/v1"

# Token complètement faux
fake_tokens = [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.fake_signature",  # algo HS256 au lieu de RS256
    "Bearer invalid.token.here",
    "eyJhbGciOiJSUzI1NiJ9." + "A" * 100 + ".fake",  # payload falsifié
    "expired_token_simulation"
]

for token in fake_tokens:
    resp = requests.get(
        f"{TARGET}/vault/blob",
        headers={"Authorization": f"Bearer {token}"}
    )
    print(f"[JWT ATTACK] token={token[:30]}... → {resp.status_code} | {resp.json()}")