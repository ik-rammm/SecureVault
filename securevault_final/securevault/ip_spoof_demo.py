# ip_spoof_demo.py
import requests

TARGET = "http://localhost:5000/api/v1"

# D'abord créer un compte de test
requests.post(f"{TARGET}/auth/register", json={
    "username": "victim_user",
    "auth_hash": "b" * 64,
    "salt_hex": "c" * 64,
    "kdf": "pbkdf2",
    "blob": ""
})

# Simuler des connexions depuis différents pays via le header CF-IPCountry
# (Cloudflare envoie ce header en production — Flask peut le lire)
fake_countries = [
    ("MA", "Mozilla/5.0 Windows"),   # Maroc — normal
    ("RU", "curl/7.68.0"),           # Russie — suspect
    ("CN", "python-requests/2.28"),  # Chine — suspect
    ("KP", ""),                      # Corée du Nord + pas de User-Agent = très suspect
]

for country, ua in fake_countries:
    headers = {
        "CF-IPCountry": country,
        "User-Agent": ua,
        "X-Forwarded-For": f"1.2.3.{hash(country) % 200}"
    }
    resp = requests.post(
        f"{TARGET}/auth/login",
        json={"username": "victim_user", "auth_hash": "b" * 64},
        headers=headers
    )
    print(f"[{country}] UA='{ua[:20]}' → {resp.status_code} | {resp.json()}")