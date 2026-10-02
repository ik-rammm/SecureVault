# hibp_demo.py
import requests
import hashlib

TARGET = "http://localhost:5000/api/v1"

passwords_to_test = [
    "password",      # dans HIBP — compromis des millions de fois
    "123456",        # idem
    "P@ssw0rd!2024", # probablement clean
    "correct-horse-battery-staple"  # passphrase forte
]

for pwd in passwords_to_test:
    # Ce que SecureVault envoie vraiment à HIBP (seulement 5 chars)
    sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
    prefix_sent = sha1[:5]

    resp = requests.post(f"{TARGET}/security/hibp", json={"password": pwd})
    result = resp.json()

    print(f"\n[HIBP] Password: '{pwd}'")
    print(f"  SHA-1 complet : {sha1}")
    print(f"  Envoyé à HIBP : {prefix_sent} (5 chars seulement — k-anonymat)")
    print(f"  Résultat       : {'⚠️ COMPROMIS ' + str(result.get('count')) + ' fois' if result.get('pwned') else '✅ Clean'}")