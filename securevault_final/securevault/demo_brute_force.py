# demo_brute_force.py
# Place ce fichier dans : securevault_final/securevault/
# Lance avec : python demo_brute_force.py

import requests
import time

TARGET = "http://localhost:5000/api/v1"
USERNAME = "testuser123"  # le compte que tu as créé sur le site

print("=" * 50)
print("  DÉMO BRUTE FORCE — SecureVault SOC")
print("=" * 50)
print(f"\nCible : {USERNAME}")
print("Ouvre le dashboard SOC sur http://localhost:5000 pour voir les alertes en temps réel\n")
time.sleep(2)

# Liste de mots de passe que l'attaquant essaie
mots_de_passe_testes = [
    "password",
    "123456",
    "admin123",
    "letmein",
    "qwerty",
    "iloveyou",
    "monkey",   # ceci va déclencher le RATE_LIMIT / BRUTE_FORCE
]

for i, pwd in enumerate(mots_de_passe_testes, 1):
    print(f"[Tentative {i}] Essai du mot de passe : '{pwd}'")

    # Étape 1 : récupérer le sel (comme le ferait un vrai attaquant)
    salt_resp = requests.get(f"{TARGET}/auth/salt", params={"username": USERNAME})
    print(f"  → Sel récupéré : {salt_resp.json().get('salt', '')[:20]}...")

    # Étape 2 : envoyer un faux auth_hash (64 caractères hex)
    # Un vrai attaquant ne connaît pas K_auth donc il envoie n'importe quoi
    fake_hash = "a" * 64

    resp = requests.post(f"{TARGET}/auth/login", json={
        "username": USERNAME,
        "auth_hash": fake_hash
    })

    status = resp.status_code
    body = resp.json()

    if status == 401:
        print(f"  → ÉCHEC ({status}) : {body.get('message', '')}")
    elif status == 429:
        print(f"  → BLOQUÉ ! Rate limit atteint ({status})")
        print(f"  → retry_after = {body.get('retry_after')} secondes")
        print(f"\n  *** BRUTE FORCE DÉTECTÉ — Vérifie le dashboard SOC ! ***")
        break
    else:
        print(f"  → {status} : {body}")

    time.sleep(0.8)  # petite pause entre chaque tentative

print("\n" + "=" * 50)
print("  Fin de la démo — Regarde le dashboard SOC")
print("  Tu dois voir : LOGIN_FAIL x N + RATE_LIMIT")
print("=" * 50)