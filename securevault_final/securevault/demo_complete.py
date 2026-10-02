# demo_complete.py — Lance tout en séquence avec pauses visuelles

import requests, time, hashlib

T = "http://localhost:5000/api/v1"

def sep(title):
    print(f"\n{'='*50}\n  {title}\n{'='*50}")

# ── 1. Brute Force ──
sep("1. BRUTE FORCE ATTACK")
for i in range(6):
    r = requests.post(f"{T}/auth/login", json={"username":"test","auth_hash":"a"*64})
    print(f"  Tentative {i+1} → {r.status_code} | {r.json().get('message','')[:50]}")
    time.sleep(0.5)

# ── 2. JWT invalides ──
sep("2. JWT MANIPULATION")
for tok in ["fake.jwt.here", "A"*100, "eyJhbGc.fake.sig"]:
    r = requests.get(f"{T}/vault/blob", headers={"Authorization": f"Bearer {tok}"})
    print(f"  Token={tok[:20]}... → {r.status_code}")

# ── 3. Rate limit flood ──
sep("3. RATE LIMIT FLOOD")
for i in range(35):
    r = requests.post(f"{T}/security/strength", json={"password":"test"})
    if r.status_code == 429:
        print(f"  BLOQUÉ au {i+1}ème appel ! retry_after={r.json().get('retry_after')}s")
        break

# ── 4. HIBP ──
sep("4. HIBP K-ANONYMAT")
for pwd in ["password", "123456", "SecureV@ult2024!"]:
    sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
    r = requests.post(f"{T}/security/hibp", json={"password": pwd})
    d = r.json()
    status = f"COMPROMIS {d['count']} fois" if d.get('pwned') else "CLEAN"
    print(f"  '{pwd}' | SHA1 prefix envoyé: {sha1[:5]} | {status}")

# ── 5. Connexions suspectes ──
sep("5. IP SPOOFING / GEO ANOMALIES")
for country, ua in [("MA","Mozilla/5.0"), ("RU","curl/7.68"), ("CN",""), ("KP","")]:
    r = requests.post(f"{T}/auth/login",
        json={"username":"test","auth_hash":"a"*64},
        headers={"CF-IPCountry": country, "User-Agent": ua}
    )
    risk = r.json().get("session_risk", {})
    print(f"  [{country}] UA={'✓' if ua else '✗'} → risk={risk.get('score',0)} reasons={risk.get('reasons',[])}")

print("\n✅ Démo terminée — Vérifie le dashboard SOC !")