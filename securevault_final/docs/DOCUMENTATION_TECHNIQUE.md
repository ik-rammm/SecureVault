# Documentation technique — SecureVault v3

## 1. Vue d'ensemble

SecureVault est un gestionnaire de mots de passe **Zero-Knowledge** : toute la cryptographie
sensible s'exécute dans le navigateur. Le serveur Flask agit en **orchestrateur aveugle** : il
authentifie via une preuve SHA-256, stocke des **blobs opaques** et journalise les événements de
sécurité pour une **console SOC** intégrée.

- **Backend :** Python 3 / Flask + Flask-SocketIO, SQLite (WAL).
- **Frontend :** SPA JavaScript vanilla + WebCrypto (aucun framework, aucune dépendance CDN runtime).
- **IA :** scikit-learn (Isolation Forest) pour la détection d'anomalies de connexion + scoring ML.

## 2. Flux cryptographique (Zero-Knowledge)

### Inscription (UC-01/02)
1. `salt = CSPRNG(32 octets)` (`crypto.js : randomSalt`).
2. `bits = KDF(masterPassword, salt)` → 512 bits (PBKDF2-SHA256 600k, ou Argon2id si WASM).
3. `K_enc = bits[0:32]` (reste en RAM), `K_auth = bits[32:64]`.
4. `Auth_Hash = SHA-256(K_auth)`.
5. `blob = AES-256-GCM(coffre_vide, K_enc)`.
6. `POST /auth/register {username, salt_hex, auth_hash, kdf, blob}`.

### Connexion (UC-02)
1. `GET /auth/salt?username` → `{salt, kdf}` (sel HMAC déterministe si inconnu).
2. Dérivation locale identique → `Auth_Hash`.
3. `POST /auth/login {username, auth_hash}` → comparaison **temps constant** → **JWT RS256**.
4. `GET /vault/blob` → déchiffrement local avec `K_enc`.

### Opérations coffre (UC-03)
- Le client modifie le coffre en RAM, ré-chiffre (`encryptBlob`) et fait `PUT /vault/blob`.
- En cas de mauvaise clé, le **tag AEAD** échoue → exception bloquante (intégrité garantie).

### Format du blob
`base64( version(1) || IV(12) || ciphertext+tag )` — AES-256-GCM, IV 96 bits.

## 3. Modèle de données (conforme UML §2.3)

| Table | Entité UML | Colonnes clés |
|---|---|---|
| `users` | Utilisateur | `auth_hash` (=master_password_hash), `salt_hex`, `kdf`, `created_at`, `last_login` |
| `vaults` | EntreeCoffreFort (composition 1→0..*, `ON DELETE CASCADE`) | `encrypted_blob`, `updated_at` |
| `security_events` | JournalAudit | `event_type`, `detail`, `ip_hash`, `risk_score` (=score_risque_ia), `ts` |

> Le coffre est persisté en **blob unique** (déjà présent dans le code initial) : ce choix est
> compatible ZK (le serveur ne distingue pas les entrées). La composition CASCADE est préservée.

## 4. Sécurité

- **JWT RS256** (`app/jwt_keys.py`) : paire RSA 2048 auto-générée, clé privée `chmod 600`.
- **CSP nonce-based stricte** (`app/security.py`) : pas de `unsafe-inline`, `frame-ancestors 'none'`,
  `base-uri`/`form-action 'self'`. En-têtes : HSTS, X-Frame-Options DENY, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, COOP/CORP.
- **Rate limiting** glissant par IP (login/register/salt/generate/blob) + **lockout** 5 essais/5 min.
- **Anti-énumération** : sel pseudo-déterministe + timing uniforme.
- **HIBP k-anonymat** côté client : seul un préfixe SHA-1 (5 hex) est requêté.
- **Vie privée des logs** : IP hachée (SHA-256 tronqué), jamais de secret journalisé.
- **Blacklist JWT** : Redis si disponible, sinon repli mémoire (logout/refresh).

## 5. SQLCipher (production, défense en profondeur)

Les données étant déjà chiffrées côté client, le fichier `.db` ne contient que des blobs opaques.
En production, SQLCipher peut chiffrer l'intégralité du fichier :

```sql
PRAGMA key = '<SQLCIPHER_KEY>';
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 256000;          -- AES-256-CBC, conforme rapport §2.3
```

Non activé en démo locale (dépendance `pysqlcipher3` lourde sous Windows) ; documenté ici.

## 6. Module IA (`app/ai.py`)

- **Détection d'anomalies** : `IsolationForest` par utilisateur sur des features de connexion
  (heure cyclique, jour, pays bucket, empreinte UA, etc.), persisté via `joblib`. Repli à base de
  règles tant que < 10 échantillons.
- **Scoring de mot de passe** : heuristiques + modèle ML optionnel ; bigrammes, marches clavier,
  normalisation leet, entropie.
- **Génération contextuelle** : phrases de passe mémorisables à partir d'un indice de site.

## 7. Fichiers principaux

| Fichier | Rôle |
|---|---|
| `app/__init__.py` | Factory, clés RS256, headers, error handlers, Socket.IO |
| `app/jwt_keys.py` | Gestion de la paire RSA RS256 |
| `app/routes.py` | API REST v1 (auth ZK, vault blob, SIEM, IA, génération) |
| `app/database.py` | SQLite WAL : comptes ZK, blobs, JournalAudit |
| `app/schemas.py` | Validation stricte (hex, blob, longueurs) |
| `app/security.py` | CSP nonce, headers, rate limiting, risk scoring, log SIEM |
| `app/crypto.py` | `password_score`, `sha1_prefix` (+ crypto legacy de test) |
| `app/ai.py` | Isolation Forest, scoring ML, génération contextuelle |
| `static/js/crypto.js` | Crypto ZK navigateur (KDF, AES-GCM, CSPRNG, HIBP) |
| `static/js/charts.js` | Graphiques SVG (donut, barres, jauge) |
| `static/js/app.js` | Contrôleur SPA (auth ZK, vault, dashboard, alertes, monitoring) |
| `static/css/styles.css` | Design system SOC (thèmes clair/sombre, responsive) |
| `templates/index.html` | SPA ; `404.html`/`500.html` pages d'erreur |

## 8. API — codes de retour

`200` OK · `201` créé · `401` non authentifié / token invalide · `409` conflit (username pris)
· `422` validation · `429` rate limit · `404` introuvable · `503` service externe indisponible (HIBP).
