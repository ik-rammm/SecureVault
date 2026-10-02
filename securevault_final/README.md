# SecureVault v3.0 — Zero-Knowledge Password Manager + SOC Console

**Gestionnaire de mots de passe Zero-Knowledge avec tableau de bord SIEM et Intelligence Artificielle**

Projet de Fin d'Année — 4ᵉ Année Cycle Ingénieur — EMSI Tanger 2025-2026
4CIRT Groupe 1 — Architecture Cryptographique Zero-Knowledge | Encadrant : Pr. Smail Ait El Asri

---

## Membres du groupe

| Membre | Rôle |
|---|---|
| Amine Er-Rebbat | Conception / Cryptographie & IA |
| Moukhafi Ikram | Cryptographie, KDF, tests |
| Berrghouz Ghita | Backend API Flask, JWT, base de données |
| Amrous Iman | Frontend / UX, dashboard SOC |

---

## En une phrase

Vos secrets sont **chiffrés dans votre navigateur** (AES-256-GCM) avec une clé dérivée
localement de votre mot de passe maître. **Le serveur ne voit jamais** votre mot de passe,
ni vos clés, ni vos données en clair — il ne stocke que des **blobs opaques** et une preuve
d'authentification SHA-256. Le tout est supervisé par une **console SOC** (dashboard, alertes,
monitoring) inspirée des plateformes SIEM.

---

## Architecture Zero-Knowledge (conforme au rapport §2.1)

```
 NAVIGATEUR (zone de confiance)                 │   SERVEUR (orchestrateur aveugle)
 ───────────────────────────────────────────────┼───────────────────────────────────
 Master Password                                 │
   └─ KDF(salt)  PBKDF2-SHA256 600k / Argon2id   │
        └─ 512 bits                              │
             ├─ K_enc  (bits 0-255) ── reste en RAM, JAMAIS transmise
             │     └─ AES-256-GCM ─► blob opaque ─────► stockage SQLite (blob)
             └─ K_auth (bits 256-511)            │
                   └─ SHA-256 = Auth_Hash ───────► comparaison temps constant
                                                 │     └─ JWT signé RS256
```

**La clé `K_enc` ne quitte jamais le navigateur et n'est jamais persistée** (ni localStorage,
ni sessionStorage — uniquement le tas mémoire JS pour la durée de la session).

---

## Arborescence

```
securevault/
├── app/
│   ├── __init__.py     # Factory Flask + clés RS256 + headers sécurité + error handlers
│   ├── jwt_keys.py     # Génération/chargement de la paire RSA (RS256)          [NOUVEAU]
│   ├── crypto.py       # Utilitaires (password_score, sha1_prefix) + crypto legacy
│   ├── database.py     # SQLite WAL — comptes ZK, blobs opaques, JournalAudit
│   ├── routes.py       # API REST v1 (auth ZK, vault blob, SIEM, IA)
│   ├── schemas.py      # Validation stricte des entrées
│   ├── ai.py           # Isolation Forest + scoring ML + génération contextuelle
│   └── security.py     # CSP nonce, headers, rate limiting, journal SIEM
├── static/
│   ├── css/styles.css  # Design system SOC (thèmes clair/sombre)               [NOUVEAU]
│   └── js/
│       ├── crypto.js   # Crypto Zero-Knowledge côté client (WebCrypto)         [NOUVEAU]
│       ├── charts.js   # Graphiques SVG autonomes (CSP-clean)                  [NOUVEAU]
│       └── app.js      # Contrôleur SPA (ZK + SIEM)
├── templates/
│   ├── index.html      # SPA (console SOC)
│   ├── 404.html        # Page d'erreur                                          [NOUVEAU]
│   └── 500.html        # Page d'erreur                                          [NOUVEAU]
├── tests/              # 105 tests (crypto, IA, database ZK, API ZK)
├── keys/               # Paire RSA RS256 (auto-générée, hors versioning)
├── scripts/            # benchmark_kdf.py, train_ml_model.py
├── openapi.json        # Spécification OpenAPI
└── requirements.txt
docs/                   # Audit, journal des modifications, soutenance, guides
```

---

## Démarrage rapide (local)

```bash
cd securevault_final
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate sur Linux/Mac)
pip install -r securevault/requirements.txt

cd securevault
python main.py
```

Application disponible sur **http://localhost:5000**. Redis est **optionnel** (dégradation
gracieuse vers une blacklist JWT en mémoire si Redis est absent).

### Production (Docker Compose, optionnel)

```bash
cp .env.example .env     # éditer les secrets
docker-compose up -d
```

---

## API REST (v1)

| Méthode | Route | Description | Auth |
|---|---|---|---|
| GET  | `/api/v1/auth/salt?username=` | Sel public (anti-énumération) | — |
| POST | `/api/v1/auth/register` | Créer un compte (ZK) | — |
| POST | `/api/v1/auth/login` | Authentification par Auth_Hash → JWT RS256 | — |
| POST | `/api/v1/auth/logout` | Invalider le JWT | JWT |
| POST | `/api/v1/auth/refresh` | Rotation du JWT | JWT |
| GET  | `/api/v1/vault/blob` | Télécharger le coffre chiffré (opaque) | JWT |
| PUT  | `/api/v1/vault/blob` | Enregistrer le coffre chiffré (opaque) | JWT |
| POST | `/api/v1/security/strength` | Scoring de force (IA) | — |
| POST | `/api/v1/security/hibp` | HaveIBeenPwned (k-anonymat) | — |
| GET  | `/api/v1/security/audit` | Journal d'événements (SIEM) | JWT |
| GET  | `/api/v1/security/alerts` | Risque de session + alertes | JWT |
| POST | `/api/v1/ai/anomaly` | Détection d'anomalie (Isolation Forest) | JWT |
| POST | `/api/v1/ai/suggest` | Suggestion contextuelle | — |
| POST | `/api/v1/generate` | Mot de passe aléatoire (serveur) | — |
| POST | `/api/v1/generate/memorable` | Phrase de passe mémorisable | — |
| GET  | `/api/v1/health` | État du système | — |

---

## Tests

```bash
cd securevault
python -m pytest -q          # 105 tests
python -m pytest --cov=app   # avec couverture
```

---

## Documentation

| Document | Contenu |
|---|---|
| [docs/AUDIT.md](docs/AUDIT.md) | Audit : exigences, bugs, vulnérabilités, améliorations |
| [docs/CHANGELOG_MODIFICATIONS.md](docs/CHANGELOG_MODIFICATIONS.md) | Journal détaillé des modifications |
| [docs/DOCUMENTATION_TECHNIQUE.md](docs/DOCUMENTATION_TECHNIQUE.md) | Architecture, flux, fichiers |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Installation pas à pas |
| [docs/GUIDE_UTILISATION.md](docs/GUIDE_UTILISATION.md) | Guide d'utilisation |
| [docs/SOUTENANCE.md](docs/SOUTENANCE.md) | Résumé, démo, questions/réponses du jury |
| [docs/CHECKLIST.md](docs/CHECKLIST.md) | Checklist de vérification finale |
| [SECURITY.md](SECURITY.md) | Politique de sécurité |

---

## Variables d'environnement

| Variable | Description | Défaut |
|---|---|---|
| `SECRET_KEY` | Clé de session Flask | Aléatoire |
| `JWT_PRIVATE_KEY_PATH` | Chemin de la clé privée RSA (RS256) | `keys/jwt_private.pem` (auto) |
| `JWT_PUBLIC_KEY_PATH` | Chemin de la clé publique RSA | `keys/jwt_public.pem` (auto) |
| `DATA_DIR` | Dossier de la base SQLite | `securevault/data/` |
| `REDIS_URL` / `REDIS_PASSWORD` | Redis (optionnel) | `redis://redis:6379` |
| `FLASK_ENV` | `development` / `production` | `production` |

---

## Licence

Projet académique — EMSI Tanger 2025-2026. Tous droits réservés.
