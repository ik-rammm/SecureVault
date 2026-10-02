# Arborescence finale du projet — SecureVault v3

```
securevault_final/
├── README.md                       # Présentation, démarrage, API
├── SECURITY.md                     # Politique & architecture de sécurité (mise à jour)
├── .env.example                    # Variables d'environnement (RS256, Redis, DATA_DIR)
├── .gitignore
├── docker-compose.yml              # Stack production (backend + redis + nginx)
├── nginx/
│   ├── nginx.conf                  # Reverse proxy (TLS en production)
│   └── certs/
├── docs/                           # ── Documentation livrée ──
│   ├── AUDIT.md                    # Audit : exigences, bugs, vulnérabilités, améliorations
│   ├── CHANGELOG_MODIFICATIONS.md  # Journal détaillé des modifications
│   ├── DOCUMENTATION_TECHNIQUE.md  # Architecture, flux ZK, fichiers
│   ├── INSTALLATION.md             # Installation pas à pas
│   ├── GUIDE_UTILISATION.md        # Guide d'utilisation
│   ├── SOUTENANCE.md               # Résumé, démo, questions/réponses jury
│   ├── CHECKLIST.md                # Vérification finale
│   └── ARBORESCENCE.md             # Ce fichier
└── securevault/
    ├── main.py                     # Point d'entrée (socketio.run)
    ├── requirements.txt
    ├── Dockerfile
    ├── run.sh
    ├── openapi.json                # Spécification OpenAPI 3.1 (API ZK)
    ├── app/
    │   ├── __init__.py             # Factory + clés RS256 + headers + error handlers
    │   ├── jwt_keys.py             # [NOUVEAU] Paire RSA RS256 (auto-générée)
    │   ├── routes.py               # API REST v1 (auth ZK, vault blob, SIEM, IA)
    │   ├── database.py             # SQLite WAL — comptes ZK, blobs, JournalAudit
    │   ├── schemas.py              # Validation stricte (hex, blob, longueurs)
    │   ├── security.py             # CSP nonce, headers, rate limiting, log SIEM
    │   ├── crypto.py               # password_score, sha1_prefix (+ crypto legacy de test)
    │   └── ai.py                   # Isolation Forest + scoring ML + génération contextuelle
    ├── static/
    │   ├── css/
    │   │   └── styles.css          # [NOUVEAU] Design system SOC (clair/sombre, responsive)
    │   └── js/
    │       ├── crypto.js           # [NOUVEAU] Crypto Zero-Knowledge navigateur (WebCrypto)
    │       ├── charts.js           # [NOUVEAU] Graphiques SVG autonomes
    │       └── app.js              # Contrôleur SPA (ZK + SIEM)
    ├── templates/
    │   ├── index.html              # SPA (console SOC)
    │   ├── 404.html                # [NOUVEAU] Page d'erreur
    │   └── 500.html                # [NOUVEAU] Page d'erreur
    ├── tests/                      # 105 tests
    │   ├── conftest.py
    │   ├── test_crypto.py
    │   ├── test_ai.py
    │   ├── test_database.py        # Réécrit (API ZK)
    │   └── test_routes.py          # Réécrit (API ZK)
    ├── scripts/
    │   ├── benchmark_kdf.py
    │   └── train_ml_model.py
    ├── data/                       # SQLite + logs (généré au runtime, ignoré par git)
    ├── keys/                       # Paire RSA RS256 (générée au runtime, ignorée par git)
    └── models/                     # Modèles ML persistés (runtime)
```

> Les dossiers `data/`, `keys/`, `models/` et les caches sont **générés à l'exécution** et
> volontairement exclus de l'archive (ils se recréent au premier démarrage).
