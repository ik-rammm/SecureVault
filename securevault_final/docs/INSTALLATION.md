# Guide d'installation — SecureVault v3

## Prérequis

- **Python 3.11+** (testé sous Python 3.13).
- pip, et `venv`.
- (Optionnel) Docker + Docker Compose pour la stack production.
- (Optionnel) Redis — sinon dégradation gracieuse automatique.

## Installation locale (recommandée pour la démo)

### Windows (PowerShell)

```powershell
cd securevault_final
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r securevault\requirements.txt

cd securevault
python main.py
```

### Linux / macOS

```bash
cd securevault_final
python3 -m venv .venv
source .venv/bin/activate
pip install -r securevault/requirements.txt

cd securevault
python main.py
```

➡️ Ouvrir **http://localhost:5000**

> Au premier démarrage, une paire de clés RSA RS256 est générée automatiquement dans
> `securevault/keys/`. La base SQLite est créée dans `securevault/data/`.

## Variables d'environnement (facultatif)

Copier `.env.example` en `.env` et ajuster si besoin :

```bash
cp .env.example .env
```

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | Clé de session Flask |
| `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` | Clés RS256 (auto si absentes) |
| `DATA_DIR` | Dossier base SQLite |
| `REDIS_URL` / `REDIS_PASSWORD` | Redis (optionnel) |
| `FLASK_ENV` | `development` / `production` |

## Lancer les tests

```bash
cd securevault
python -m pytest -q            # 105 tests
python -m pytest --cov=app     # avec couverture
```

## Déploiement Docker (production, optionnel)

```bash
cp .env.example .env     # éditer les secrets
docker-compose up -d     # backend + redis + nginx
docker-compose logs -f backend
```

- Nginx expose l'application (ajouter de vrais certificats TLS 1.3 en production).
- Redis gère la blacklist JWT et le rate limiting distribué.

## Dépannage

| Symptôme | Cause / solution |
|---|---|
| `ModuleNotFoundError` | Le venv n'est pas activé / dépendances non installées. |
| Port 5000 occupé | Fermer l'autre processus ou changer le port dans `main.py`. |
| HIBP indisponible | Pas d'accès Internet → la vérification renvoie une erreur non bloquante. |
| Argon2id non utilisé | Module `hash-wasm` non chargé → repli PBKDF2 (normal en local). |
| « wrong master password » | Mot de passe maître erroné — le coffre est **irrécupérable** sans lui (par conception ZK). |
