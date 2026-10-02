# Checklist de vérification finale — SecureVault v3

| Domaine | Élément | État |
|---|---|:---:|
| **Fonctionnalités du rapport** | UC-01 Création de compte (sel CSPRNG client) | ✅ |
| | UC-02 Authentification ZK (Argon2id/PBKDF2 client, Auth_Hash, RS256) | ✅ |
| | UC-03 Gestion du coffre (AES-256-GCM local, blobs opaques) | ✅ |
| | UC-04 Générateur autonome (CSPRNG navigateur) | ✅ |
| | K_enc jamais transmise / aucun localStorage-sessionStorage | ✅ |
| | JournalAudit (événements + score_risque_ia) | ✅ |
| **Sécurité** | JWT RS256 (signature asymétrique) | ✅ |
| | Comparaison temps constant (`hmac.compare_digest`) | ✅ |
| | Anti-énumération de comptes (sel HMAC + timing uniforme) | ✅ |
| | Rate limiting + lockout brute force | ✅ |
| | CSP stricte sans `unsafe-inline` + en-têtes de durcissement | ✅ |
| | HIBP k-anonymat (côté client) | ✅ |
| | IP hachée dans les logs (vie privée) | ✅ |
| **Interface** | Console SOC (dashboard, alertes, monitoring) | ✅ |
| | Graphiques (donut, barres, jauge) | ✅ |
| | Thèmes clair/sombre, responsive | ✅ |
| | Pages d'erreur 404/500, toasts, écrans de chargement | ✅ |
| **Performance** | SQLite WAL, requêtes paramétrées, index | ✅ |
| | Graphiques SVG sans dépendance CDN (hors-ligne) | ✅ |
| **Base de données** | Schéma `users`/`vaults`(CASCADE)/`security_events` | ✅ |
| | Initialisation automatique au démarrage | ✅ |
| **Tests** | Suite verte | ✅ 105/105 |
| **Compilation / exécution** | `python main.py` démarre, sert l'app | ✅ |
| | Dépendances installables (`requirements.txt`) | ✅ |
| | Parcours ZK E2E validé (register→login→blob, rejet AEAD) | ✅ |

## Commandes de vérification

```bash
cd securevault
python -m pytest -q          # → 105 passed
python main.py               # → http://localhost:5000
```

> Limites documentées (non bloquantes) : SQLCipher en option production ; Argon2id WASM en option
> (repli PBKDF2). Voir `AUDIT.md` §4.
