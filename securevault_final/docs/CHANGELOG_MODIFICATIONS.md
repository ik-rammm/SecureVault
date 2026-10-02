# Journal détaillé des modifications — SecureVault v3

Format par modification : Fichier · Ancien comportement · Nouveau comportement · Problème · Solution · Justification · Impact.

---

## Modification 1 — Migration de l'authentification vers le Zero-Knowledge

**Fichiers :** `app/routes.py`, `app/database.py`, `app/schemas.py`, `static/js/crypto.js`

**Ancien comportement :** Le client envoyait `username` + `password` (mot de passe maître) en
clair sur le réseau. Le serveur hachait le mot de passe avec Argon2 (`PasswordHasher`) et le
vérifiait côté serveur.

**Nouveau comportement :** Le client dérive localement `K_enc`/`K_auth` (PBKDF2 600k / Argon2id),
calcule `Auth_Hash = SHA-256(K_auth)` et n'envoie **que** cette empreinte. Le serveur compare en
temps constant.

**Problème :** Le rapport décrit une architecture Zero-Knowledge, mais le code transmettait le
secret au serveur — contradiction majeure et faille de confidentialité (OWASP A02/A04).

**Solution :** Nouveau module `crypto.js` (WebCrypto) ; routes `/auth/salt`, `/auth/register`,
`/auth/login` réécrites ; `verify_auth_hash` avec `hmac.compare_digest`.

**Justification :** Aligner le code sur la conception validée (UC-02) et éliminer l'exposition du
mot de passe maître.

**Impact :** Le serveur ne peut plus déchiffrer le coffre ni connaître le mot de passe. Conformité
ZK réelle. API d'authentification modifiée (tests adaptés).

---

## Modification 2 — Coffre-fort : stockage en blob opaque chiffré côté client

**Fichiers :** `app/routes.py`, `app/database.py`, `static/js/app.js`, `static/js/crypto.js`

**Ancien comportement :** Le serveur déchiffrait le coffre (`decrypt_vault`), modifiait les entrées
et le ré-chiffrait — il voyait donc le contenu en clair en RAM. Le mot de passe maître était requis
à chaque requête (`X-Master-Password`).

**Nouveau comportement :** Le CRUD des entrées est **entièrement côté client** (déchiffrement en
RAM avec `K_enc`, modification, ré-chiffrement AES-256-GCM). Le serveur n'expose que
`GET/PUT /vault/blob` et ne manipule que des blobs opaques.

**Problème :** Le chiffrement serveur violait le ZK (le serveur voyait les secrets).

**Solution :** `ZK.encryptBlob`/`decryptBlob` (format `version||IV||ciphertext+tag`) ; routes blob.

**Justification :** UC-03 — « déchiffrement exclusivement en RAM côté client ».

**Impact :** Confidentialité de bout en bout. Suppression des routes `/vault/entry*` serveur.

---

## Modification 3 — JWT RS256 (signature asymétrique)

**Fichiers :** `app/jwt_keys.py` (nouveau), `app/__init__.py`, `app/routes.py`

**Ancien comportement :** JWT signé en **HS256** avec un secret symétrique (`JWT_SECRET`).

**Nouveau comportement :** Paire RSA 2048 auto-générée/chargée ; JWT signé **RS256** (clé privée)
et vérifié avec la clé publique.

**Problème :** Le rapport exige RS256 ; HS256 partage le secret entre signataire et vérificateur.

**Solution :** Module `jwt_keys.load_or_create_keys()` ; configuration `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`.

**Justification :** Conformité §2.1, posture de sécurité renforcée.

**Impact :** Tokens RS256 vérifiables sans exposer la clé de signature.

---

## Modification 4 — Comparaison temps constant + anti-énumération

**Fichiers :** `app/database.py`, `app/routes.py`

**Ancien comportement :** Vérification par hachage Argon2 ; endpoint de sel inexistant.

**Nouveau comportement :** `verify_auth_hash` compare `Auth_Hash` en temps constant ; timing
uniforme que l'utilisateur existe ou non ; `/auth/salt` renvoie un sel pseudo-déterministe (HMAC)
pour les utilisateurs inconnus.

**Problème :** Risque d'énumération de comptes et d'attaques temporelles.

**Solution :** `hmac.compare_digest` + sel HMAC déterministe.

**Justification :** OWASP A07, §2.1 (comparaison temps constant).

**Impact :** Pas de fuite d'existence de compte ; lockout 5 essais/5 min conservé.

---

## Modification 5 — Durcissement CSP (suppression de `unsafe-inline`)

**Fichier :** `app/security.py`, `templates/*.html`, `static/js/app.js`, `static/css/styles.css`

**Ancien comportement :** `style-src 'unsafe-inline'` ; styles inline dans le HTML.

**Nouveau comportement :** CSP entièrement nonce-based (`script-src`/`style-src 'nonce-…'`),
ajout de `base-uri`/`form-action`. Tous les styles externalisés (`styles.css`) ; styles dynamiques
appliqués via le CSSOM (`element.style`).

**Problème :** `unsafe-inline` élargit la surface XSS (test de sécurité en échec).

**Solution :** Externalisation CSS + nonces + suppression de tout attribut `style=`.

**Justification :** OWASP A03, défense XSS.

**Impact :** CSP stricte vérifiée par test ; aucune régression visuelle.

---

## Modification 6 — Journal de sécurité persistant (JournalAudit / SIEM)

**Fichiers :** `app/security.py`, `app/database.py`, `app/routes.py`

**Ancien comportement :** Événements écrits en fichier log + WebSocket pour les critiques ; pas de
persistance interrogeable.

**Nouveau comportement :** `log_security_event` persiste aussi en table `security_events`
(`event_type`, `detail`, `ip_hash`, `risk_score`, `ts`) ; endpoints `/security/audit` et
`/security/alerts` alimentent le dashboard.

**Problème :** Pas de source de données pour la supervision SOC.

**Solution :** Table = `JournalAudit` du rapport ; IP hachée (vie privée).

**Justification :** Modèle de persistance §2.3 + objectif SIEM.

**Impact :** Monitoring, alertes et timeline alimentés par des données réelles.

---

## Modification 7 — Console SOC / SIEM (front-end)

**Fichiers :** `templates/index.html`, `static/js/app.js`, `static/js/charts.js`, `static/css/styles.css`

**Ancien comportement :** SPA basique (dashboard, vault, generator, audit) avec styles inline.

**Nouveau comportement :** Console SOC complète — cartes statistiques (entrées, événements,
alertes critiques/moyennes/faibles, **score de risque**, état système), graphiques SVG (donut
sévérité, barres événements/7j, jauge de risque), **centre d'alertes** (filtres sévérité/statut,
recherche, statuts Ouverte/En cours/Résolue), **monitoring** (journal, dernières connexions,
anomalies IA), thèmes clair/sombre, responsive, toasts, pages d'erreur.

**Problème :** Le rapport et la soutenance attendent une supervision de niveau professionnel.

**Solution :** Refonte UI + graphiques autonomes + logique de triage d'alertes (persistée, ZK).

**Justification :** Objectif « produit mature », inspiration SIEM/SOC du cahier des charges.

**Impact :** Démonstration plus convaincante ; cohérence visuelle.

---

## Modification 8 — Corrections diverses & nettoyage

**Fichiers :** `app/crypto.py`, `app/ai.py`, `app/routes.py`, projet

- `crypto.decrypt_vault` : entrée non base64 → `WrongPassword` (au lieu d'une exception brute).
- `ai._extract_features` : vecteur de features homogène en `float`.
- `/generate` : ajout du `rate_limit` manquant.
- Suppression du catch-all `/api/<path>` (308).
- Nettoyage : dossiers parasites, `index_new.html`, `index_backup.html`, caches, DB/log régénérables.

**Impact :** Robustesse, cohérence, archive propre.

---

## Modification 9 — Suite de tests réécrite

**Fichiers :** `tests/test_routes.py`, `tests/test_database.py`, `tests/test_crypto.py`, `tests/test_ai.py`

**Ancien comportement :** 16 tests en échec (API obsolète).

**Nouveau comportement :** Tests adaptés au contrat ZK (sel, register/login par `Auth_Hash`, blob
get/put, comparaison temps constant, anti-énumération, lockout, CASCADE, headers CSP) → **105 verts**.

**Bypass `TESTING` du rate limiting** ajouté pour des exécutions déterministes.

**Impact :** Non-régression garantie ; couverture du cœur ZK.
