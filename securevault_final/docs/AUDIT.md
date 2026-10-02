# Rapport d'audit — SecureVault v3 (Zero-Knowledge Password Manager)

> Audit réalisé sur la base du *Livrable Intermédiaire 2* (rapport de conception) et du code
> source fourni (`ghita.zip`). Objectif : aligner le code sur la conception validée, corriger
> les défauts, compléter les fonctionnalités manquantes et enrichir l'application.

---

## 1. Conformité aux exigences du rapport

| Exigence (rapport) | Présente | Partielle | Absente | Action réalisée |
|---|:---:|:---:|:---:|---|
| **UC-01** Créer un compte (sel CSPRNG 32 o généré côté client, transmis en clair) | | ✓ (avant) | | Sel désormais **généré côté client** (`ZK.randomSalt`), transmis et persisté. |
| **UC-02a** Dérivation Argon2id/PBKDF2 **côté client**, split K_enc/K_auth | | | ✓ (avant) | Implémenté dans `crypto.js` (`deriveKeys`) — PBKDF2 600k natif + Argon2id optionnel. |
| **UC-02b** Validation `Auth_Hash` en **temps constant**, JWT **RS256** | | ✓ (avant) | | `verify_auth_hash` (`hmac.compare_digest`) + JWT **RS256** (`jwt_keys.py`). |
| **UC-03** Coffre : chiffrement **AES-256-GCM local**, blobs opaques, CRUD | | ✓ (avant) | | Chiffrement **navigateur**, serveur = stockage de blob opaque (`/vault/blob`). |
| **UC-04** Générateur autonome (CSPRNG navigateur, sans transmission) | | ✓ (avant) | | `ZK.generatePassword` via `window.crypto.getRandomValues`. |
| K_enc **jamais transmise**, **aucun localStorage/sessionStorage** (§3.1) | | | ✓ (avant) | Secrets uniquement en **tas mémoire JS** ; suppression du stockage du mot de passe. |
| JWT **RS256** (signature asymétrique) | | | ✓ (avant, HS256) | Paire RSA 2048 auto-générée ; signature/vérification RS256. |
| Comparaison **temps constant** (`secrets.compare_digest`) | | | ✓ (avant) | Ajoutée ; timing uniforme utilisateur connu/inconnu. |
| Modèle de persistance (Utilisateur, EntreeCoffreFort, SessionActive, JournalAudit) | ✓ | | | Tables `users`, `vaults` (CASCADE), `security_events` (= JournalAudit avec `score_risque_ia`). |
| **JournalAudit** immuable (type_evenement, score_risque_ia, horodatage) | | ✓ (avant) | | Persistance DB de tous les événements de sécurité + score de risque. |
| Rate limiting `/auth/login` | ✓ | | | Conservé + appliqué aussi à register/salt/generate/blob. |
| En-têtes de sécurité (CSP, HSTS, X-Frame-Options…) | ✓ | | | CSP **durcie** (suppression de `unsafe-inline`). |
| HaveIBeenPwned par **k-anonymat** | ✓ | | | Conservé + **déplacé côté client** (le mot de passe ne quitte jamais l'appareil). |
| Détection d'anomalies **IA** (score de risque) | ✓ | | | Conservée (Isolation Forest) + intégrée au dashboard SOC. |
| SQLCipher au repos (AES-256-CBC) | | | ✓ | **Documenté** comme couche production (les données sont déjà chiffrées ZK). Voir §4. |
| Dashboard / supervision (type SIEM) | | ✓ (avant) | | **Console SOC complète** : cartes, graphiques, alertes, monitoring. |

**Constat central :** le code initial **contredisait la thèse Zero-Knowledge du rapport** (chiffrement
serveur, mot de passe maître transmis via header `X-Master-Password` et stocké en `sessionStorage`).
La version finale rend le code **réellement Zero-Knowledge**, conforme à la conception validée.

---

## 2. Bugs détectés et corrigés

| # | Fichier | Bug | Correction |
|---|---|---|---|
| B1 | `crypto.py` | `decrypt_vault('not_b64')` levait `binascii.Error` au lieu de `WrongPassword`. | `b64decode(validate=True)` encapsulé → `WrongPassword`. |
| B2 | `ai.py` | `_extract_features` renvoyait un mélange int/float (échec de test). | Cast systématique en `float`. |
| B3 | `routes.py` | `/api/v1/generate` sans `rate_limit` (DoS possible). | Décorateur `rate_limit(60,60)` ajouté. |
| B4 | `security.py` | CSP avec `unsafe-inline` (test rouge + faiblesse XSS). | CSP entièrement nonce-based, `unsafe-inline` supprimé. |
| B5 | Suite de tests | **16 tests en échec** (suite rouge). | Tests réécrits pour l'API ZK → **105 tests verts**. |
| B6 | Projet | Dossiers parasites (`{app,templates,static…}`), `index_new.html` vide, `index_backup.html` obsolète, caches versionnés. | Nettoyés. |
| B7 | `routes.py` | Catch-all `/api/<path>` → 308 (risque de boucles/ambiguïté). | Supprimé ; le front utilise directement `/api/v1`. |

---

## 3. Vulnérabilités détectées et traitées (STRIDE / OWASP)

| # | Vulnérabilité | Gravité | Traitement |
|---|---|:---:|---|
| V1 | **Mot de passe maître transmis au serveur** (header) — viole le ZK (A04/A02) | Critique | Supprimé : seul `Auth_Hash` (SHA-256) transite. |
| V2 | **Mot de passe maître stocké en `sessionStorage`** (XSS → vol des secrets, A03) | Critique | Supprimé : K_enc/JWT uniquement en mémoire JS volatile. |
| V3 | **JWT HS256** (clé symétrique partagée, A02) | Élevée | Migration **RS256** (signature asymétrique). |
| V4 | **CSP `unsafe-inline`** (surface XSS, A03) | Moyenne | CSP nonce-based stricte. |
| V5 | **Énumération de comptes** via `/auth/salt` (A07) | Moyenne | Sel pseudo-déterministe (HMAC) pour utilisateur inconnu + timing uniforme à la connexion. |
| V6 | **Brute force** sur l'authentification (A07) | Moyenne | Verrouillage 5 essais / 5 min + rate limiting IP. |
| V7 | **Comparaison non temps-constant** des secrets (A02) | Moyenne | `hmac.compare_digest`. |
| V8 | Fuite d'IP dans les logs (vie privée) | Faible | IP **hachée** (SHA-256 tronqué) dans tous les journaux. |

> Le secret RSA privé est restreint en permissions (`chmod 600` sur POSIX) et hors du dépôt versionné.

---

## 4. Limites assumées et documentées

- **SQLCipher au repos** : non activé en démo locale (dépendance `pysqlcipher3` difficile sous
  Windows). Ce n'est **pas une faille** : les données sont déjà chiffrées côté client (ZK), donc
  le fichier `.db` ne contient que des blobs opaques. SQLCipher reste recommandé en production
  comme défense en profondeur (PRAGMA key, AES-256-CBC, kdf_iter 256000) — voir `DOCUMENTATION_TECHNIQUE.md`.
- **Argon2id navigateur** : actif si un module `hash-wasm` est chargé ; sinon repli transparent
  vers **PBKDF2-SHA256 600 000 itérations** (natif WebCrypto, garanti hors-ligne). Le champ `kdf`
  reflète l'algorithme réellement utilisé.
- **TLS 1.3** : assuré par le reverse proxy (Nginx) en production ; en local, HTTP simple.

---

## 5. Améliorations réalisées (au-delà des corrections)

1. **Console SOC / SIEM** : dashboard (cartes statistiques, score de risque, graphiques),
   **centre d'alertes** (sévérité, statuts Ouverte/En cours/Résolue, filtres/recherche/tri),
   **monitoring** (journal d'événements, dernières connexions, anomalies IA).
2. **Design system moderne** : thèmes clair/sombre, responsive, badges, squelettes de
   chargement, toasts, pages d'erreur personnalisées (404/500), icônes vectorielles.
3. **Graphiques SVG autonomes** (donut, barres, jauge) — sans dépendance CDN, CSP-clean, hors-ligne.
4. **HIBP côté client** (k-anonymat strict, le mot de passe ne quitte jamais l'appareil).
5. **Jauge de force côté client** (aucune transmission de mots de passe candidats au serveur).
6. **Journal de sécurité persistant** (SQLite) alimentant la supervision.
7. **Suite de tests** portée à **105 tests verts** couvrant le contrat ZK.

Voir `CHANGELOG_MODIFICATIONS.md` pour le détail fichier par fichier.
