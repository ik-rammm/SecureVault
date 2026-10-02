# Dossier de soutenance — SecureVault v3

## 1. Résumé du projet

### Objectif
Concevoir et réaliser un **gestionnaire de mots de passe Zero-Knowledge** : l'utilisateur est le
seul détenteur de ses secrets ; le serveur ne peut **jamais** déchiffrer les données, même s'il est
compromis. Le projet est enrichi d'une **console de supervision de sécurité (SOC/SIEM)** et d'un
**module d'Intelligence Artificielle** (détection d'anomalies + scoring de mots de passe).

### Architecture
- **Client (zone de confiance)** : dérivation de clés (PBKDF2-SHA256 600k / Argon2id) et chiffrement
  AES-256-GCM **dans le navigateur** via WebCrypto. La clé `K_enc` ne quitte jamais la machine.
- **Serveur (orchestrateur aveugle)** : Flask. Authentifie via `Auth_Hash = SHA-256(K_auth)`
  comparé en temps constant, émet un **JWT RS256**, stocke des **blobs opaques** et journalise les
  événements de sécurité.
- **Persistance** : SQLite (WAL) — `users`, `vaults` (CASCADE), `security_events` (JournalAudit).

### Technologies
Python 3 / Flask, Flask-SocketIO, PyJWT (RS256), cryptography, scikit-learn (Isolation Forest),
SQLite ; côté client : JavaScript vanilla + WebCrypto, graphiques SVG maison ; Docker/Nginx/Redis
pour la production.

### Fonctionnement général
Mot de passe maître → KDF(salt) → 512 bits → `K_enc` (chiffrement local) + `K_auth` (preuve d'auth).
Seuls le sel, la preuve SHA-256 et le blob chiffré transitent. La supervision exploite le journal
d'événements et le module IA.

---

## 2. Guide de démonstration (≈ 8 min)

1. **Inscription** — créer un compte. Ouvrir les **DevTools → Network** sur `/auth/register` et
   montrer la charge utile : `salt_hex`, `auth_hash`, `blob` — **aucun mot de passe en clair**.
2. **Connexion** — montrer `/auth/salt` puis `/auth/login` (seul `auth_hash` part). Montrer dans
   l'onglet **Application** qu'**aucun** mot de passe/JWT n'est en localStorage/sessionStorage.
3. **JWT RS256** — coller le token sur jwt.io (ou montrer l'en-tête) : `"alg":"RS256"`.
4. **Coffre** — ajouter une entrée ; sur `PUT /vault/blob`, montrer que le corps est un **blob
   opaque** (base64 illisible). Recharger : l'entrée est bien là (déchiffrée localement).
5. **Preuve ZK** — montrer la base : `sqlite3 data/securevault.db "SELECT encrypted_blob FROM vaults"`
   → contenu chiffré illisible côté serveur.
6. **Générateur + HIBP** — générer un mot de passe ; tester un mot de passe connu (ex. `password`) :
   « trouvé dans N fuites » ; montrer dans Network que seul un préfixe SHA-1 part vers HIBP.
7. **Dashboard SOC** — cartes, jauge de risque, graphiques.
8. **Centre d'alertes** — provoquer des `LOGIN_FAIL` (mauvais mot de passe) → apparition d'alertes ;
   changer un statut Ouverte → Résolue.
9. **Monitoring** — journal d'événements, dernières connexions, **analyse d'anomalie IA**.
10. **Déconnexion** — le token est invalidé (logout → blacklist) : un rappel d'API renvoie 401.

---

## 3. Améliorations ajoutées (et leur justification)

| Amélioration | Justification |
|---|---|
| Vrai **Zero-Knowledge client** | Le code initial contredisait le rapport ; correction de la faille centrale. |
| **JWT RS256** | Conformité §2.1 ; signature asymétrique plus sûre que HS256. |
| **CSP stricte** (sans `unsafe-inline`) | Réduction de la surface XSS (OWASP A03). |
| **Anti-énumération** + temps constant | Empêche la découverte de comptes et les attaques temporelles. |
| **Console SOC / SIEM** | Supervision professionnelle attendue par le cahier des charges. |
| **HIBP & scoring côté client** | Cohérence ZK : aucun mot de passe candidat envoyé au serveur. |
| **Graphiques SVG autonomes** | Aucune dépendance CDN → CSP-clean et hors-ligne. |
| **105 tests verts** | Non-régression et preuve de robustesse. |

---

## 4. Questions possibles du jury — et réponses

**Q1. En quoi est-ce réellement « Zero-Knowledge » ?**
Le mot de passe maître ne quitte jamais le navigateur. On y dérive `K_enc` (chiffrement) et `K_auth`
(authentification). Seuls `SHA-256(K_auth)` et le blob AES-256-GCM transitent. Le serveur ne possède
ni la clé ni le secret : il ne peut pas déchiffrer, même compromis. Démonstration : le contenu de la
table `vaults` est illisible.

**Q2. Où s'exécute la dérivation Argon2id ? Le rapport parle de WASM.**
Dans le navigateur. PBKDF2-SHA256 600 000 itérations est natif WebCrypto (garanti, hors-ligne).
Argon2id s'active via un module WASM (`hash-wasm`) ; en son absence, repli transparent vers PBKDF2.
Le champ `kdf` reflète l'algorithme réellement employé. Argon2id est préférable (résistance
mémoire-dure aux GPU/ASIC), PBKDF2 reste un standard OWASP solide.

**Q3. Pourquoi RS256 plutôt que HS256 ?**
RS256 est asymétrique : la clé **privée** signe, la clé **publique** vérifie. Un service de
vérification n'a donc pas besoin du secret de signature. HS256 partage un même secret, plus risqué
si un composant fuit. La paire RSA 2048 est générée au démarrage et la clé privée est restreinte
(`chmod 600`).

**Q4. Que se passe-t-il si l'utilisateur oublie son mot de passe maître ?**
Le coffre est **irrécupérable** : c'est le prix du Zero-Knowledge. Il n'existe aucune porte dérobée.
On le documente clairement à l'utilisateur. (Une fonctionnalité de récupération nécessiterait de
stocker un secret côté serveur, ce qui briserait le modèle.)

**Q5. Comment empêchez-vous le brute force et l'énumération de comptes ?**
Verrouillage 5 essais/5 min par utilisateur + rate limiting glissant par IP. L'endpoint de sel
renvoie un sel pseudo-déterministe (HMAC) pour un utilisateur inconnu, et la comparaison de
`Auth_Hash` se fait en temps constant et avec un timing uniforme → pas de fuite d'existence.

**Q6. La comparaison du hash d'authentification est-elle sûre ?**
Oui : `hmac.compare_digest` (temps constant), conforme au rapport (`secrets.compare_digest`).

**Q7. Comment protégez-vous contre le XSS, vu que les secrets sont en mémoire JS ?**
CSP stricte nonce-based (pas de `unsafe-inline`), `frame-ancestors 'none'`, en-têtes de durcissement
(HSTS, X-Frame-Options, X-Content-Type-Options…), échappement systématique du contenu utilisateur.
Aucun secret n'est en localStorage/sessionStorage : la fenêtre d'exposition est réduite à la session.

**Q8. La vérification HIBP n'envoie-t-elle pas le mot de passe ?**
Non. On calcule SHA-1 localement et on n'envoie que les **5 premiers caractères** du hash
(k-anonymat). Le service renvoie tous les suffixes correspondants ; la comparaison finale est locale.

**Q9. À quoi sert le module IA ? N'est-ce pas du « marketing » ?**
Deux usages concrets : (1) un **Isolation Forest** par utilisateur apprend les habitudes de connexion
(heure, jour, etc.) et signale les anomalies — c'est le `score_risque_ia` du JournalAudit ; (2) un
scoring de mot de passe plus fin (bigrammes, marches clavier, leet, entropie). Le modèle est persisté
(`joblib`) et utilise des règles tant qu'il manque de données.

**Q10. Pourquoi un seul blob chiffré plutôt qu'une entrée par ligne (UML EntreeCoffreFort) ?**
Le blob unique était déjà le choix d'implémentation ; il est **compatible ZK** (le serveur ne peut
de toute façon pas distinguer les entrées). La composition `Utilisateur 1→0..* EntreeCoffreFort` est
conservée au niveau conceptuel et la contrainte CASCADE est appliquée (suppression du compte ⇒
suppression du coffre). On ne modifie donc pas la conception validée.

**Q11. Et le chiffrement au repos (SQLCipher) annoncé dans le rapport ?**
Les données sont **déjà** chiffrées côté client : la base ne contient que des blobs opaques.
SQLCipher (AES-256-CBC, kdf_iter 256000) reste une défense en profondeur recommandée en production
(PRAGMA key). Il n'est pas activé en démo locale car `pysqlcipher3` est lourd à installer sous
Windows ; c'est documenté et sans impact sur la confidentialité.

**Q12. Que stocke exactement le serveur ?**
Par utilisateur : `username`, `salt_hex` (public), `auth_hash` (SHA-256), `kdf`, un `encrypted_blob`
opaque, et un journal d'événements (avec IP **hachée**). Aucune donnée exploitable en clair.

**Q13. Comment gérez-vous l'expiration et la révocation des JWT ?**
Expiration 15 min ; rotation via `/auth/refresh` (l'ancien `jti` est blacklisté) ; révocation
immédiate au logout. La blacklist est dans Redis (ou en mémoire en repli local).

**Q14. Quelle est la couverture de tests ?**
105 tests : crypto, IA, couche base de données ZK (création, vérification temps constant, lockout,
CASCADE, JournalAudit), et l'API ZK de bout en bout (sel, register/login, blob, headers CSP).

**Q15. Quelles évolutions futures ?**
Argon2id WASM packagé par défaut, SQLCipher activé en production, partage de secrets chiffré entre
utilisateurs (échange de clés), 2FA (TOTP) en complément du mot de passe maître, export/import chiffré.

---

## 5. Points forts à mettre en avant
- Conformité **réelle** au modèle Zero-Knowledge du rapport (et non seulement dans le discours).
- Sécurité défendable : RS256, CSP stricte, temps constant, anti-énumération, k-anonymat.
- Valeur ajoutée visible : **console SOC** + **IA** opérationnelles.
- Qualité logicielle : architecture claire, validation stricte, **suite de tests verte**.
