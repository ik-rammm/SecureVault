# Guide d'utilisation — SecureVault v3

## 1. Créer un compte

1. Ouvrir http://localhost:5000 → onglet **Create account**.
2. Choisir un nom d'utilisateur (3–32 caractères) et un **mot de passe maître** (≥ 12 caractères).
   La jauge de force s'actualise en temps réel (calcul **local**).
3. Choisir le KDF (PBKDF2 par défaut ; Argon2id si le module WASM est chargé).
4. **Create encrypted vault** : les clés sont dérivées dans le navigateur, le coffre vide est
   chiffré localement, et seul le sel + la preuve SHA-256 + le blob sont envoyés.

> ⚠️ **Important :** le mot de passe maître n'est ni transmis ni stocké. Si vous l'oubliez, le
> coffre est **définitivement irrécupérable** (c'est la garantie Zero-Knowledge).

## 2. Se connecter

Onglet **Sign in** → nom d'utilisateur + mot de passe maître → **Unlock vault**.
Le navigateur récupère le sel, dérive les clés, prouve l'identité (SHA-256), puis télécharge et
déchiffre le coffre en mémoire.

## 3. Tableau de bord (Dashboard SOC)

- **Cartes** : nombre d'identifiants, score de santé du coffre, événements de sécurité, alertes
  critiques, **score de risque de session**, état du chiffrement.
- **Graphiques** : événements de sécurité sur 7 jours, jauge de risque, répartition des alertes.
- **Activité récente** : fusion du journal du coffre et des événements serveur.

## 4. Coffre-fort (Vault)

- **New entry** : titre, identifiant, mot de passe (avec générateur intégré), URL, catégorie, notes.
- **Recherche** et **filtres par catégorie**.
- Clic sur une entrée → détail : révéler/copier le mot de passe, force, éditer, supprimer.
- Toute modification re-chiffre le coffre et le renvoie comme blob opaque.

## 5. Générateur

- **Random** : longueur réglable, majuscules/chiffres/symboles — généré via CSPRNG **local**.
- **Memorable** : phrase de passe lisible (avec indice de site optionnel).
- **AI suggest** : suggestion contextuelle assistée par le module IA.
- **Breach check (HIBP)** : vérifie si un mot de passe est compromis — seul un préfixe SHA-1
  (5 caractères) est envoyé (k-anonymat) ; le mot de passe ne quitte jamais l'appareil.

## 6. Centre d'alertes

- Liste des alertes (risque de session + événements de sévérité moyenne et plus).
- **Filtres** par sévérité (Critique/Élevée/Moyenne/Faible) et **statut**, **recherche**, **tri**.
- Pour chaque alerte, changer le **statut** : Ouverte → En cours → Résolue. Le triage est persisté
  dans le coffre chiffré (donc Zero-Knowledge).

## 7. Monitoring

- **Journal d'événements système** : type, détail, IP hachée, score de risque, horodatage ; avec
  filtre par type et recherche.
- **Dernières connexions**.
- **Détection d'anomalie IA** : analyse la session courante via le modèle Isolation Forest.

## 8. Confort

- **Thème clair/sombre** (bouton en haut à droite, préférence mémorisée).
- **Responsive** : sidebar repliable sur mobile (bouton menu).
- **Déconnexion** : invalide immédiatement le JWT et efface les secrets de la mémoire.
