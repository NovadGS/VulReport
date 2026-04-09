# Rapport de Securite - VulnReport

**Projet** : VulnReport - Assistant de generation de rapports de pentest  
**Module** : UE7 DevSecOps - Developpement de solutions web securisees  
**Date** : Avril 2026  

---

## 1. Introduction

VulnReport est une application web permettant de generer des rapports de tests d'intrusion et de maintenir une base de connaissance offensive. Ce rapport documente les mesures de securite mises en place, les resultats des analyses automatisees (SAST, SCA, DAST) et les risques residuels identifies.

L'application est construite avec Django 5 (Python 3.11), PostgreSQL 16, et deploye via Docker Compose avec Nginx en reverse proxy. L'approche Security by Design a ete appliquee des la conception.

---

## 2. Architecture technique

### 2.1 Vue d'ensemble

```
                    +-----------+
  Client HTTP ----> |   Nginx   | (port 80)
                    |  (proxy)  |
                    +-----+-----+
                          |
                    +-----v-----+
                    | Gunicorn  | (port 8000)
                    |  Django   |
                    +-----+-----+
                          |
                    +-----v-----+
                    | PostgreSQL| (port 5432)
                    |   16      |
                    +-----------+
```

### 2.2 Composants

| Composant | Role | Image/Tech |
|-----------|------|------------|
| Nginx | Reverse proxy, headers securite, fichiers statiques | nginx:alpine |
| Gunicorn/Django | Serveur applicatif, logique metier | python:3.11-slim (multi-stage) |
| PostgreSQL | Base de donnees relationnelle | postgres:16-alpine |

### 2.3 Schema de la base de donnees

Tables principales :
- `users` : utilisateurs avec role RBAC (admin/pentester/viewer), champs MFA
- `reports` : rapports de pentest avec workflow de statuts (Brouillon > En cours > Finalise > Publie)
- `findings` : vulnerabilites rattachees aux rapports, avec severite et score CVSS
- `kb_entries` : base de connaissance offensive (fiches vulnerabilites)
- `audit_logs` : journal d'audit de toutes les actions sensibles
- `organizations` / `organization_memberships` : gestion multi-tenant
- `top_devices` : dispositifs TOTP pour le MFA
- `friend_requests` : systeme de contacts entre utilisateurs

### 2.4 Flux d'authentification

1. L'utilisateur saisit ses identifiants sur `/accounts/login/`
2. Django verifie le mot de passe (hashage Argon2id)
3. django-axes verifie le nombre de tentatives echouees (blocage apres 5 echecs)
4. Si MFA active : redirection vers `/mfa/verify/` pour saisir le code TOTP
5. Session creee avec cookies securises (HttpOnly, SameSite=Lax, Secure en prod)
6. L'action est journalisee dans `audit_logs`

---

## 3. Mesures de securite OWASP

### 3.1 A01 - Broken Access Control

**Risque** : Un utilisateur accede a des ressources qui ne lui appartiennent pas (IDOR).

**Mesures** :
- RBAC strict avec 3 roles : Viewer (lecture seule), Pentester (ses rapports), Admin (tout)
- Verification ownership sur chaque vue : `_ensure_can_view_report()` et `_ensure_can_edit_report()` dans views.py
- Le middleware `MFAGuardMiddleware` empeche l'acces aux vues protegees sans MFA si requis
- Les requetes ORM sont filtrees par utilisateur (ex: `report.author_id == user.id`)

**Code** :
```python
def _ensure_can_edit_report(user, report):
    if user.role == UserRole.ADMIN:
        return
    if user.role == UserRole.PENTESTER and report.author_id == user.id:
        return
    raise PermissionDenied("Acces interdit.")
```

### 3.2 A02 - Cryptographic Failures

**Risque** : Donnees sensibles stockees ou transmises en clair.

**Mesures** :
- Hashage des mots de passe avec Argon2id (recommandation OWASP)
- Cles TOTP chiffrees avec Fernet (cryptography) avant stockage en base
- Cookies de session avec flags `HttpOnly`, `Secure`, `SameSite=Lax`
- HSTS active en production (max-age=31536000)
- Proxy SSL header configure (`X-Forwarded-Proto`)

**Configuration** (settings.py) :
```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    ...
]
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # en production
CSRF_COOKIE_HTTPONLY = True
```

### 3.3 A03 - Injection

**Risque** : Injection SQL, injection de commandes.

**Mesures** :
- Utilisation exclusive de l'ORM Django (pas de requetes SQL brutes)
- Validation des entrees utilisateur cote serveur via les formulaires Django
- Fonction `_clean_text()` pour nettoyer les textes avant traitement
- Limitation de la taille des imports (`MAX_IMPORT_FILE_SIZE = 2 Mo`)

### 3.4 A05 - Security Misconfiguration

**Risque** : Configuration par defaut non securisee, headers manquants.

**Mesures Django** (settings.py) :
```python
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

**Mesures Nginx** (default.conf) :
```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

### 3.5 A06 - Vulnerable and Outdated Components

**Risque** : Dependances avec des CVE connues.

**Mesures** :
- pip-audit dans la pipeline CI pour scanner les dependances Python
- Trivy pour scanner l'image Docker (vulnerabilites OS + libraries)
- Snyk (optionnel) pour une analyse SCA avancee
- Dependances epinglees dans requirements.txt avec bornes de version

### 3.6 A07 - Identification and Authentication Failures

**Risque** : Brute-force, sessions faibles, mots de passe triviaux.

**Mesures** :
- django-axes : blocage apres 5 tentatives echouees (cooldown 1h)
- Validation de mot de passe : 10 caracteres minimum, majuscule, minuscule, caractere special
- MFA/TOTP optionnel avec pyotp
- Sessions Django avec timeout configurable
- Tokens d'activation par email pour les nouveaux comptes

### 3.7 A09 - Security Logging and Monitoring

**Risque** : Pas de tracabilite des actions, incidents non detectes.

**Mesures** :
- Modele `AuditLog` avec champs : acteur, action, type d'objet, id, IP, timestamp, metadonnees
- Actions journalisees : login, logout, creation/edition/suppression de rapports, findings, KB, changements de roles
- Middleware `AuditLogMiddleware` pour capturer l'IP client
- Signaux Django pour les connexions/deconnexions
- Dashboard admin avec historique des evenements d'audit

---

## 4. Content Security Policy (CSP)

Configuration django-csp stricte :

```python
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_IMG_SRC = ("'self'", "data:")
CSP_FONT_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_CONNECT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
```

Seul `cdn.jsdelivr.net` est autorise (pour Bootstrap CSS/fonts). Aucun inline script, aucun iframe, aucun objet embarque.

---

## 5. Resultats SAST/SCA

### 5.1 Semgrep (SAST)

Rulesets utilises : `p/security-audit`, `p/python`, `p/django`, `p/secrets`

**Resultats** : Aucun finding bloquant detecte sur le code applicatif (`app/`).

Les regles couvrent : injections SQL, XSS, CSRF bypass, deserialization, secrets hardcodes, mauvaises pratiques Django.

### 5.2 Bandit (SAST Python)

Commande : `bandit -r app -f txt -ll` (niveau medium et au-dessus)

**Resultats** : Aucun finding de severite medium ou high.

### 5.3 pip-audit (SCA)

Commande : `pip-audit -r requirements.txt`

**Resultats** : Toutes les dependances a jour, aucune CVE connue dans les versions utilisees.

Dependances principales : Django>=5.0, psycopg>=3.1, cryptography>=46.0.6, django-axes>=6.5, django-csp>=3.8.

### 5.4 GitLeaks (detection de secrets)

Scan complet de l'historique Git.

**Resultats** : Aucun secret detecte (cles API, mots de passe, tokens).

Le fichier `.env` est dans `.gitignore` et n'est jamais commite.

### 5.5 Trivy (scan image Docker)

Scan de l'image Docker pour les vulnerabilites HIGH et CRITICAL.

**Resultats** : Les vulnerabilites OS de l'image de base (`python:3.11-slim`) sont signalees avec `--exit-code 0` (informatif). Pas de vulnerabilite bloquante dans les packages Python installes.

---

## 6. Resultats DAST

### 6.1 OWASP ZAP (baseline scan)

Scan en mode baseline sur `http://localhost/`.

**Findings typiques et corrections** :

| Finding ZAP | Severite | Statut |
|-------------|----------|--------|
| Missing Anti-clickjacking Header | Medium | Corrige (X-Frame-Options: DENY) |
| X-Content-Type-Options Header Missing | Low | Corrige (nosniff) |
| Cookie Without Secure Flag | Low | Corrige (SECURE=True en prod) |
| Cookie Without SameSite | Low | Corrige (SameSite=Lax) |
| CSP Header Not Set | Medium | Corrige (django-csp) |

### 6.2 ffuf (fuzzing)

Wordlist testee : admin, login, register, api, dashboard, secret, backup, .git, .env, debug.

**Resultats** : Les endpoints sensibles (`.git`, `.env`, `debug`) retournent 404. Les endpoints legitimes (admin, login, dashboard) retournent les codes attendus (301/302 redirect vers login).

---

## 7. Corrections appliquees

| Probleme | Source | Correction |
|----------|--------|------------|
| Headers securite manquants | DAST (ZAP) | Ajout dans nginx/default.conf + settings.py |
| CSP non configuree | DAST (ZAP) | django-csp avec politique stricte |
| Cookies non securises | DAST (ZAP) | Flags HttpOnly, Secure, SameSite |
| Dependances vulnerables | SCA (pip-audit) | Mise a jour des versions dans requirements.txt |
| Image Docker trop grosse | Trivy + bonnes pratiques | Dockerfile multi-stage |
| Secrets dans le code | GitLeaks | Externalisation dans .env + .gitignore |
| Brute-force possible | Analyse risques | django-axes (5 tentatives max) |
| Mots de passe faibles | OWASP | Validation complexe (10 car, maj, min, special) |
| IDOR sur les rapports | Analyse code | Verification ownership systematique |

---

## 8. Risques residuels et ameliorations

### 8.1 Risques residuels

| Risque | Severite | Justification |
|--------|----------|---------------|
| Pas de rate limiting global (hors login) | Faible | django-axes protege le login, les autres endpoints sont proteges par l'authentification |
| MFA optionnel (pas force) | Moyen | L'utilisateur peut choisir de ne pas activer le TOTP |
| Pas de WAF | Faible | Nginx filtre les requetes basiques, un WAF serait un plus en production |
| Image Docker `python:3.11-slim` inclut des paquets OS avec des CVE | Info | Les CVE sont dans des paquets systeme non utilises par l'application |
| Pas de chiffrement au repos de la base | Moyen | PostgreSQL ne chiffre pas les donnees au repos par defaut |

### 8.2 Ameliorations possibles

- **Rate limiting global** : ajouter django-ratelimit sur les endpoints critiques
- **MFA obligatoire** : forcer l'enrollment TOTP pour les roles Admin et Pentester
- **WAF** : deployer ModSecurity devant Nginx
- **Monitoring** : integrer Prometheus + Grafana pour le suivi des metriques securite
- **SBOM** : generer un Software Bill of Materials pour le suivi des composants
- **Pentest manuel** : completer les scans automatises par un audit manuel
- **Chiffrement au repos** : activer le chiffrement PostgreSQL (pgcrypto ou TDE)
- **Rotation des secrets** : automatiser la rotation de DJANGO_SECRET_KEY et MFA_TOTP_ENCRYPTION_KEY

---

## 9. Conclusion

VulnReport integre les bonnes pratiques de securite des la conception : RBAC strict, hashage Argon2id, cookies securises, CSP, headers de securite, audit log complet, et MFA optionnel. La pipeline CI/CD automatise les verifications de securite (SAST avec Semgrep et Bandit, SCA avec pip-audit et Trivy, DAST avec OWASP ZAP) a chaque push. Les findings des scans ont ete corriges et documentes. Les risques residuels identifies sont de severite faible a moyenne et des pistes d'amelioration sont proposees pour une mise en production renforcee.
