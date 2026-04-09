# VulnReport

Application Django de gestion de rapports de pentest avec base de connaissance offensive, construite avec une approche Security by Design.

## Stack technique

- Python 3.11 / Django 5
- PostgreSQL 16
- Gunicorn + Nginx (reverse proxy)
- Docker + Docker Compose
- Bootstrap 5 (templates Django)
- WeasyPrint (export PDF)

## Demarrage rapide

### Pre-requis

- Docker et Docker Compose installes
- Git

### Lancement

```bash
git clone <url-du-repo>
cd VulnReport
cp .env.example .env   # adapter les valeurs si besoin
docker compose up --build -d
```

L'application est accessible sur `http://localhost`.

### Comptes seed (crees automatiquement)

| Utilisateur | Mot de passe       | Role      |
|-------------|-------------------|-----------|
| admin       | VulnReport2025!   | Admin     |
| pentester   | VulnReport2025!   | Pentester |
| viewer      | VulnReport2025!   | Viewer    |

Le mot de passe seed peut etre change via la variable `SEED_PASSWORD` dans `.env`.

### Commandes utiles

```bash
# Lancer la stack
docker compose up --build -d

# Voir les logs
docker compose logs -f web

# Arreter
docker compose down

# Reset complet (supprime les volumes/donnees)
docker compose down -v

# Executer une commande Django
docker compose exec web python manage.py <commande>

# Creer un superuser manuellement
docker compose exec web python manage.py createsuperuser
```

## Variables d'environnement

Fichier `.env` a la racine du projet :

| Variable | Description | Defaut |
|----------|-------------|--------|
| `DJANGO_SECRET_KEY` | Cle secrete Django (obligatoire) | - |
| `DJANGO_DEBUG` | Mode debug | `False` |
| `DJANGO_ALLOWED_HOSTS` | Hosts autorises (separes par virgule) | `localhost` |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Origins CSRF | `http://localhost` |
| `POSTGRES_DB` | Nom de la base | `vulnreport` |
| `POSTGRES_USER` | Utilisateur PostgreSQL | `vulnreport` |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL | `vulnreport` |
| `POSTGRES_HOST` | Hote PostgreSQL | `db` |
| `POSTGRES_PORT` | Port PostgreSQL | `5432` |
| `SEED_PASSWORD` | Mot de passe des comptes seed | `VulnReport2025!` |
| `SECURE_SSL_REDIRECT` | Redirection HTTPS | `True` (prod) |
| `SESSION_COOKIE_SECURE` | Cookie session secure | `True` (prod) |
| `CSRF_COOKIE_SECURE` | Cookie CSRF secure | `True` (prod) |
| `AXES_FAILURE_LIMIT` | Tentatives avant blocage | `5` |
| `MFA_TOTP_ENCRYPTION_KEY` | Cle Fernet pour chiffrement TOTP | - |
| `EMAIL_HOST` | Serveur SMTP | `smtp.gmail.com` |
| `EMAIL_PORT` | Port SMTP | `587` |
| `EMAIL_HOST_USER` | Utilisateur SMTP | - |
| `EMAIL_HOST_PASSWORD` | Mot de passe SMTP | - |

## Securite implementee

- **Authentification** : sessions Django, cookies HttpOnly/Secure/SameSite
- **Hashage** : Argon2id (recommande OWASP)
- **RBAC** : 3 roles (Viewer, Pentester, Admin) avec controle d'acces strict
- **MFA/TOTP** : double authentification avec pyotp + chiffrement Fernet
- **Anti brute-force** : django-axes (blocage apres 5 tentatives)
- **CSP** : Content Security Policy stricte via django-csp
- **Headers securite** : X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy
- **Validation** : mots de passe complexes (10 car. min, maj, min, special)
- **Audit log** : tracabilite de toutes les actions sensibles
- **Anti-IDOR** : verification ownership sur chaque vue

## Architecture

```
VulnReport/
├── .env / .env.example
├── Dockerfile              # Multi-stage build
├── docker-compose.yml      # web + db + nginx
├── nginx/default.conf      # Reverse proxy + headers securite
├── requirements.txt
├── scripts/entrypoint.sh   # Migrations + collectstatic + seed
└── app/
    ├── manage.py
    ├── config/             # Settings, URLs, WSGI
    └── core/               # App principale
        ├── models.py       # User, Report, Finding, KB, AuditLog...
        ├── views.py        # Toutes les vues
        ├── forms.py        # Formulaires
        ├── middleware.py   # Audit + MFA guard
        ├── mfa.py          # TOTP enrollment/verification
        ├── cve_sources.py  # Lookup CVE via API MITRE
        └── templates/      # Templates Django
```

## CI/CD (GitHub Actions)

### Pipeline Securite CI (`security-ci.yml`)
Declenchee a chaque push/PR sur `main` :
- **Semgrep** : SAST (regles security-audit + python + django + secrets)
- **Bandit** : SAST Python
- **pip-audit** : SCA (vulnerabilites dans les dependances)
- **GitLeaks** : detection de secrets commites
- **Trivy** : scan de l'image Docker (vuln OS + libs)
- **Snyk** : SCA avancee (si token configure)
- **SonarQube** : qualite de code (si configure)

### Tests DAST et Fuzzing (`dast-fuzz.yml`)
Declenchee manuellement ou chaque lundi :
- **OWASP ZAP** : scan baseline DAST
- **ffuf** : fuzzing des endpoints

### Deploiement CD (`cd-deploy.yml`)
Declenchee apres la pipeline securite :
- Build + push image Docker vers GHCR
- Deploiement SSH optionnel

### Secrets GitHub a configurer

| Secret | Usage |
|--------|-------|
| `SNYK_TOKEN` | Analyse Snyk (optionnel) |
| `SONAR_TOKEN` | SonarQube (optionnel) |
| `SONAR_HOST_URL` | URL SonarQube (optionnel) |
| `SSH_HOST`, `SSH_USER`, `SSH_PRIVATE_KEY` | Deploiement SSH (optionnel) |
