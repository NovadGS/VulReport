# VulnReport

Application Django de gestion de rapports de pentest avec base de connaissance offensive, construite avec une approche Security by Design.

### Creer le fichier .env

Le fichier `.env` n'est pas dans le depot . Il faut le creer a partir du template .env.example 

**Obligatoire** : editer `.env` et remplacer `DJANGO_SECRET_KEY` par une cle aleatoire. Sans cette cle, l'application refuse de demarrer.

Générer une clé dans PowerShell : ```python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'```

### Comptes seed (crees automatiquement)

Les 3 comptes suivants sont crees automatiquement au premier demarrage par `scripts/entrypoint.sh` (commande Django `seed_accounts`). **Pas besoin de les creer manuellement**.

| Utilisateur | Mot de passe       | Role      | Usage                           |
|-------------|--------------------|-----------|---------------------------------|
| `admin`     | `VulnReport2025!`  | Admin     | Dashboard admin, gestion users  |
| `pentester` | `VulnReport2025!`  | Pentester | Creation rapports + findings    |
| `viewer`    | `VulnReport2025!`  | Viewer    | Lecture seule                   |

Le mot de passe par defaut est `VulnReport2025!`. Il peut etre modifie via `SEED_PASSWORD` dans `.env` **avant** le premier demarrage.


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

## CI/CD (GitHub Actions)

### Pipeline Securite CI (`security-ci.yml`)
Declenchee a chaque push/PR sur `main` :
- **Semgrep** : SAST (regles security-audit + python + django + secrets)
- **Bandit** : SAST Python
- **pip-audit** : SCA 
- **GitLeaks** : detection de secrets commites
- **Trivy** : scan de l'image Docker 
- **Snyk** : SCA avancee (si token configure)
- **SonarQube** : qualite de code (si configure)

### Tests DAST et Fuzzing (`dast-fuzz.yml`)
Declenchee manuellement ou programmé :
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
