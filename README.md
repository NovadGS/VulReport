# VulnReport

Application Django de gestion de rapports de pentest, construite avec une approche Security by Design.

## Stack technique

- Python 3.11+
- Django + ORM
- PostgreSQL
- Templates Django + Bootstrap 5
- Docker + Docker Compose + Nginx
- Bandit, pip-audit, WeasyPrint

## Arborescence

```text
VulnReport/
├── .env
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── nginx/
│   └── default.conf
├── requirements.txt
├── scripts/
│   └── entrypoint.sh
└── app/
    ├── manage.py
    ├── config/
    │   ├── __init__.py
    │   ├── asgi.py
    │   ├── settings.py
    │   ├── urls.py
    │   └── wsgi.py
    ├── core/
    │   ├── __init__.py
    │   ├── admin.py
    │   ├── apps.py
    │   ├── middleware.py
    │   ├── migrations/
    │   │   └── __init__.py
    │   ├── models.py
    │   ├── signals.py
    │   ├── urls.py
    │   └── views.py
    └── templates/
        ├── base.html
        ├── core/
        │   ├── home.html
        │   └── report_detail.html
        └── registration/
            └── login.html
```

## Sécurité implémentée (socle)

- `AUTH_USER_MODEL` custom avec champ `role` (`admin`, `pentester`, `viewer`)
- Modèles `Report` et `AuditLog` avec champs de traçabilité
- Middleware d’audit pour capturer l’IP client
- Logs automatiques de connexion/déconnexion (signaux)
- Contrôle anti-IDOR dans la vue `report_detail`
- En-têtes de sécurité Django et CSP stricte via `django-csp`
- Préparation MFA/WebAuthn avec `django-mfa2`

## Démarrage

1. Mettre à jour les secrets dans `.env`.
2. Lancer les conteneurs :

```bash
docker compose up --build
```

3. Ouvrir `http://localhost`.

## Initialisation RBAC recommandée

Après le premier démarrage, créer les groupes Django :

- `Admin`
- `Pentester`
- `Viewer`

Puis attribuer les permissions via l’admin Django selon le cahier des charges.

## Outils DevSecOps

- SAST :
  - `bandit -r app`
- SCA :
  - `pip-audit -r requirements.txt`

## Push Git

```bash
git init
git add .
git commit -m "feat: bootstrap secure VulnReport stack and core models"
git branch -M main
git remote add origin <votre-url-repo>
git push -u origin main
```
