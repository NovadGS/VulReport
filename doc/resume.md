# Resume des modifications - Session du 09-10/04/2026

## Ce qu'on a fait et pourquoi

### 1. Fix des pipelines CI/CD (les 3 etaient cassees)

**Pourquoi** : Aucune pipeline n'avait jamais passe depuis la creation du repo. Un projet DevSecOps sans CI/CD qui tourne, ca tient pas.

**Causes principales** :
- Secrets GitHub inaccessibles dans les conditions de jobs (deplace en step-level)
- `django-mfa2` dans requirements.txt provoquait un backtracking pip infini (supprime car inutilise - on a notre propre MFA avec pyotp)
- `django-advanced-password-validation==1.1.0` avait un setup.py casse (pin >=1.2.0)
- `semgrep` sans version pin tombait sur des versions 0.x incompatibles (pin >=1.90.0)
- `aquasecurity/trivy-action@0.24.0` n'existait pas (remplace par install CLI)
- Image Docker en majuscules (`NovadGS`) alors que Docker exige du lowercase (ajout `tr`)

**Ou voir** : GitHub Actions -> les 3 workflows sont verts (Security CI, Deploiement CD, DAST)

### 2. Ajout creation de findings manuelle + depuis la KB

**Pourquoi** : Le CDC exige qu'on puisse ajouter des findings "custom" et depuis la KB avec pre-remplissage. C'etait pas implemente.

**Dans le code** :
- `app/core/views.py` : fonctions `finding_create()` et `finding_from_kb()`
- `app/core/urls.py` : 2 nouvelles routes
- `app/templates/core/finding_form.html` : support mode creation
- `app/templates/core/report_detail.html` : bouton "Ajouter manuellement" + liste KB

**Sur le site** : Ouvrir un rapport -> section "Ajouter un finding" -> bouton vert "Ajouter manuellement" OU cliquer sur une fiche KB dans la liste en dessous

### 3. Ajout recherche et filtres (rapports + KB)

**Pourquoi** : Demande dans le CDC, section "Recherche & filtres".

**Dans le code** :
- `app/core/views.py` : parametres GET `q`, `status`, `severity` dans `home()` et `kb_q`, `category` dans `kb_list()`
- `app/templates/core/home.html` : barre de recherche (texte + statut + severite)
- `app/templates/core/kb_list.html` : barre de filtres (mot-cle + categorie)

**Sur le site** : Page d'accueil `/` et page KB `/kb/` -> barres de filtres en haut

### 4. Severity CRITICAL + categories OWASP dans la KB

**Pourquoi** : Le CDC dit "L/M/H/Critique" pour la severite et demande des categories alignees OWASP.

**Dans le code** :
- `app/core/models.py` : `CRITICAL = 4` dans SeverityLevel, 7 nouvelles categories KB (Injection, Auth, XSS, etc.)
- `app/core/migrations/0008_extend_severity_and_kb_categories.py`

**Sur le site** : Creer/editer un finding -> select severite a 4 niveaux. Page KB -> filtre par categorie OWASP.

### 5. Hardening Docker + infrastructure

**Pourquoi** : Bonnes pratiques securite, headers OWASP, image plus legere.

**Dans le code** :
- `Dockerfile` : multi-stage build (builder + runtime)
- `.dockerignore` : nouveau fichier
- `nginx/default.conf` : 5 headers securite (X-Frame-Options, X-Content-Type-Options, etc.)
- `scripts/entrypoint.sh` : seed_accounts + load_owasp_top10 automatiques
- `app/core/management/commands/seed_accounts.py` : creation auto des 3 comptes

**Sur le site** : Comptes `admin`/`pentester`/`viewer` (mdp: `VulnReport2025!`) crees automatiquement. Headers visibles dans DevTools -> Network -> Response Headers.

### 6. Statuts de rapport corriges pour correspondre au CDC

**Pourquoi** : Le CDC dit "Brouillon, En cours, Finalise, Publie". On avait "Brouillon, En revue, Final, Archive".

**Dans le code** :
- `app/core/models.py` : ReportStatus modifie (IN_PROGRESS, FINAL, PUBLISHED)
- `app/core/views.py` : workflow mis a jour (draft -> in_progress -> final -> published)
- `app/core/migrations/0009_update_report_statuses.py` : conversion des donnees
- `app/templates/core/report_detail.html` : boutons "Passer en cours", "Finaliser", "Publier"

**Sur le site** : Page d'un rapport -> section "Workflow & partage" -> boutons de transition de statut

### 7. Dashboard admin ameliore

**Pourquoi** : Le CDC demande "compteurs: # rapports, # findings par severite, rapports recemment modifies".

**Dans le code** :
- `app/core/views.py` : `admin_dashboard()` avec compteurs par severite + rapports recents
- `app/templates/core/admin_dashboard.html` : cartes colorees par severite + tableau rapports recents

**Sur le site** : Se connecter en `admin` -> Dashboard Admin (`/admin-dashboard/`)

### 8. README complet + .env.example

**Pourquoi** : Le CDC exige "README: setup, variables d'env, comptes seed, commandes Docker".

**Fichiers** : `README.md` (reecrit) + `.env.example` (nouveau)

### 9. Rapport de securite

**Pourquoi** : Le CDC exige un "Rapport securite (8-10 p.)" couvrant architecture, mesures OWASP, resultats scans, corrections, risques residuels.

**Fichier** : `doc/rapport_securite.md`

### 10. Fix bouton deconnexion page MFA

**Pourquoi** : Le bouton "Se deconnecter" sur la page OTP faisait un GET au lieu d'un POST -> erreur 405.

**Dans le code** : `app/templates/core/mfa_verify.html` : remplacement du lien par un formulaire POST

**Sur le site** : Page `/mfa/verify/` -> le bouton "Se deconnecter" fonctionne maintenant

---

## Fichiers principaux modifies

| Fichier | Quoi |
|---------|------|
| `requirements.txt` | Suppression django-mfa2, pin dependances |
| `Dockerfile` | Multi-stage build |
| `.dockerignore` | Nouveau |
| `.env.example` | Nouveau |
| `.gitignore` | Ajout suivi.md, retrait doc/ |
| `README.md` | Reecrit complet |
| `nginx/default.conf` | Headers securite |
| `scripts/entrypoint.sh` | Seed + OWASP auto |
| `app/core/models.py` | Statuts CDC, severity CRITICAL, categories OWASP |
| `app/core/views.py` | finding_create, finding_from_kb, filtres, dashboard, workflow |
| `app/core/urls.py` | 2 routes findings |
| `app/core/forms.py` | Inchange (FindingForm existait deja) |
| `app/core/migrations/0008_*.py` | Severity + categories |
| `app/core/migrations/0009_*.py` | Statuts rapport |
| `app/core/management/commands/seed_accounts.py` | Nouveau |
| `app/templates/core/home.html` | Filtres |
| `app/templates/core/kb_list.html` | Filtres |
| `app/templates/core/report_detail.html` | Boutons findings + workflow |
| `app/templates/core/finding_form.html` | Mode creation |
| `app/templates/core/admin_dashboard.html` | Compteurs severite + rapports recents |
| `app/templates/core/mfa_verify.html` | Fix bouton logout |
| `.github/workflows/security-ci.yml` | Fix pipeline |
| `.github/workflows/dast-fuzz.yml` | Fix pipeline |
| `.github/workflows/cd-deploy.yml` | Fix pipeline |
| `doc/doc.md` | Documentation pipeline CI/CD |
| `doc/rapport_securite.md` | Rapport securite (livrable CDC) |
