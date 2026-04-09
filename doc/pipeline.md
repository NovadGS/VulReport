# Pipeline CI/CD - Documentation technique

## Ou sont definis les pipelines

Les pipelines sont definis dans le dossier `.github/workflows/` a la racine du projet. Ce dossier est specifique a GitHub Actions : GitHub detecte automatiquement les fichiers YAML dans ce dossier et les execute selon les conditions definies dans chaque fichier.

On a 3 fichiers, donc 3 pipelines independantes :

```
.github/workflows/
├── security-ci.yml      # Pipeline securite (CI)
├── dast-fuzz.yml         # Tests dynamiques et fuzzing
└── cd-deploy.yml         # Construction et deploiement (CD)
```

Chaque fichier YAML decrit :
- **Quand** la pipeline se declenche (push, PR, horaire, manuellement...)
- **Sur quelle machine** elle tourne (un serveur Ubuntu fourni par GitHub)
- **Quels jobs** sont executes (des groupes d'etapes)
- **Quelles etapes** composent chaque job (des commandes ou des actions)

---

## Comment ca fonctionne concretement

Quand on push du code sur la branche `main`, GitHub lit les fichiers YAML et demarre les pipelines concernees. Chaque pipeline tourne sur une machine virtuelle Ubuntu jetable (un "runner") fournie par GitHub. La machine est creee pour l'occasion, execute les etapes, puis est detruite. Ca veut dire qu'on part toujours d'un environnement propre.

Les pipelines peuvent avoir des **jobs** qui tournent en parallele ou en sequence. Dans un job, les **etapes** (steps) s'executent toujours les unes apres les autres. Si une etape echoue, les suivantes ne s'executent pas (sauf si on a mis `if: always()`).

---

## Pipeline 1 : Pipeline Securite CI (`security-ci.yml`)

### Quand elle se declenche

```yaml
on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]
```

A chaque push sur `main` et a chaque Pull Request qui cible `main`. C'est la pipeline principale, elle tourne a chaque modification du code.

### Permissions

```yaml
permissions:
  contents: read
  security-events: write
```

La pipeline peut lire le code du repo et ecrire des alertes de securite dans l'onglet "Security" de GitHub.

### Job 1 : `analyse-code-et-deps` (Analyse SAST + SCA)

C'est le premier job. Il analyse le code source et les dependances sans executer l'application.

#### Etape 1 : Recuperation du code

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Clone le repo Git sur le runner. `fetch-depth: 0` recupere tout l'historique (necessaire pour GitLeaks qui scanne les anciens commits).

#### Etape 2 : Installation Python 3.11

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
```

Installe Python 3.11 sur le runner. On utilise la meme version qu'en production pour que les tests soient representatifs.

#### Etape 3 : Installation des dependances projet

```yaml
- run: |
    python -m pip install --upgrade pip
    pip install -r requirements.txt
```

Installe toutes les librairies Python du projet (Django, psycopg, cryptography, etc.). C'est necessaire pour que les outils d'analyse connaissent les dependances.

#### Etape 4 : Installation des outils de securite

```yaml
- run: pip install bandit pip-audit 'semgrep>=1.90.0'
```

Installe les 3 outils d'analyse dans une etape separee. On les separe des dependances projet pour eviter les conflits de versions. `semgrep>=1.90.0` est epingle pour eviter que pip installe des versions 0.x incompatibles.

#### Etape 5 : Semgrep (SAST)

```yaml
- run: semgrep scan --config p/security-audit --config p/python --config p/django --config p/secrets app/
```

**Qu'est-ce que c'est** : Semgrep est un outil d'analyse statique (SAST = Static Application Security Testing). Il lit le code source ligne par ligne et cherche des patterns connus de vulnerabilites, sans jamais executer le code.

**Ce qu'il fait ici** : Il scanne tout le dossier `app/` avec 4 jeux de regles :
- `p/security-audit` : regles generales de securite (injections, deserialisation, crypto faible...)
- `p/python` : regles specifiques a Python (eval() dangereux, subprocess sans sanitisation...)
- `p/django` : regles specifiques a Django (requetes SQL brutes via l'ORM, templates non escapees, CSRF desactive...)
- `p/secrets` : detection de secrets hardcodes dans le code (cles API, mots de passe, tokens...)

**Pourquoi cet outil** : Bandit (etape suivante) ne connait pas Django. Semgrep a des regles qui comprennent le framework : il sait que `|safe` dans un template Django desactive l'echappement XSS, que `extra()` dans l'ORM permet de l'injection SQL, etc. Les deux outils ensemble couvrent plus de cas qu'un seul.

**Exemple concret** : Si quelqu'un ecrit `Report.objects.raw("SELECT * FROM reports WHERE id = " + user_input)` dans le code, Semgrep le detecte comme une injection SQL potentielle et bloque la pipeline.

**Si ca echoue** : La pipeline s'arrete. Le code n'est pas deploye tant que le probleme n'est pas corrige.

#### Etape 6 : Bandit (SAST Python)

```yaml
- run: bandit -r app -f txt -ll
```

**Qu'est-ce que c'est** : Bandit est un outil SAST specifique a Python, developpe par l'equipe securite d'OpenStack. Il detecte les mauvaises pratiques de securite dans le code Python.

**Ce qu'il fait ici** : Il scanne recursivement (`-r`) le dossier `app/`, affiche les resultats en texte (`-f txt`), et ne remonte que les findings de severite medium et haute (`-ll` = low-level filter, ignore les findings de severite "low").

**Pourquoi cet outil** : Bandit est plus ancien et plus strict que Semgrep sur certains patterns Python purs (utilisation de `eval()`, `exec()`, `pickle.loads()`, `subprocess.call(shell=True)`, hash faibles comme MD5/SHA1, etc.). C'est l'outil SAST Python de reference.

**Difference avec Semgrep** : Semgrep est generaliste et comprend les frameworks. Bandit est specialise Python et plus pointilleux sur les fonctions dangereuses du langage. Ils sont complementaires : Semgrep trouve les problemes Django, Bandit trouve les problemes Python.

**Si ca echoue** : La pipeline s'arrete.

#### Etape 7 : pip-audit (SCA)

```yaml
- run: pip-audit -r requirements.txt
```

**Qu'est-ce que c'est** : pip-audit est un outil SCA (Software Composition Analysis). Contrairement au SAST qui analyse notre code, le SCA analyse les librairies qu'on utilise. Il verifie si les versions de nos dependances ont des vulnerabilites connues (CVE).

**Ce qu'il fait ici** : Il lit `requirements.txt`, resout les versions installees, et compare chaque package contre la base de donnees OSV (Open Source Vulnerabilities) qui reference toutes les CVE connues pour les packages Python.

**Pourquoi cet outil** : Notre projet utilise une quinzaine de librairies externes (Django, cryptography, psycopg, etc.). Chacune peut avoir des failles de securite decouvertes apres sa publication. On ne peut pas auditer manuellement chaque librairie a chaque mise a jour. pip-audit automatise cette verification.

**Exemple concret** : Si `cryptography==43.0.0` a une CVE connue (par exemple une faille dans le chiffrement AES), pip-audit le detecte et affiche la CVE avec la version corrigee.

**Si ca echoue** : La pipeline s'arrete. Il faut mettre a jour la dependance vulnerable dans requirements.txt.

#### Etape 8 : GitLeaks (detection de secrets)

```yaml
- uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Qu'est-ce que c'est** : GitLeaks scanne l'historique Git complet du repo pour trouver des secrets qui auraient ete commites par erreur : mots de passe, cles API, tokens d'acces, cles privees SSH, etc.

**Ce qu'il fait ici** : Il parcourt tous les commits (pas seulement le dernier, tout l'historique) et utilise des expressions regulieres pour detecter des patterns de secrets. Par exemple, une chaine qui ressemble a `AKIA...` (format d'une cle AWS), ou `ghp_...` (token GitHub), ou une ligne `password = "..."` dans un fichier de config.

**Pourquoi cet outil** : Meme si on a un `.gitignore` qui exclut le fichier `.env`, un developpeur peut commiter un secret par erreur dans un autre fichier, ou commiter temporairement le `.env` puis le supprimer. Le probleme c'est que Git garde tout l'historique : meme si le fichier est supprime, le secret est toujours dans les anciens commits. GitLeaks detecte ca.

**Si ca echoue** : La pipeline s'arrete. Il faut supprimer le secret de l'historique Git (avec `git filter-branch` ou BFG Repo Cleaner) et le revoquer/changer immediatement.

### Job 2 : `scan-image-docker` (Scan image Docker Trivy)

Ce job ne demarre que si le job 1 a reussi (`needs: analyse-code-et-deps`).

#### Etape 1 : Construction de l'image Docker

```yaml
- run: docker build -t vulnreport:${{ github.sha }} .
```

Build l'image Docker du projet. On la tag avec le SHA du commit pour la tracabilite.

#### Etape 2 : Installation de Trivy

```yaml
- run: |
    sudo apt-get update -qq
    sudo apt-get install -y -qq wget apt-transport-https gnupg
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
    sudo apt-get update -qq
    sudo apt-get install -y -qq trivy
```

Installe Trivy via le depot APT officiel d'Aqua Security. On l'installe en CLI plutot que via une GitHub Action car l'action officielle avait des problemes de compatibilite de version.

#### Etape 3 : Scan Trivy

```yaml
- run: trivy image --ignore-unfixed --vuln-type os,library --severity HIGH,CRITICAL --exit-code 0 --format table vulnreport:${{ github.sha }}
```

**Qu'est-ce que c'est** : Trivy est un scanner de vulnerabilites pour les images Docker, developpe par Aqua Security. Il analyse le contenu complet d'une image Docker : les packages de l'OS (Debian, Alpine...), les librairies applicatives (Python, Node, Java...), et les fichiers de configuration.

**Ce qu'il fait ici** : Il scanne l'image qu'on vient de builder et cherche des vulnerabilites connues. Les options :
- `--ignore-unfixed` : ignore les CVE qui n'ont pas encore de correctif disponible (on ne peut rien y faire)
- `--vuln-type os,library` : scanne les packages systeme ET les librairies applicatives
- `--severity HIGH,CRITICAL` : ne montre que les vulnerabilites graves
- `--exit-code 0` : ne fait pas echouer la pipeline (mode informatif)
- `--format table` : affiche les resultats dans un tableau lisible

**Pourquoi cet outil** : pip-audit ne verifie que les packages Python. Mais notre image Docker contient aussi des packages systeme installes via `apt-get` (libcairo2, libpango, libxml2... necessaires pour WeasyPrint). Si un de ces packages systeme a une CVE, pip-audit ne le voit pas. Trivy scanne tout.

**Pourquoi exit-code 0 (pas bloquant)** : L'image de base `python:3.11-slim` (Debian) contient des centaines de packages systeme. Certains ont des CVE dans des fonctionnalites qu'on n'utilise pas. Bloquer la pipeline pour ca serait trop contraignant. On prefere etre informe et agir manuellement si c'est pertinent.

### Job 3 : `analyse-snyk` (Analyse dependances Snyk)

Ce job tourne en parallele du job 2, apres le job 1.

```yaml
- id: check
  run: |
    if [ -z "${{ secrets.SNYK_TOKEN }}" ]; then
      echo "skip=true" >> "$GITHUB_OUTPUT"
    else
      echo "skip=false" >> "$GITHUB_OUTPUT"
    fi
```

**Verification du token** : Snyk est un service commercial qui necessite un compte et un token API. Si le token n'est pas configure dans les GitHub Secrets, toutes les etapes suivantes sont ignorees avec `if: steps.check.outputs.skip == 'false'`. Ca permet a la pipeline de fonctionner meme sans compte Snyk.

**Qu'est-ce que c'est** : Snyk est un outil SCA commercial (avec un tier gratuit). Comme pip-audit, il verifie les dependances contre une base de CVE. Mais Snyk a sa propre base de vulnerabilites, souvent mise a jour plus rapidement que OSV (utilisee par pip-audit), et propose des suggestions de fix automatiques.

**Pourquoi en plus de pip-audit** : Chaque outil SCA a sa propre base de donnees. Une CVE peut etre dans la base de Snyk mais pas encore dans OSV, et inversement. Avoir deux outils SCA c'est de la defense en profondeur : si l'un rate quelque chose, l'autre peut le trouver.

### Job 4 : `analyse-sonarqube` (Analyse qualite SonarQube)

Meme principe que Snyk : le job verifie si les tokens SonarQube sont configures, et s'execute seulement si c'est le cas.

**Qu'est-ce que c'est** : SonarQube est une plateforme d'analyse de qualite et de securite du code. Elle detecte les code smells (mauvaises pratiques), la duplication de code, la complexite excessive, et les vulnerabilites de securite.

**Difference avec Semgrep/Bandit** : SonarQube est plus oriente "qualite globale" que securite pure. Il donne une note au projet (A/B/C/D/E) et suit l'evolution dans le temps. Semgrep et Bandit sont specialises securite.

---

## Pipeline 2 : Tests DAST et Fuzzing (`dast-fuzz.yml`)

### Quand elle se declenche

```yaml
on:
  workflow_dispatch:
  schedule:
    - cron: "30 2 * * 1"
```

Deux declencheurs :
- `workflow_dispatch` : manuellement depuis l'interface GitHub (onglet Actions -> "Run workflow")
- `schedule` : automatiquement chaque lundi a 2h30 UTC

**Pourquoi pas a chaque push ?** : Cette pipeline est beaucoup plus lente que la premiere. Elle doit construire les images Docker, demarrer toute la stack (Django + PostgreSQL + Nginx), attendre que l'application soit prete, puis lancer les scans. Ca prend plusieurs minutes. La lancer a chaque push serait trop lent et consommerait trop de minutes GitHub Actions.

### Job : `tests-dynamiques` (OWASP ZAP + ffuf)

#### Etape 1 : Preparation du .env

```yaml
- run: |
    cat > .env << 'EOF'
    DJANGO_SECRET_KEY=ci-only-secret-key-please-change
    DJANGO_DEBUG=False
    ...
    EOF
```

Cree un fichier `.env` temporaire pour la CI. Le vrai `.env` n'est jamais commite (il est dans `.gitignore`), donc il faut en creer un pour que l'application demarre. Les valeurs sont volontairement generiques ("ci-only-secret-key") car c'est un environnement jetable.

#### Etape 2 : Demarrage de la stack Docker

```yaml
- run: docker compose up -d --build
```

Lance `docker compose` qui demarre 3 conteneurs :
- `db` : PostgreSQL 16 (base de donnees)
- `web` : Django + Gunicorn (application)
- `nginx` : Nginx (reverse proxy)

Le `-d` lance en arriere-plan, `--build` reconstruit les images.

#### Etape 3 : Attente que l'appli soit prete

```yaml
- run: |
    for i in {1..30}; do
      if curl -fsS http://localhost/ > /dev/null 2>&1; then
        echo "Appli demarree"
        exit 0
      fi
      sleep 5
    done
    echo "L'appli n'a pas demarre a temps"
    docker compose logs --tail 200
    exit 1
```

Boucle qui teste toutes les 5 secondes si l'application repond sur `http://localhost/`. Au bout de 30 tentatives (2 min 30), si l'appli n'est toujours pas prete, on affiche les logs Docker et on echoue. C'est necessaire car les conteneurs mettent quelques secondes a demarrer (migrations de base de donnees, collecte des fichiers statiques, etc.).

#### Etape 4 : OWASP ZAP (DAST)

```yaml
- run: |
    mkdir -p reports
    chmod 777 reports
    docker run --rm --network host \
      -v "${PWD}/reports:/zap/wrk:rw" \
      -u root \
      ghcr.io/zaproxy/zaproxy:stable \
      zap-baseline.py -t http://localhost/ -r zap-report.html -J zap-report.json -I || true
```

**Qu'est-ce que c'est** : OWASP ZAP (Zed Attack Proxy) est l'outil DAST de reference, developpe par l'OWASP. Contrairement au SAST qui lit le code, le DAST teste l'application en cours d'execution. ZAP se comporte comme un attaquant : il envoie des requetes HTTP a l'application et analyse les reponses.

**Ce qu'il fait ici** :
1. On lance ZAP dans un conteneur Docker (`ghcr.io/zaproxy/zaproxy:stable`)
2. `--network host` : ZAP accede au reseau du runner, donc a `localhost` ou tourne notre appli
3. `zap-baseline.py` : mode baseline = scan rapide et non intrusif (il ne va pas essayer de supprimer des donnees)
4. `-t http://localhost/` : la cible a scanner
5. `-r zap-report.html -J zap-report.json` : genere un rapport HTML et un rapport JSON
6. `-I` : ignore les warnings (ne fait pas echouer le scan pour des findings informatifs)
7. `|| true` : meme si ZAP retourne un code d'erreur, la pipeline continue

**Pourquoi `-u root` et `chmod 777`** : Le conteneur ZAP tourne par defaut avec l'utilisateur `zap` (uid 1000). Le volume monte pour les rapports est cree par le runner GitHub avec l'utilisateur `runner`. Sans ces options, ZAP n'a pas les permissions d'ecrire les rapports.

**Ce que ZAP detecte** :
- Headers de securite manquants (X-Frame-Options, Content-Security-Policy, X-Content-Type-Options...)
- Cookies sans les flags de securite (HttpOnly, Secure, SameSite)
- Formulaires sans protection CSRF
- Informations de version exposees dans les headers HTTP
- Pages d'erreur qui revelent des informations techniques (stack traces, chemins de fichiers...)
- Redirections ouvertes
- Et bien d'autres (ZAP a des centaines de regles)

**Difference avec le SAST** : Le SAST analyse le code, le DAST teste le comportement reel. Un header de securite peut etre configure dans le code Django mais ecrase par Nginx — seul le DAST le verra. Inversement, une injection SQL dans le code sera trouvee par le SAST meme si le DAST n'a pas teste le bon endpoint.

#### Etape 5 : ffuf (Fuzzing)

```yaml
- run: |
    cat > wordlist.txt << 'EOF'
    admin
    login
    register
    api
    dashboard
    secret
    backup
    .git
    .env
    debug
    EOF
    ffuf -w wordlist.txt -u http://localhost/FUZZ -mc 200,204,301,302,307,401,403 -of json -o reports/ffuf.json || true
```

**Qu'est-ce que c'est** : ffuf (Fuzz Faster U Fool) est un outil de fuzzing web. Le fuzzing consiste a envoyer des tonnes de requetes avec des valeurs differentes pour decouvrir des choses cachees. Ici, on fait du "content discovery" : on cherche des URLs qui existent sur le serveur mais qui ne sont pas supposees etre accessibles.

**Ce qu'il fait ici** :
1. On cree une wordlist de mots a tester : `admin`, `login`, `.git`, `.env`, `backup`, etc.
2. ffuf remplace `FUZZ` dans l'URL par chaque mot : `http://localhost/admin`, `http://localhost/.git`, `http://localhost/.env`...
3. `-mc 200,204,301,302,307,401,403` : ne garde que les reponses avec ces codes HTTP (= l'URL existe)
4. Les resultats sont sauvegardes en JSON

**Pourquoi cet outil** : ZAP teste les fonctionnalites visibles de l'application (formulaires, liens). Mais il ne cherche pas les fichiers ou dossiers caches. ffuf verifie qu'on n'expose pas accidentellement :
- `/.git` : le depot Git (contient tout le code source et l'historique)
- `/.env` : le fichier d'environnement (contient les mots de passe et cles secretes)
- `/backup` : des sauvegardes
- `/debug` : des pages de debug

Si `/.env` retourne un code 200, c'est une faille critique : n'importe qui peut lire nos mots de passe.

#### Etape 6 : Sauvegarde des rapports

```yaml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: rapports-dast-fuzz
    path: reports
```

Sauvegarde les rapports ZAP et ffuf comme "artefacts" GitHub. Ils sont telechargeable depuis l'onglet Actions du repo, meme si la pipeline echoue (`if: always()`). Ca permet de consulter les resultats detailles apres l'execution.

#### Etape 7 : Arret de la stack

```yaml
- run: docker compose down -v
  if: always()
```

Arrete et supprime les conteneurs Docker et leurs volumes. Le `-v` supprime aussi les volumes de donnees (base PostgreSQL). On nettoie tout car c'est un environnement jetable.

---

## Pipeline 3 : Deploiement CD (`cd-deploy.yml`)

### Quand elle se declenche

```yaml
on:
  workflow_dispatch:
  workflow_run:
    workflows: ["Pipeline Securite CI"]
    types: [completed]
```

Deux declencheurs :
- `workflow_dispatch` : manuellement
- `workflow_run` : automatiquement quand la pipeline "Pipeline Securite CI" se termine avec succes

Ca veut dire que le deploiement ne se fait que si tous les tests de securite sont passes. C'est le principe du DevSecOps : pas de deploiement sans validation securite.

### Condition supplementaire

```yaml
if: ${{ github.event_name == 'workflow_dispatch' || github.event.workflow_run.conclusion == 'success' }}
```

Le job ne s'execute que si la pipeline de securite a reussi (`conclusion == 'success'`). Si elle a echoue, le deploiement est bloque.

### Job 1 : `build-et-push` (Construction et push image Docker)

#### Etape 1 : Connexion au registre GHCR

```yaml
- uses: docker/login-action@v3
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}
```

Se connecte au GitHub Container Registry (GHCR). C'est le registre d'images Docker integre a GitHub. `GITHUB_TOKEN` est un token automatiquement genere par GitHub pour chaque execution de pipeline.

#### Etape 2 : Build et push

```yaml
- run: |
    OWNER=$(echo "${{ github.repository_owner }}" | tr '[:upper:]' '[:lower:]')
    IMAGE="ghcr.io/${OWNER}/vulnreport:${{ github.sha }}"
    docker build -t "$IMAGE" .
    docker push "$IMAGE"
```

1. Convertit le nom du proprietaire du repo en minuscules (`tr '[:upper:]' '[:lower:]'`). Docker n'accepte pas les majuscules dans les noms d'images.
2. Construit l'image Docker avec le tag `ghcr.io/<owner>/vulnreport:<sha-du-commit>`
3. Pousse l'image sur GHCR

Le tag avec le SHA du commit permet de savoir exactement quel code est dans chaque image. On ne deploie jamais `latest`, toujours une version precise.

### Job 2 : `deploiement-serveur` (Deploiement sur le serveur)

Ce job ne demarre que si le job 1 a reussi.

#### Verification des secrets SSH

```yaml
- run: |
    if [ -z "${{ secrets.SSH_HOST }}" ] || [ -z "${{ secrets.SSH_USER }}" ] || [ -z "${{ secrets.SSH_PRIVATE_KEY }}" ]; then
      echo "skip=true" >> "$GITHUB_OUTPUT"
    else
      echo "skip=false" >> "$GITHUB_OUTPUT"
    fi
```

Verifie que les secrets SSH sont configures. Si non, le deploiement est ignore. Ca permet au repo de fonctionner sans serveur de deploiement configure.

#### Deploiement via SSH

```yaml
- uses: appleboy/ssh-action@v1.0.3
  with:
    host: ${{ secrets.SSH_HOST }}
    username: ${{ secrets.SSH_USER }}
    key: ${{ secrets.SSH_PRIVATE_KEY }}
    script: |
      docker pull <image>
      docker stop vulnreport-web || true
      docker rm vulnreport-web || true
      docker run -d --name vulnreport-web --env-file /opt/vulreport/.env -p 8000:8000 <image>
```

Se connecte au serveur de production via SSH et :
1. Telecharge la nouvelle image depuis GHCR
2. Arrete l'ancien conteneur (s'il existe)
3. Supprime l'ancien conteneur
4. Demarre un nouveau conteneur avec la nouvelle image

Le fichier `.env` de production est stocke sur le serveur (`/opt/vulreport/.env`), jamais dans le repo.

---

## Schema global : comment les 3 pipelines s'enchainent

```
Push sur main
     |
     v
+----------------------------------+
| Pipeline Securite CI             |
|                                  |
|  Job 1: Analyse code + deps     |
|    - Semgrep (SAST Django)       |
|    - Bandit (SAST Python)        |
|    - pip-audit (SCA)             |
|    - GitLeaks (secrets)          |
|         |                        |
|         v (si OK)                |
|  Job 2: Scan image Docker        |      Job 3: Snyk        Job 4: SonarQube
|    - Build image                 |        (optionnel)         (optionnel)
|    - Trivy scan                  |
+----------------------------------+
     |
     v (si tout est OK)
+----------------------------------+
| Deploiement CD                   |
|                                  |
|  Job 1: Build + push GHCR       |
|         |                        |
|         v                        |
|  Job 2: Deploy SSH (optionnel)   |
+----------------------------------+

Separement, chaque lundi :
+----------------------------------+
| Tests DAST et Fuzzing            |
|                                  |
|  - Docker Compose up             |
|  - OWASP ZAP (DAST)             |
|  - ffuf (content discovery)      |
|  - Sauvegarde rapports           |
|  - Docker Compose down           |
+----------------------------------+
```

---

## Recapitulatif des outils

| Outil | Type | Ce qu'il analyse | Ce qu'il detecte | Bloquant ? |
|-------|------|-----------------|-------------------|------------|
| Semgrep | SAST | Code source Python/Django | Injections SQL, XSS, CSRF, secrets hardcodes, patterns Django dangereux | Oui |
| Bandit | SAST | Code source Python | eval(), exec(), subprocess dangereux, hash faibles, pickle | Oui |
| pip-audit | SCA | Dependances Python (requirements.txt) | CVE connues dans les librairies Python | Oui |
| GitLeaks | Secrets | Historique Git complet | Mots de passe, cles API, tokens commites par erreur | Oui |
| Trivy | Container | Image Docker (OS + libs) | CVE dans les packages systeme et librairies de l'image | Non (informatif) |
| Snyk | SCA | Dependances Python | CVE (base proprietaire, souvent plus a jour) | Optionnel |
| SonarQube | Qualite | Code source | Code smells, duplication, complexite, vulnerabilites | Optionnel |
| OWASP ZAP | DAST | Application en execution | Headers manquants, cookies non securises, CSRF, info exposure | Non (informatif) |
| ffuf | Fuzzing | URLs du serveur | Fichiers/dossiers exposes (/.env, /.git, /backup...) | Non (informatif) |

---

## Ou voir les resultats

- **GitHub Actions** : Onglet "Actions" du repo -> cliquer sur un run -> voir les logs de chaque etape
- **Artefacts DAST** : Dans un run de "Tests DAST et Fuzzing" -> en bas de la page -> "Artifacts" -> telecharger "rapports-dast-fuzz"
- **Alertes Snyk/SonarQube** : Dans les dashboards respectifs de ces outils (si configures)

## Secrets GitHub a configurer

Dans le repo GitHub : Settings -> Secrets and variables -> Actions -> New repository secret

| Secret | Obligatoire ? | Usage |
|--------|---------------|-------|
| `SNYK_TOKEN` | Non | Active le job Snyk (SCA) |
| `SONAR_TOKEN` | Non | Active le job SonarQube |
| `SONAR_HOST_URL` | Non | URL du serveur SonarQube |
| `SSH_HOST` | Non | Active le deploiement SSH |
| `SSH_USER` | Non | Utilisateur SSH du serveur |
| `SSH_PRIVATE_KEY` | Non | Cle privee SSH |

Aucun secret n'est obligatoire. Sans eux, les jobs optionnels sont simplement ignores et la pipeline continue.
