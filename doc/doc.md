# Documentation Pipeline CI/CD - VulnReport

## C'est quoi le DevSecOps en gros ?

Le DevSecOps c'est le fait d'integrer la securite directement dans le cycle de developpement, pas a la fin quand c'est trop tard. Au lieu d'avoir une equipe secu qui audite le code une fois par an, on automatise les tests de securite dans la pipeline CI/CD pour que chaque push soit verifie.

Notre pipeline se decoupe en 3 workflows GitHub Actions :
1. **Pipeline Securite CI** - tourne a chaque push/PR sur main
2. **Tests DAST et Fuzzing** - tourne une fois par semaine (lundi 2h30) ou manuellement
3. **Deploiement CD** - se declenche automatiquement apres que la pipeline securite passe

---

## Les grandes categories de tests

### SAST (Static Application Security Testing)
= Analyse du code source SANS l'executer. On regarde le code ligne par ligne pour trouver des patterns dangereux (injections SQL, XSS, etc). C'est comme un correcteur orthographique mais pour la securite.

**Avantage** : Tres rapide, trouve les bugs tot dans le cycle de dev.
**Limite** : Peut donner des faux positifs (signaler un truc qui n'est pas vraiment un probleme), et ne voit pas les problemes qui n'apparaissent qu'a l'execution.

### SCA (Software Composition Analysis)
= Analyse des dependances (les librairies qu'on utilise). Verifie si les versions qu'on a dans requirements.txt ont des vulnerabilites connues (CVE).

**Avantage** : On utilise des dizaines de librairies, on peut pas toutes les auditer a la main.
**Limite** : Ne dit rien sur notre propre code, que sur les libs.

### DAST (Dynamic Application Security Testing)
= Test de l'application EN COURS D'EXECUTION. On lance l'appli et on l'attaque comme un vrai attaquant le ferait (requetes HTTP malveillantes, injections, etc).

**Avantage** : Trouve des problemes reels qu'on ne voit pas dans le code (mauvaise config serveur, headers manquants, etc).
**Limite** : Plus lent (faut demarrer toute la stack), et ne couvre que les endpoints qu'il connait.

### Detection de secrets
= Scan du repo git pour trouver des secrets commites par erreur (cles API, mots de passe, tokens).

---

## Correspondance avec le Plan de Developpement

Notre Plan de Dev prevoyait la stack suivante pour la securite CI/CD :
> "Bandit (SAST), pip-audit (SCA), OWASP ZAP (DAST)"
> "Snyk, Safety ou pip-audit pour scanner les dependances"
> "Bandit ou SonarQube pour detecter les mauvaises pratiques de code"
> "OWASP ZAP pour valider le comportement en conditions reelles"

Voici ce qu'on a mis en place, avec pour chaque outil s'il etait prevu ou non :

| Outil | Prevu dans le plan ? | Justification |
|-------|---------------------|---------------|
| Bandit | **Oui** - cite explicitement | SAST Python, c'etait dans la stack de base |
| pip-audit | **Oui** - cite comme option SCA | SCA gratuit et officiel PyPA |
| Snyk | **Oui** - cite comme option SCA | Deuxieme source SCA, base de CVE differente |
| SonarQube | **Oui** - cite comme option SAST | Analyse qualite + securite |
| OWASP ZAP | **Oui** - cite explicitement | DAST, test dynamique de l'appli |
| Semgrep | **Non** - ajoute en plus | Justification ci-dessous |
| GitLeaks | **Non** - ajoute en plus | Justification ci-dessous |
| Trivy | **Non** - ajoute en plus | Justification ci-dessous |
| ffuf | **Non** - ajoute en plus | Justification ci-dessous |

### Pourquoi on a ajoute des outils en plus du plan ?

Le plan de dev definissait le minimum viable. En avancant dans le projet, on s'est rendu compte que certaines zones n'etaient pas couvertes :

**Semgrep** : Le plan prevoyait "Bandit ou SonarQube" pour le SAST. On a garde Bandit ET ajoute Semgrep parce que Bandit est tres specialise Python mais ne connait pas Django. Semgrep a des regles specifiques Django (detection de raw SQL dans les vues, CSRF manquant, XSS dans les templates). Ca couvre un angle mort de Bandit. C'est le principe de defense en profondeur qu'on mentionne dans notre analyse de risques.

**GitLeaks** : Le plan mentionne dans les risques la "fuite de secrets (Git/GitHub)" comme risque majeur, et dans les bonnes pratiques "il est strictement interdit de pousser des identifiants". Mais on n'avait aucun outil pour verifier ca automatiquement. GitLeaks repond directement a ce risque identifie dans notre propre analyse. C'est la coherence entre l'analyse de risque et les mesures de mitigation.

**Trivy** : Le plan parle de "conteneurisation securisee" et du risque "images Docker vulnerables" dans l'analyse de risques. pip-audit ne verifie que les packages Python, mais notre image Docker contient aussi des packages systeme Debian (libcairo, libpango, etc pour WeasyPrint). Trivy scanne toute l'image, OS compris. Sans ca, on aurait un angle mort sur la supply chain de notre conteneur, alors que notre plan identifie ce risque.

**ffuf** : Le plan mentionne le risque de "mauvaise configuration de l'infrastructure" et "exposition de fichiers sensibles (.env)". ffuf fait du content discovery pour verifier qu'on n'expose pas des endpoints sensibles (/.env, /.git, /debug...). Ca complete ZAP qui fait du DAST sur les fonctionnalites, tandis que ffuf cherche des ressources cachees. C'est un outil de pentest classique.

**En resume** : Chaque outil ajoute repond a un risque qu'on a nous-memes identifie dans notre analyse de risques du Plan de Dev. C'est pas du rajout au hasard, c'est de la coherence.

---

## Outils utilises - Pipeline Securite CI

### 1. Bandit (SAST Python) - PREVU DANS LE PLAN

**C'est quoi** : Un outil SAST specifiquement concu pour Python, maintenu par le projet OpenStack/PyCQA. Il analyse l'AST (Abstract Syntax Tree) du code Python.

**Comment ca marche** : Il parse chaque fichier .py en arbre syntaxique et applique des plugins de detection. Chaque plugin cherche un pattern specifique (ex: utilisation de `eval`, `exec`, `pickle.loads`, etc).

**Notre config** :
```
bandit -r app -f txt -ll
```
- `-r app` : scan recursif du dossier app/
- `-f txt` : format texte pour la sortie
- `-ll` : ne montre que les issues Medium et High (ignore les Low pour eviter trop de bruit)

**Lien avec le plan** : Cite dans "Stack technique retenue" et dans "Analyse SAST : Des outils comme Bandit".

**Exemple de ce qu'il detecte** :
- B301 : `pickle.loads()` -> risque de deserialisation non securisee
- B310 : `urllib.request.urlopen(user_input)` -> SSRF potentiel
- B608 : SQL injection via string formatting

**Note** : On a du ajouter `# nosec B310` sur 2 lignes dans notre code (cve_sources.py et views.py) parce que Bandit signalait des `urlopen` qui utilisent des URLs controlees par le code, pas par l'utilisateur. C'est un faux positif.

---

### 2. Semgrep (SAST) - AJOUTE (complement de Bandit)

**C'est quoi** : Un outil d'analyse statique open-source developpe par r2c (maintenant Semgrep Inc). Il scanne le code source pour trouver des patterns de vulnerabilites.

**Comment ca marche** : On lui donne des regles (patterns a chercher) et il parcourt le code. C'est comme un grep intelligent qui comprend la structure du code (AST), pas juste du texte.

**Notre config** :
```
semgrep scan --config p/security-audit --config p/python --config p/django --config p/secrets app/
```

On utilise 4 packs de regles :
- `p/security-audit` : regles generales de securite (injections, crypto faible, etc)
- `p/python` : regles specifiques Python (eval dangereux, subprocess sans sanitize, etc)
- `p/django` : regles specifiques Django (CSRF, XSS dans les templates, raw SQL, etc)
- `p/secrets` : detection de secrets hardcodes (cles API, passwords dans le code)

**Pourquoi on l'a ajoute** : Bandit ne connait pas Django. Si on fait `cursor.execute("SELECT * FROM x WHERE id=" + request.GET['id'])` dans une vue Django, Bandit le voit. Mais si on utilise `.extra()` ou `.raw()` de l'ORM Django de maniere dangereuse, seul Semgrep avec les regles `p/django` le detecte. Notre plan dit "defense en profondeur", donc on applique ce principe a nos propres outils SAST.

**Exemple de ce qu'il detecte que Bandit ne voit pas** :
- Utilisation de `|safe` dans un template Django sans sanitization -> XSS
- `@csrf_exempt` sur une vue qui modifie des donnees -> CSRF
- `DEBUG = True` dans les settings de prod

---

### 3. pip-audit (SCA) - PREVU DANS LE PLAN

**C'est quoi** : Un outil developpe par les Python Packaging Authority (PyPA) qui verifie les dependances Python contre la base de donnees de vulnerabilites OSV (Open Source Vulnerabilities) et PyPI.

**Comment ca marche** : Il lit requirements.txt, resout les versions installees, et compare chaque package+version contre les CVE connues.

**Notre config** :
```
pip-audit -r requirements.txt
```

**Lien avec le plan** : Cite dans "Stack technique retenue" et dans "Snyk, Safety ou pip-audit pour scanner les dependances".

**Pourquoi cet outil** : C'est l'outil officiel recommande par PyPA. Gratuit, open-source, pas besoin de compte.

**Ce qu'on a du corriger** : Au debut nos dependances avaient 3 CVE. On a bumpe weasyprint (62 -> 68) et cryptography (43 -> 46.0.6) dans requirements.txt.

---

### 4. Snyk (SCA) - PREVU DANS LE PLAN

**C'est quoi** : Un service commercial (avec tier gratuit) d'analyse de dependances. Comme pip-audit mais avec une base de donnees de vulnerabilites plus large et des fonctions en plus (suggestions de fix, monitoring continu).

**Notre config** :
```
snyk test --file=requirements.txt --package-manager=pip
```

**Lien avec le plan** : Cite explicitement dans "Snyk, Safety ou pip-audit".

**Particularite** : Necessite un token (`SNYK_TOKEN`) pour fonctionner. Si le token n'est pas configure dans les secrets GitHub, l'etape est ignoree automatiquement. C'est pas bloquant pour la pipeline.

**Pourquoi en plus de pip-audit** : Snyk a sa propre base de vulnerabilites qui peut contenir des CVE que OSV (pip-audit) n'a pas encore, et inversement. Le plan dit "Snyk, Safety ou pip-audit" comme des alternatives, nous on en met deux pour la defense en profondeur.

---

### 5. GitLeaks (Detection de secrets) - AJOUTE (reponse a un risque identifie)

**C'est quoi** : Un outil qui scanne l'historique git pour trouver des secrets commites par erreur (mots de passe, cles API, tokens, etc).

**Comment ca marche** : Il utilise des expressions regulieres pour detecter des patterns de secrets dans les fichiers ET dans l'historique git (tous les commits, meme les anciens). Donc meme si tu supprimes un mot de passe dans un commit ulterieur, GitLeaks le trouve dans l'ancien commit.

**Notre config** :
```yaml
uses: gitleaks/gitleaks-action@v2
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Pourquoi on l'a ajoute** : Notre plan de dev dit textuellement :
> "Fuite de secrets (Git/GitHub) : C'est le risque majeur. Pousser par erreur un fichier .env ou des identifiants sur un depot GitHub, meme prive, est une vulnerabilite critique."
> "Il est strictement interdit de pousser des identifiants ou des fichiers .env sur les depots"

Dire "c'est interdit" c'est bien, mais sans outil pour verifier, ca repose sur la discipline humaine. GitLeaks automatise ce controle. C'est la coherence entre notre analyse de risque et nos mesures de mitigation.

**Exemple** : Si quelqu'un commit `DJANGO_SECRET_KEY=super-secret-key-12345` dans un fichier, GitLeaks le detecte et bloque la pipeline.

---

### 6. Trivy (Scan d'image Docker) - AJOUTE (couverture supply chain conteneur)

**C'est quoi** : Un scanner de vulnerabilites pour les images Docker developpe par Aqua Security. Il analyse les packages OS (apt) et les librairies applicatives dans l'image.

**Comment ca marche** : On build notre image Docker, puis Trivy l'analyse couche par couche. Il regarde les packages Debian installes, les librairies Python, et compare tout ca contre les bases de CVE.

**Notre config** :
```
trivy image --ignore-unfixed --vuln-type os,library --severity HIGH,CRITICAL --exit-code 0 --format table vulnreport:$COMMIT_SHA
```
- `--ignore-unfixed` : ignore les CVE qui n'ont pas encore de correctif (on peut rien y faire)
- `--vuln-type os,library` : scanne les packages OS et les librairies
- `--severity HIGH,CRITICAL` : ne montre que les vulnerabilites graves
- `--exit-code 0` : ne fait pas echouer la pipeline (mode informatif)

**Pourquoi on l'a ajoute** : Le plan identifie le risque :
> "Images Docker vulnerables : Utiliser des images de base non officielles ou obsoletes peut introduire des failles de securite au niveau de l'OS du conteneur."
> "Compromission de la Supply Chain (Dependances) : VulnReport repose sur un empilement de technologies."

pip-audit ne verifie que les packages Python. Mais notre Dockerfile installe aussi des packages systeme (libcairo2, libpango, libxml2... pour WeasyPrint). Trivy scanne tout : OS + Python + systeme. Sans lui, on aurait un trou dans notre couverture supply chain.

**Difference avec pip-audit** : pip-audit = packages Python seulement. Trivy = tout ce qui est dans l'image Docker (OS + libs systeme + Python).

---

### 7. SonarQube (Qualite + Securite) - PREVU DANS LE PLAN

**C'est quoi** : Une plateforme d'analyse de qualite de code. Elle verifie la qualite (code smells, duplication, complexite) ET la securite (vulnerabilites, hotspots de securite).

**Comment ca marche** : SonarQube a un serveur central qui stocke les resultats. Le scanner envoie le code au serveur qui l'analyse et genere un rapport.

**Lien avec le plan** : Cite dans "Bandit (Python) ou SonarQube pour detecter les mauvaises pratiques de code".

**Notre config** : Utilise l'action officielle SonarSource. Necessite `SONAR_TOKEN` et `SONAR_HOST_URL`. Si pas configure, l'etape est ignoree.

**Pourquoi** : C'est l'outil standard en entreprise pour le suivi de la qualite de code dans le temps. Ca donne une "note" globale au projet et suit l'evolution.

---

## Tests DAST et Fuzzing (2eme workflow)

### 8. OWASP ZAP (DAST) - PREVU DANS LE PLAN

**C'est quoi** : Le Zed Attack Proxy, developpe par l'OWASP (Open Web Application Security Project). C'est un proxy d'interception qui peut aussi servir de scanner automatise.

**Lien avec le plan** : Cite dans "Stack technique retenue" et "OWASP ZAP (DAST) pour valider le comportement en conditions reelles".

**Comment ca marche dans notre pipeline** :
1. On demarre toute la stack Docker (Django + PostgreSQL + Nginx)
2. On attend que l'appli soit accessible sur localhost
3. On lance ZAP en mode "baseline scan" contre http://localhost/
4. ZAP explore le site, envoie des requetes malveillantes, et genere un rapport

**Notre config** :
```
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost/ -r zap-report.html -J zap-report.json -I
```
- `--network host` : ZAP accede au localhost du runner (ou tourne notre appli)
- `zap-baseline.py` : mode baseline (scan rapide, pas intrusif)
- `-r / -J` : rapports HTML et JSON
- `-I` : ignore les warnings (ne fait pas echouer la pipeline)

**Pourquoi** : C'est le seul test qui attaque vraiment l'application en cours d'execution. Les SAST lisent le code, le DAST teste le comportement reel.

**Exemples de ce qu'il detecte** :
- Headers de securite manquants (X-Frame-Options, CSP, etc)
- Cookies sans flag Secure/HttpOnly
- Formulaires sans protection CSRF
- Informations de version exposees dans les headers serveur

---

### 9. ffuf (Fuzzing / Discovery) - AJOUTE (complement du DAST)

**C'est quoi** : "Fuzz Faster U Fool" - un outil de fuzzing web en Go, tres rapide. Il teste des listes de mots contre des URLs pour decouvrir des endpoints caches.

**Comment ca marche** :
```
ffuf -w wordlist.txt -u http://localhost/FUZZ -mc 200,204,301,302,307,401,403
```
- `-w wordlist.txt` : liste de mots a tester
- `FUZZ` : sera remplace par chaque mot de la liste
- `-mc` : codes HTTP a considerer comme "trouves"

Il va tester : `/admin`, `/login`, `/register`, `/api`, `/secret`, `/backup`, `/.git`, `/.env`, `/debug`...

**Pourquoi on l'a ajoute** : Le plan identifie le risque :
> "Mauvaise configuration de l'infrastructure : ports laisses ouverts, exposition de fichiers sensibles (comme le .env contenant les cles secretes)"

ZAP teste les fonctionnalites de l'appli (formulaires, authentification, etc). Mais il ne cherche pas les fichiers/dossiers caches. ffuf fait du content discovery : il verifie qu'on n'expose pas des trucs qu'on devrait pas (/.env, /.git, /debug, /backup...). C'est deux angles differents du DAST.

**Exemple de probleme** : Si `/.env` retourne un code 200, ca veut dire que notre fichier d'environnement (avec les mots de passe) est accessible publiquement.

---

## Deploiement CD (3eme workflow)

### 10. GHCR (GitHub Container Registry)

**C'est quoi** : Le registre d'images Docker integre a GitHub. Comme Docker Hub mais prive et lie au repo.

**Comment ca marche** :
1. On build l'image Docker
2. On la tag avec le SHA du commit (pour la tracabilite)
3. On la push sur ghcr.io

**Pourquoi** : Ca permet de versionner nos images Docker et de deployer exactement la meme image qui a ete testee par la pipeline de securite.

### 11. Deploiement SSH

**Comment ca marche** : On se connecte au serveur de prod via SSH, on pull la nouvelle image, et on relance le container.

**Securite** : Les credentials SSH sont stockees dans les GitHub Secrets (jamais dans le code). Si les secrets ne sont pas configures, l'etape est ignoree.

---

## Ce qui est dans le plan mais pas encore mis en place

**Prometheus / Grafana** : Le plan mentionne dans les mesures de mitigation "Supervision (Prometheus/Grafana) : mise en place d'alertes sur les comportements anormaux". C'est pas encore fait, c'etait prevu en P3 (priorite basse). Ca servirait a monitorer l'appli en prod (alertes sur les pics de connexions echouees, usage CPU/RAM, etc). Pour l'instant on a le dashboard admin Django qui affiche les stats Docker mais c'est pas du vrai monitoring.

---

## Comment tout s'enchaine

```
Push sur main
    |
    v
Pipeline Securite CI
    |
    +-- Semgrep (SAST)          <- ajoute, complete Bandit sur Django
    +-- Bandit (SAST)           <- prevu dans le plan
    +-- pip-audit (SCA)         <- prevu dans le plan
    +-- GitLeaks (secrets)      <- ajoute, repond au risque "fuite de secrets"
    |
    v (si l'etape precedente passe)
    +-- Trivy (scan image)      <- ajoute, couvre la supply chain Docker
    +-- Snyk (SCA - optionnel)  <- prevu dans le plan
    +-- SonarQube (optionnel)   <- prevu dans le plan
    |
    v (si tout passe)
Deploiement CD
    |
    +-- Build image Docker
    +-- Push sur GHCR
    +-- Deploy via SSH (si configure)
```

Le DAST tourne separement chaque semaine :
```
Lundi 2h30 (ou declenchement manuel)
    |
    v
Tests DAST et Fuzzing
    +-- Docker Compose up (stack complete)
    +-- OWASP ZAP (DAST)        <- prevu dans le plan
    +-- ffuf (discovery)        <- ajoute, verifie les fichiers exposes
    +-- Upload rapports
    +-- Docker Compose down
```

---

## Questions qu'on pourrait me poser

**Q: Pourquoi Semgrep alors que c'est pas dans votre plan de dev ?**
R: Le plan prevoyait Bandit comme SAST. Mais Bandit ne connait pas le framework Django. Semgrep a des regles specifiques pour Django (XSS dans les templates, CSRF, raw SQL via l'ORM). On a applique le principe de defense en profondeur de notre propre analyse de risques : plusieurs couches de detection qui se completent.

**Q: Pourquoi avoir plusieurs outils SCA (pip-audit + Snyk) ?**
R: Le plan listait les trois comme des alternatives ("Snyk, Safety ou pip-audit"). On en a garde deux parce que chacun a sa propre base de vulnerabilites. pip-audit utilise OSV (base open-source), Snyk a sa base proprietaire. Une CVE peut etre dans l'une et pas dans l'autre. C'est de la defense en profondeur.

**Q: Pourquoi GitLeaks alors que c'est pas dans le plan ?**
R: Le plan identifie la fuite de secrets comme "le risque majeur" dans l'analyse de risques des outils. Il dit aussi "il est strictement interdit de pousser des identifiants". GitLeaks automatise cette verification. Sans lui, on comptait sur la discipline humaine, ce qui est pas suffisant en securite.

**Q: Pourquoi Trivy alors que vous avez deja pip-audit ?**
R: pip-audit ne verifie que les packages Python. Mais notre image Docker installe aussi des packages systeme (libcairo, libpango, libxml2 pour WeasyPrint). Si un de ces packages systeme a une CVE, pip-audit ne le voit pas. Trivy scanne tout le contenu de l'image. Le plan identifie le risque "images Docker vulnerables" donc c'est coherent.

**Q: Pourquoi ffuf en plus de ZAP ?**
R: ZAP fait du DAST classique (il teste les fonctionnalites). ffuf fait du content discovery (il cherche des fichiers/dossiers caches). Ce sont deux approches complementaires. ZAP va tester si le formulaire de login est vulnerable, ffuf va verifier qu'on n'a pas laisse un /.env ou /.git accessible.

**Q: Pourquoi Trivy ne fait pas echouer la pipeline ?**
R: On a mis `exit-code 0` parce que l'image de base Debian peut avoir des CVE dans des packages systeme qu'on n'utilise pas directement. On prefere etre informe sans bloquer le deploiement. Si on voit un HIGH/CRITICAL sur un package qu'on utilise vraiment, on intervient manuellement.

**Q: C'est quoi la difference entre SAST et DAST ?**
R: SAST analyse le code source sans l'executer (white-box), DAST teste l'application en cours d'execution (black-box). SAST trouve les bugs dans le code, DAST trouve les problemes de configuration et de comportement reel.

**Q: Pourquoi le DAST ne tourne pas a chaque push ?**
R: C'est beaucoup plus lent (faut build les images, demarrer Docker Compose, attendre que l'appli demarre, scanner...). Ca prendrait trop longtemps pour chaque push. Une fois par semaine c'est suffisant pour detecter les regressions.

**Q: Comment on gere les faux positifs ?**
R: On utilise des annotations dans le code. Par exemple `# nosec B310` pour dire a Bandit d'ignorer un warning specifique sur une ligne. On le fait que quand on est sur que c'est un faux positif (URL controlee par le code, pas par l'utilisateur). On documente pourquoi dans le code.

**Q: Pourquoi utiliser GitHub Actions et pas Jenkins/GitLab CI ?**
R: Notre code est sur GitHub donc c'est le plus simple. Pas besoin de maintenir un serveur CI separe. C'est gratuit pour les repos publics et les repos prives ont des minutes gratuites.

**Q: C'est quoi un CVE ?**
R: Common Vulnerabilities and Exposures. C'est un identifiant unique pour chaque vulnerabilite connue (ex: CVE-2024-3094). Ca permet de referencer une faille de maniere standard. Les outils SCA comparent nos dependances contre cette base.

**Q: Pourquoi les secrets sont dans GitHub Secrets et pas dans le code ?**
R: Si les secrets sont dans le code (meme dans un .env commite), n'importe qui avec acces au repo peut les voir. GitHub Secrets sont chiffres et injectes uniquement pendant l'execution de la pipeline. Meme les admins du repo ne peuvent pas les relire une fois entres.

**Q: Et Prometheus/Grafana, c'etait pas prevu ?**
R: Si, c'est dans les mesures de mitigation du plan ("Supervision Prometheus/Grafana"). On ne l'a pas encore mis en place, c'etait en priorite basse. Pour l'instant la supervision se fait via le dashboard admin Django qui affiche les stats des conteneurs Docker. C'est une amelioration possible pour une prochaine iteration.

**Q: Votre plan parle d'images Alpine/Distroless, vous utilisez quoi ?**
R: On utilise python:3.11-slim (base Debian). On a choisi slim plutot qu'Alpine parce que certaines dependances de WeasyPrint (libcairo, libpango) sont plus compliquees a installer sur Alpine (faut compiler depuis les sources). Slim est un bon compromis : plus leger que l'image complete, mais compatible avec apt.

---

## Ou voir les modifs sur le site

Comptes dispo : `admin` / `pentester` / `viewer` — mot de passe : `VulnReport2025!`

| Fonctionnalite | Ou la trouver |
|---|---|
| Ajout finding manuel | Page d'un rapport -> section "Ajouter un finding" -> bouton vert "Ajouter manuellement" |
| Ajout finding depuis KB | Meme section -> liste des fiches KB en dessous, cliquer sur une fiche -> formulaire pre-rempli |
| Filtres rapports | Page d'accueil `/` -> barre de recherche en haut (texte + statut + severite) |
| Filtres KB | Page `/kb/` -> barre de filtres (mot-cle + categorie + CVE) |
| Severity CRITICAL | Creation/edition d'un finding -> select severite -> 4 niveaux (Low, Medium, High, Critical) |
| Categories KB OWASP | Page `/kb/` -> select categorie dans les filtres (Injection, XSS, Broken Auth, etc.) |
| Comptes seed | Se deconnecter et tester les 3 roles (admin/pentester/viewer) |
| Headers securite nginx | DevTools (F12) -> Network -> Response Headers (X-Frame-Options, X-Content-Type-Options, etc.) |
