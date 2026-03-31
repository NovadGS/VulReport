from django.core.management.base import BaseCommand

from core.models import KnowledgeBase, KBCategory, SeverityLevel


OWASP_TOP10 = [
    {
        "name": "A01:2021 - Broken Access Control",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.HIGH,
        "description": "Contrôles d'accès insuffisants permettant à un attaquant d'accéder à des ressources ou actions non autorisées.",
        "recommendation": "Implémenter un contrôle d'accès côté serveur systématique, basé sur l'identité et le rôle, avec une politique par défaut de refus.",
        "references": "OWASP Top 10 2021 A01; https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    {
        "name": "A02:2021 - Cryptographic Failures",
        "category": KBCategory.CRYPTO,
        "default_severity": SeverityLevel.HIGH,
        "description": "Données sensibles exposées en transit ou au repos à cause d'algorithmes faibles, d'absence de chiffrement ou d'une mauvaise gestion des clés.",
        "recommendation": "Appliquer TLS à jour, chiffrer les données sensibles au repos avec des algorithmes modernes et protéger rigoureusement les clés.",
        "references": "OWASP Top 10 2021 A02; https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    {
        "name": "A03:2021 - Injection",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.HIGH,
        "description": "Données non fiabilisées sont envoyées à un interpréteur (SQL, OS, LDAP, etc.) et permettent l'exécution de commandes arbitraires.",
        "recommendation": "Utiliser des requêtes paramétrées, éviter la concaténation de chaînes et valider strictement toutes les entrées.",
        "references": "OWASP Top 10 2021 A03; https://owasp.org/Top10/A03_2021-Injection/",
    },
    {
        "name": "A04:2021 - Insecure Design",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.MEDIUM,
        "description": "Faiblesses structurelles dans la conception de l'application qui créent des risques, même si l'implémentation est correcte.",
        "recommendation": "Intégrer la modélisation de menace et les patterns de conception sécurisée dès les premières phases du cycle de vie.",
        "references": "OWASP Top 10 2021 A04; https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    {
        "name": "A05:2021 - Security Misconfiguration",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.MEDIUM,
        "description": "Mauvaises configurations (fonctionnalités inutiles, messages d'erreur verbeux, réglages par défaut) ouvrant la surface d'attaque.",
        "recommendation": "Automatiser les déploiements, appliquer des configurations minimales et durcies, et désactiver les fonctions non nécessaires.",
        "references": "OWASP Top 10 2021 A05; https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    {
        "name": "A06:2021 - Vulnerable and Outdated Components",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.HIGH,
        "description": "Librairies, frameworks ou composants d'infrastructure présentant des vulnérabilités connues.",
        "recommendation": "Maintenir un inventaire SBOM, surveiller les avis de sécurité et mettre à jour les composants dès que possible.",
        "references": "OWASP Top 10 2021 A06; https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    {
        "name": "A07:2021 - Identification and Authentication Failures",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.HIGH,
        "description": "Authentification faible (mots de passe, sessions, MFA) permettant à un attaquant d'usurper l'identité d'utilisateurs.",
        "recommendation": "Implémenter des politiques de mots de passe robustes, la MFA et une gestion sûre des sessions.",
        "references": "OWASP Top 10 2021 A07; https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    {
        "name": "A08:2021 - Software and Data Integrity Failures",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.MEDIUM,
        "description": "Mécanismes insuffisants pour garantir l'intégrité du code et des données (CI/CD, mises à jour, désérialisation).",
        "recommendation": "Signer les artefacts, vérifier les chaînes de confiance et restreindre la désérialisation à des formats sûrs.",
        "references": "OWASP Top 10 2021 A08; https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    {
        "name": "A09:2021 - Security Logging and Monitoring Failures",
        "category": KBCategory.NETWORK,
        "default_severity": SeverityLevel.MEDIUM,
        "description": "Journalisation et surveillance insuffisantes empêchant la détection et la réponse rapide aux incidents de sécurité.",
        "recommendation": "Centraliser et corréler les journaux, définir des alertes et tester régulièrement les scénarios d'incident.",
        "references": "OWASP Top 10 2021 A09; https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    {
        "name": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "category": KBCategory.WEB,
        "default_severity": SeverityLevel.MEDIUM,
        "description": "Capacité pour un attaquant de forcer le serveur à initier des requêtes vers des systèmes internes ou externes non prévus.",
        "recommendation": "Valider et filtrer strictement les URL côté serveur, et segmenter le réseau pour limiter l'impact.",
        "references": "OWASP Top 10 2021 A10; https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
    },
]


class Command(BaseCommand):
    help = "Charge les entrées OWASP Top 10 dans la base de connaissance."

    def handle(self, *args, **options):
        created_count = 0
        for item in OWASP_TOP10:
            obj, created = KnowledgeBase.objects.get_or_create(
                name=item["name"],
                defaults={
                    "category": item["category"],
                    "default_severity": item["default_severity"],
                    "description": item["description"],
                    "recommendation": item["recommendation"],
                    "references": item["references"],
                },
            )
            if created:
                created_count += 1
        self.stdout.write(self.style.SUCCESS(f"{created_count} entrées OWASP Top 10 créées (ou déjà présentes)."))

