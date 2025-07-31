class SecurityPrompts:
    """Collection de prompts optimisés pour l'analyse de sécurité avec DeepSeek-R1"""
    
    def get_security_analysis_prompt(self) -> str:
        """Prompt principal pour l'analyse de sécurité optimisé pour DeepSeek-R1"""
        return """
<thinking>
Je vais analyser ce code pour identifier les vulnérabilités de sécurité. Je dois être précis et éviter les faux positifs tout en détectant les vraies failles de sécurité basées sur OWASP Top 10.
</thinking>

Tu es un expert en cybersécurité spécialisé dans l'analyse de code. Analyse le fichier suivant pour identifier les vulnérabilités de sécurité réelles.

**Fichier à analyser:** {filename}

**Code:**
```
{code}
```

**Instructions précises:**
1. Recherche UNIQUEMENT les vraies vulnérabilités de sécurité
2. Base-toi sur les critères OWASP Top 10 2021
3. Évite absolument les faux positifs
4. Analyse le contexte avant de signaler une vulnérabilité

**Vulnérabilités à détecter:**
- A01: Broken Access Control
- A02: Cryptographic Failures  
- A03: Injection (SQL, NoSQL, OS, LDAP)
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging Failures
- A10: Server-Side Request Forgery (SSRF)

**Format de réponse obligatoire:**
Pour chaque vulnérabilité réelle trouvée:
```
TYPE: [nom_exact_vulnerabilite]
SEVERITY: [critical|high|medium|low]
DESCRIPTION: [description_claire_et_precise]
LINE: [numero_ligne_si_applicable]
---
```

Si aucune vulnérabilité n'est trouvée, réponds exactement: "NO_VULNERABILITIES_FOUND"

**Important:** Ne signale une vulnérabilité que si tu es certain qu'elle représente un risque de sécurité réel.
"""

    def get_dependency_analysis_prompt(self) -> str:
        """Prompt pour l'analyse des dépendances avec DeepSeek-R1"""
        return """
<thinking>
Je dois analyser ces dépendances pour identifier celles qui ont des vulnérabilités connues. Je vais me concentrer sur les versions qui ont des CVE documentées.
</thinking>

Analyse les dépendances suivantes pour identifier les packages avec des vulnérabilités de sécurité connues:

**Fichier de dépendances:**
```
{dependencies}
```

**Instructions:**
1. Identifie les packages avec des versions vulnérables connues
2. Vérifie les CVE et failles de sécurité documentées
3. Évalue la criticité basée sur l'impact potentiel

**Format de réponse:**
```
VULNERABLE_PACKAGE: [nom_package]
VERSION: [version_actuelle]
SEVERITY: [critical|high|medium|low]
CVE: [numéro_cve_ou_reference]
DESCRIPTION: [description_vulnerabilite]
RECOMMENDATION: [version_recommandee]
---
```

Si aucune vulnérabilité n'est trouvée: "NO_VULNERABLE_DEPENDENCIES"
"""

    def get_code_quality_prompt(self) -> str:
        """Prompt pour l'analyse de qualité sécurisée"""
        return """
<thinking>
Je vais évaluer ce code du point de vue de la sécurité en cherchant les mauvaises pratiques qui peuvent mener à des vulnérabilités.
</thinking>

Évalue la qualité sécuritaire du code suivant:

**Code à analyser:**
```
{code}
```

**Critères d'évaluation:**
1. Gestion sécurisée des erreurs
2. Validation et sanitisation des entrées
3. Gestion des secrets et credentials
4. Pratiques cryptographiques
5. Contrôles d'accès et permissions
6. Logging sécurisé

**Format de réponse:**
```
SECURITY_ISSUE: [description_probleme]
SEVERITY: [critical|high|medium|low]
CATEGORY: [input_validation|crypto|access_control|error_handling|logging]
RECOMMENDATION: [comment_corriger]
---
```

Si le code respecte les bonnes pratiques: "CODE_SECURITY_GOOD"
"""

    def get_secret_detection_prompt(self) -> str:
        """Prompt spécialisé pour la détection de secrets"""
        return """
<thinking>
Je dois identifier les secrets, clés API, mots de passe ou tokens qui pourraient être exposés dans ce code. Je dois éviter les faux positifs comme les exemples ou placeholders.
</thinking>

Analyse ce code pour détecter des secrets, credentials ou informations sensibles exposées:

**Code:**
```
{code}
```

**Types de secrets à détecter:**
- Clés API (AWS, Google, GitHub, etc.)
- Mots de passe hardcodés
- Tokens d'authentification
- Certificats et clés privées
- Chaînes de connexion base de données
- Secrets cryptographiques

**Format de réponse:**
```
SECRET_TYPE: [api_key|password|token|certificate|db_connection|crypto_key]
PATTERN: [pattern_détecté_masqué]
SEVERITY: [critical|high|medium|low]
LOCATION: [ligne_ou_variable]
RISK: [description_du_risque]
---
```

Si aucun secret exposé: "NO_SECRETS_FOUND"

**Important:** Ignore les exemples, tests unitaires et placeholders évidents.
"""
