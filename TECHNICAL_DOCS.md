# Documentation Technique — Antivirus à base de signatures (Python → C++)

**Version :** 1.0  
**Auteur :** Projet personnel  
**Dernière mise à jour :** 2026-04

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture globale](#2-architecture-globale)
3. [Modules Python](#3-modules-python)
4. [Bibliothèques et outils](#4-bibliothèques-et-outils)
5. [Structure des répertoires](#5-structure-des-répertoires)
6. [Base de données de signatures](#6-base-de-données-de-signatures)
7. [Flux d'exécution détaillé](#7-flux-dexécution-détaillé)
8. [API REST (optionnel)](#8-api-rest-optionnel)
9. [Feuille de route C++](#9-feuille-de-route-c)
10. [Étapes de développement](#10-étapes-de-développement)
11. [Tests et validation](#11-tests-et-validation)
12. [Références](#12-références)

---

## 1. Vue d'ensemble

Ce projet est un antivirus pédagogique et extensible, conçu en deux phases :

- **Phase 1 (Python)** — prototype fonctionnel avec détection par signatures de hachage (MD5, SHA-256) et règles YARA, gestion de quarantaine, rapports et interface CLI.
- **Phase 2 (C++)** — remplacement progressif des composants critiques (scanner, moteur YARA) par des modules C++ liés à Python via `pybind11` ou `ctypes`, pour des performances proches d'un antivirus professionnel.

### Principes directeurs

- **Modularité** : chaque composant est indépendant et interchangeable.
- **Extensibilité** : nouveaux modules de détection ajoutables sans modifier le cœur.
- **Testabilité** : couverture de tests unitaires et d'intégration dès la phase Python.
- **Séparation des couches** : détection, quarantaine, reporting et configuration sont strictement découplés.

---

## 2. Architecture globale

```
┌──────────────────────────────────────────────────────────────┐
│                  Interfaces utilisateur                       │
│         CLI (Click/Argparse)    REST API (FastAPI)           │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│                  Scanner Engine (core)                        │
│     File Walker · Hash Calculator · Orchestration            │
└───────┬──────────────────┬──────────────────┬────────────────┘
        │                  │                  │
┌───────▼──────┐  ┌────────▼──────┐  ┌────────▼──────────────┐
│  Signature   │  │  Heuristic    │  │   Signature DB         │
│  Matcher     │  │  Analyzer     │  │   (SQLite/JSON)        │
│  MD5/SHA256  │  │  Entropie     │  │   Updater intégré      │
│  YARA rules  │  │  Patterns     │  │                        │
└───────┬──────┘  └────────┬──────┘  └────────────────────────┘
        │                  │
┌───────▼──────────────────▼──────────────────────────────────┐
│           Report Generator    │    Quarantine Manager        │
│           JSON/CSV/Console    │    Move/Encrypt/Restore      │
└─────────────────────────────────────────────────────────────┘
                Services transversaux
         Config Manager · Logger · Updater · Scheduler
```

### Couches architecturales

| Couche | Rôle |
|--------|------|
| Interface | Reçoit les commandes utilisateur (scan, update, restore…) |
| Scanner Engine | Coordonne le parcours des fichiers et dispatch les analyses |
| Détection | Identifie les menaces par plusieurs méthodes |
| Actions | Exécute les réponses (quarantaine, rapport) |
| Services | Fournit les fonctions transversales (log, config, mise à jour) |

---

## 3. Modules Python

### 3.1 `scanner/engine.py` — Scanner Engine

Composant central qui orchestre le scan. Il instancie le `FileWalker`, calcule les empreintes, et délègue aux modules de détection.

```python
class ScannerEngine:
    def __init__(self, config: Config):
        self.config = config
        self.signature_db = SignatureDB(config.db_path)
        self.matcher = SignatureMatcher(self.signature_db)
        self.heuristic = HeuristicAnalyzer()
        self.quarantine = QuarantineManager(config.quarantine_dir)
        self.reporter = ReportGenerator()

    def scan_path(self, path: str) -> ScanReport:
        results = []
        for file in FileWalker(path, self.config.extensions):
            result = self._analyze_file(file)
            if result.is_threat:
                self.quarantine.quarantine(file)
            results.append(result)
        return self.reporter.generate(results)

    def _analyze_file(self, file: Path) -> FileResult:
        hashes = HashCalculator.compute(file)
        sig_match = self.matcher.check(hashes)
        heuristic_match = self.heuristic.analyze(file)
        return FileResult(file, sig_match, heuristic_match)
```

### 3.2 `scanner/walker.py` — File Walker

Parcourt récursivement un répertoire ou analyse un fichier unique. Supporte les filtres par extension, taille maximale, et liste d'exclusions.

**Responsabilités :**
- Parcours récursif avec `os.walk` ou `pathlib.Path.rglob`
- Filtrage par extension (`.exe`, `.dll`, `.pdf`, `.js`, etc.)
- Exclusion de chemins système ou utilisateur
- Gestion des erreurs de permission (`PermissionError`)

### 3.3 `scanner/hasher.py` — Hash Calculator

Calcule les empreintes cryptographiques d'un fichier. Utilise la lecture par blocs pour les fichiers volumineux.

```python
import hashlib

class HashCalculator:
    BLOCK_SIZE = 65536

    @staticmethod
    def compute(path: Path) -> dict:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(HashCalculator.BLOCK_SIZE):
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
```

### 3.4 `detection/signature_matcher.py` — Signature Matcher

Compare les empreintes d'un fichier contre la base de données de signatures. Supporte également les règles YARA pour la détection par patterns.

**Méthodes de détection :**
- Comparaison de hash MD5/SHA-256 contre la DB
- Correspondance de règles YARA sur le contenu binaire
- (Phase 2) Comparaison de hash fuzzy via `ssdeep`

### 3.5 `detection/heuristic.py` — Heuristic Analyzer

Détecte des comportements suspects sans signature préétablie.

**Indicateurs analysés :**
- **Entropie de Shannon** — valeur élevée (> 7.0) = contenu probablement chiffré ou packé
- **Ratio sections PE suspectes** — sections exécutables avec peu de chaînes lisibles
- **Imports PE suspects** — combinaisons d'API Windows liées à l'injection de code
- **Scripts obfusqués** — détection de `eval(base64_decode(...))` et patterns similaires

```python
def shannon_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    frequency = [data.count(b) / len(data) for b in set(data)]
    return -sum(p * math.log2(p) for p in frequency if p > 0)
```

### 3.6 `db/signature_db.py` — Signature Database

Abstraction de la base de données. Supporte SQLite (développement) et JSON plat (distribution légère).

**Schéma SQLite :**
```sql
CREATE TABLE signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_type   TEXT NOT NULL,        -- 'md5' | 'sha256'
    hash_value  TEXT NOT NULL UNIQUE,
    malware_name TEXT NOT NULL,
    severity    INTEGER DEFAULT 1,    -- 1=low, 2=medium, 3=high, 4=critical
    added_date  TEXT,
    source      TEXT
);

CREATE TABLE yara_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name   TEXT NOT NULL,
    rule_content TEXT NOT NULL,
    enabled     INTEGER DEFAULT 1,
    last_updated TEXT
);
```

### 3.7 `quarantine/manager.py` — Quarantine Manager

Isole les fichiers infectés en les déplaçant dans un répertoire sécurisé, optionnellement chiffrés.

**Fonctions :**
- `quarantine(path)` — déplace et enregistre dans `quarantine.db`
- `restore(quarantine_id)` — remet le fichier à son emplacement d'origine
- `delete(quarantine_id)` — suppression définitive
- Chiffrement optionnel avec `cryptography` (Fernet)

### 3.8 `reporting/generator.py` — Report Generator

Produit des rapports dans plusieurs formats.

**Formats supportés :**
- Console (coloré avec `rich`)
- JSON (pour intégration avec d'autres outils)
- CSV (pour analyse en tableur)
- HTML (rapport visuel, optionnel)

### 3.9 `config/manager.py` — Config Manager

Charge la configuration depuis un fichier YAML et la fusionne avec les arguments CLI.

```yaml
# config.yaml
scanner:
  extensions: [".exe", ".dll", ".js", ".pdf", ".docm"]
  max_file_size_mb: 100
  threads: 4
  exclude_paths:
    - "C:/Windows/System32"

database:
  path: "./data/signatures.db"
  auto_update: true
  update_url: "https://your-update-server/signatures"

quarantine:
  dir: "./quarantine"
  encrypt: true

logging:
  level: "INFO"
  file: "./logs/antivirus.log"
  max_size_mb: 10
  backup_count: 5
```

### 3.10 `updater/updater.py` — Updater

Met à jour la base de signatures depuis un serveur distant.

**Fonctionnement :**
- Téléchargement via `httpx` avec vérification de signature (SHA-256)
- Format de mise à jour : JSON delta (seulement les nouvelles signatures)
- Rollback automatique en cas d'échec d'intégrité

---

## 4. Bibliothèques et outils

### 4.1 Dépendances Python principales

| Bibliothèque | Version | Usage |
|---|---|---|
| `yara-python` | ≥ 4.3 | Moteur de règles YARA |
| `pefile` | ≥ 2023.2 | Parsing des exécutables Windows (PE) |
| `python-magic` | ≥ 0.4 | Détection du type MIME réel |
| `click` | ≥ 8.0 | Interface CLI déclarative |
| `pyyaml` | ≥ 6.0 | Lecture de la configuration |
| `rich` | ≥ 13.0 | Affichage console coloré et tables |
| `httpx` | ≥ 0.25 | Requêtes HTTP pour les mises à jour |
| `cryptography` | ≥ 41.0 | Chiffrement des fichiers en quarantaine |
| `ssdeep` | ≥ 3.4 | Hash fuzzy (similarité de fichiers) |
| `fastapi` | ≥ 0.100 | API REST (optionnel) |
| `uvicorn` | ≥ 0.23 | Serveur ASGI pour FastAPI |
| `pytest` | ≥ 7.0 | Tests unitaires |
| `pytest-cov` | ≥ 4.0 | Couverture de code |

### 4.2 Installation

```bash
# Environnement virtuel
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Dépendances
pip install -r requirements.txt

# Dépendances système (Linux)
sudo apt-get install libmagic1 libfuzzy-dev

# Dépendances système (Windows)
# Installer Visual C++ Build Tools pour ssdeep
```

### 4.3 `requirements.txt`

```
yara-python>=4.3.0
pefile>=2023.2.7
python-magic>=0.4.27
click>=8.1.7
pyyaml>=6.0.1
rich>=13.7.0
httpx>=0.25.2
cryptography>=41.0.7
ssdeep>=3.4
fastapi>=0.104.1
uvicorn>=0.24.0
pytest>=7.4.3
pytest-cov>=4.1.0
```

---

## 5. Structure des répertoires

```
antivirus/
├── antivirus/                  # Package principal
│   ├── __init__.py
│   ├── cli.py                  # Point d'entrée CLI (Click)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py           # Orchestrateur principal
│   │   ├── walker.py           # Parcours de fichiers
│   │   └── hasher.py           # Calcul d'empreintes
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── signature_matcher.py
│   │   ├── heuristic.py
│   │   └── yara_scanner.py
│   ├── db/
│   │   ├── __init__.py
│   │   ├── signature_db.py
│   │   └── models.py
│   ├── quarantine/
│   │   ├── __init__.py
│   │   └── manager.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   └── generator.py
│   ├── updater/
│   │   ├── __init__.py
│   │   └── updater.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── manager.py
│   └── api/                    # API REST optionnelle
│       ├── __init__.py
│       └── routes.py
├── data/
│   ├── signatures.db           # Base SQLite des signatures
│   └── yara_rules/             # Fichiers .yar
│       ├── malware.yar
│       └── packer.yar
├── quarantine/                 # Dossier de quarantaine
├── logs/
├── tests/
│   ├── unit/
│   │   ├── test_hasher.py
│   │   ├── test_matcher.py
│   │   └── test_heuristic.py
│   ├── integration/
│   │   └── test_scan_flow.py
│   └── samples/                # Fichiers EICAR de test
│       └── eicar.com
├── config.yaml
├── requirements.txt
├── setup.py
└── README.md
```

---

## 6. Base de données de signatures

### 6.1 Format JSON (simple)

```json
{
  "version": "2026.04.01",
  "signatures": [
    {
      "hash_type": "sha256",
      "hash_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "malware_name": "EICAR-Test-File",
      "severity": 4
    }
  ]
}
```

### 6.2 Format YARA (exemple)

```yara
rule EICAR_Test_File {
    meta:
        description = "Standard EICAR test file"
        author = "EICAR"
        severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PE_Packer {
    meta:
        description = "Détecte des packers PE génériques"
    strings:
        $upx = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        uint16(0) == 0x5A4D and ($upx or $upx1)
}
```

---

## 7. Flux d'exécution détaillé

```
Utilisateur → CLI : scan /chemin/vers/répertoire
    │
    ▼
ScannerEngine.scan_path("/chemin")
    │
    ├── FileWalker → génère liste de fichiers filtrés
    │
    ├── Pour chaque fichier :
    │     ├── HashCalculator.compute(file)
    │     │       → {"md5": "...", "sha256": "..."}
    │     │
    │     ├── SignatureMatcher.check(hashes)
    │     │       → Requête SQLite sur signatures
    │     │       → Scan YARA sur contenu
    │     │       → SigMatchResult(matched=True/False, name, severity)
    │     │
    │     ├── HeuristicAnalyzer.analyze(file)
    │     │       → Calcul entropie
    │     │       → Parsing PE (si .exe/.dll)
    │     │       → HeuristicResult(score, indicators)
    │     │
    │     ├── Si menace détectée :
    │     │       → QuarantineManager.quarantine(file)
    │     │             Déplace vers /quarantine/<uuid>
    │     │             Enregistre dans quarantine.db
    │     │
    │     └── FileResult(path, hashes, sig_result, heuristic_result)
    │
    └── ReportGenerator.generate(results)
              → Console (rich table)
              → scan_report_YYYYMMDD.json
```

---

## 8. API REST (optionnel)

Exposée via FastAPI pour intégration avec des outils externes (dashboard, SIEM).

### Endpoints

| Méthode | Route | Description |
|---------|-------|-------------|
| `POST` | `/scan/file` | Analyse un fichier uploadé |
| `POST` | `/scan/path` | Lance un scan sur un chemin serveur |
| `GET` | `/quarantine` | Liste les fichiers en quarantaine |
| `POST` | `/quarantine/{id}/restore` | Restaure un fichier |
| `DELETE` | `/quarantine/{id}` | Supprime définitivement |
| `POST` | `/update` | Déclenche une mise à jour des signatures |
| `GET` | `/status` | Santé du service et stats |

### Exemple de requête

```bash
curl -X POST http://localhost:8000/scan/file \
  -F "file=@suspicious.exe" \
  | python -m json.tool
```

### Exemple de réponse

```json
{
  "filename": "suspicious.exe",
  "sha256": "a3f5b2...",
  "is_threat": true,
  "detections": [
    {
      "method": "signature",
      "malware_name": "Trojan.GenericKD.12345",
      "severity": 3,
      "confidence": 1.0
    },
    {
      "method": "heuristic",
      "indicators": ["high_entropy", "suspicious_imports"],
      "score": 0.82
    }
  ],
  "quarantined": true,
  "scan_duration_ms": 47
}
```

---

## 9. Feuille de route C++

### 9.1 Objectif

Remplacer les modules Python critiques en termes de performance par des extensions C++ liées à Python, sans modifier l'architecture ni les interfaces.

### 9.2 Modules à porter en C++

| Module Python | Module C++ | Gain estimé |
|---|---|---|
| `hasher.py` | `cpp/hasher.cpp` | ×5–10 sur fichiers > 10 Mo |
| `signature_matcher.py` | `cpp/matcher.cpp` | ×3–5 (SIMD, bloom filter) |
| `yara_scanner.py` | Utilise `libyara` directement | ×2–4 |
| `walker.py` | `cpp/walker.cpp` | ×2–3 sur arborescences larges |

### 9.3 Liaison Python-C++

**Option A : `pybind11` (recommandé)**

```cpp
// cpp/hasher.cpp
#include <pybind11/pybind11.h>
#include <openssl/sha.h>

namespace py = pybind11;

std::string sha256_file(const std::string& path) {
    // implémentation C++ rapide
}

PYBIND11_MODULE(hasher_cpp, m) {
    m.def("sha256_file", &sha256_file, "Compute SHA-256 of a file");
}
```

```python
# Python — usage transparent
try:
    from hasher_cpp import sha256_file  # C++ si disponible
except ImportError:
    from .hasher import sha256_file     # fallback Python
```

**Option B : `ctypes`** (pas de compilation nécessaire côté Python)

```python
import ctypes
lib = ctypes.CDLL("./libhasher.so")
lib.sha256_file.restype = ctypes.c_char_p
result = lib.sha256_file(path.encode())
```

### 9.4 Build System C++

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(eagis_cpp)

find_package(pybind11 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED yara)

pybind11_add_module(hasher_cpp cpp/hasher.cpp)
target_link_libraries(hasher_cpp PRIVATE OpenSSL::Crypto)

pybind11_add_module(matcher_cpp cpp/matcher.cpp)
target_link_libraries(matcher_cpp PRIVATE ${YARA_LIBRARIES})
```

---

## 10. Étapes de développement

### Phase 1 — Prototype Python fonctionnel

**Étape 1 : Squelette et configuration**
- Créer la structure de répertoires
- Implémenter `Config Manager` (YAML + CLI)
- Implémenter `Logger` avec rotation

**Étape 2 : Core scanner**
- Implémenter `FileWalker` avec filtres
- Implémenter `HashCalculator` (MD5, SHA-256)
- Créer la structure de données `FileResult`

**Étape 3 : Base de signatures**
- Créer le schéma SQLite
- Implémenter `SignatureDB` (CRUD)
- Charger la signature EICAR pour les tests

**Étape 4 : Détection par signatures**
- Implémenter `SignatureMatcher` (hash lookup)
- Intégrer `yara-python` pour les règles YARA
- Tests unitaires avec EICAR

**Étape 5 : Analyse heuristique**
- Implémenter le calcul d'entropie de Shannon
- Implémenter le parsing PE avec `pefile`
- Définir les seuils et scores

**Étape 6 : Quarantaine et rapports**
- Implémenter `QuarantineManager`
- Implémenter `ReportGenerator` (JSON, console `rich`)

**Étape 7 : CLI**
- Commandes : `scan`, `update`, `quarantine list`, `quarantine restore`
- Barre de progression avec `rich`

**Étape 8 : Updater**
- Téléchargement et vérification des mises à jour
- Mise à jour delta de la base SQLite

### Phase 2 — Migration C++

**Étape 9 : Hasher C++**
- Porter `hasher.py` en C++ avec OpenSSL
- Binding `pybind11`
- Tests de régression (mêmes sorties que Python)

**Étape 10 : Matcher C++ avec Bloom filter**
- Structure Bloom filter pour lookup O(1) des hashes
- Porter la logique de matching

**Étape 11 : Intégration libyara native**
- Lier directement `libyara` depuis C++
- Multithreading avec `std::thread` ou `OpenMP`

**Étape 12 : File Walker C++ multi-thread**
- Parcours parallèle avec pool de threads
- Benchmark et optimisation

---

## 11. Tests et validation

### 11.1 Test avec EICAR

Le fichier EICAR est le standard de test antivirus. Son hash SHA-256 est connu et invariant.

```python
# tests/unit/test_matcher.py
def test_eicar_detection():
    db = SignatureDB(":memory:")
    db.add_signature("sha256",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File", severity=4)
    matcher = SignatureMatcher(db)
    result = matcher.check({"sha256": "275a021b..."})
    assert result.matched == True
    assert result.malware_name == "EICAR-Test-File"
```

### 11.2 Tests de performance

```python
# tests/integration/test_performance.py
import time

def test_scan_1000_files():
    engine = ScannerEngine(Config())
    start = time.perf_counter()
    engine.scan_path("tests/samples/")
    duration = time.perf_counter() - start
    assert duration < 10.0  # moins de 10 secondes pour 1000 fichiers
```

### 11.3 Métriques cibles (Phase 1 Python)

| Métrique | Cible |
|----------|-------|
| Vitesse de scan | > 100 fichiers/seconde |
| Faux positifs | < 0.01% |
| Temps de démarrage | < 1 seconde |
| Empreinte mémoire | < 150 Mo |

### 11.4 Métriques cibles (Phase 2 C++)

| Métrique | Cible |
|----------|-------|
| Vitesse de scan | > 1 000 fichiers/seconde |
| Empreinte mémoire | < 80 Mo |
| Latence scan fichier unique | < 5 ms |

---

## 12. Références

- **YARA documentation** : https://yara.readthedocs.io
- **pefile documentation** : https://github.com/erocarrera/pefile
- **pybind11 documentation** : https://pybind11.readthedocs.io
- **libyara C API** : https://yara.readthedocs.io/en/stable/capi.html
- **EICAR test file** : https://www.eicar.org/download-anti-malware-testfile/
- **ClamAV (référence open-source)** : https://www.clamav.net
- **OpenSSL (hashing C++)** : https://docs.openssl.org/master/man3/EVP_DigestInit/
- **Shannon entropy in malware** : https://practicalsecurityanalytics.com/file-entropy/
- **MalwareBazaar (samples de test)** : https://bazaar.abuse.ch

---

*Ce document est une référence vivante. Mettre à jour les versions des dépendances et les métriques à chaque jalon de développement.*
