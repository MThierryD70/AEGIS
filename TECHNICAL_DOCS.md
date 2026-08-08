# Documentation Technique — AEGIS Antivirus (Python + C++)

**Version :** 1.0.0
**Auteur :** MASRA Thierry D.
**Dernière mise à jour :** 2026-08

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture globale](#2-architecture-globale)
3. [Modules Python](#3-modules-python)
4. [Moteur C++ (aegis_cpp)](#4-moteur-c-aegis_cpp)
5. [Compilation C++ (MSYS2 / MinGW)](#5-compilation-c-msys2--mingw)
6. [Configuration](#6-configuration)
7. [Base de données de signatures](#7-base-de-données-de-signatures)
8. [Flux d'exécution détaillé](#8-flux-dexécution-détaillé)
9. [Heuristique — seuils et indicateurs](#9-heuristique--seuils-et-indicateurs)
10. [Règles YARA](#10-règles-yara)
11. [Rapports](#11-rapports)
12. [Tests et validation](#12-tests-et-validation)
13. [Fichiers générés et .gitignore](#13-fichiers-générés-et-gitignore)
14. [Feuille de route](#14-feuille-de-route)
15. [Références](#15-références)

---

## 1. Vue d'ensemble

AEGIS est un antivirus à base de signatures, développé en Python avec un moteur C++
haute performance lié via `pybind11`. Les deux composants critiques du scan — le hachage
MD5/SHA-256 et le lookup de signatures — sont portés en C++ et se replient automatiquement
sur des implémentations Python pures si le module compilé est indisponible.

### Principes directeurs

- **Modularité** : chaque composant (scanner, détection, quarantaine, rapport, config) est un package indépendant.
- **Détection multi-couches** : signatures, heuristique PE et règles YARA s'additionnent.
- **Repli transparent** : C++ si disponible, Python sinon — même interface (`AegisHasher`, `AegisBloomMatcher`).
- **Anti-faux-positifs** : heuristique limitée aux fichiers PE, YARA limité aux sévérités `critical`/`high`.
- **Robustesse** : chemins accentués (UTF-8 → UTF-16), alias Windows ignorés, fichiers trop gros ignorés avant hachage.

### Composition de la détection

| Couche | Module | Menace si |
|--------|--------|-----------|
| Signatures | `core/aegis_engine.py` → Bloom C++ + `db/signature_db.py` | hash connu |
| Heuristique | `detection/heuristic.py` | score ≥ 1.0 (PE uniquement) |
| YARA | `detection/yara_scanner.py` | règle de sévérité `critical` ou `high` |

---

## 2. Architecture globale

```
┌───────────────────────────────────────────────────────────────┐
│                    CLI (Click) — aegis/cli.py                  │
│  scan · update · quarantine · build · setup · generate-test   │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                 ScannerEngine (scanner/engine.py)              │
│   FileWalker → AegisHasher → AegisBloomMatcher                 │
│                                → HeuristicAnalyzer             │
│                                → YaraScanner                   │
└──────┬──────────────────┬──────────────────┬───────────────────┘
       │                  │                  │
┌──────▼──────┐   ┌───────▼───────┐   ┌──────▼──────────┐
│  core/      │   │  detection/   │   │  db/            │
│  aegis_     │   │  heuristic    │   │  signature_db   │
│  engine     │   │  yara_scanner │   │  (SQLite)       │
│  (C++⇄Py)   │   └───────────────┘   └─────────────────┘
└─────────────┘
       │
┌──────▼───────────────────────────────────────────────────────┐
│  QuarantineManager · ReportGenerator · Updater · Logger      │
└──────────────────────────────────────────────────────────────┘
        Services : Config (YAML) · setup/checker · build/*
```

### Couches architecturales

| Couche | Rôle |
|--------|------|
| Interface | `cli.py` — commandes utilisateur, options, affichage |
| Scanner Engine | Coordonne parcours, hachage et dispatch vers les détections |
| Détection | Signatures (Bloom+SQLite), heuristique PE, YARA |
| Actions | Quarantaine (move/restore/delete), rapports JSON/CSV |
| Services | Config YAML, logger rich+fichier, updater, build C++ |

---

## 3. Modules Python

### 3.1 `scanner/engine.py` — Scanner Engine

Composant central. Instancie le walker, la DB, le matcher (Bloom), l'heuristique et le scanner YARA, puis orchestre le scan.

```python
class ScannerEngine:
    def __init__(self, config: Config):
        self.walker = FileWalker(config)
        self.db = SignatureDB(config.database.path)
        self.matcher = AegisBloomMatcher(self.db)   # C++ si possible
        self.heuristic = HeuristicAnalyzer()
        self.yara_scanner = YaraScanner("data/yara_rules")
        log_status()                                # C++ chargé ou fallback Python

    def scan(self, path: str) -> ScanReport:
        for file_path in self.walker.walk(path):
            result = self._analyze(file_path)
            report.results.append(result)
            if result.is_threat:
                logger.warning(f"MENACE : {result.threat_name} → {file_path}")
```

**Types de données :**

```python
@dataclass
class FileResult:
    path: Path
    hashes: Optional[dict]
    match_result: MatchResult
    heuristic_result: HeuristicResult = None
    yara_result: YaraResult = None

    @property
    def is_threat(self) -> bool:        # OU logique des 3 couches
    @property
    def threat_name(self) -> str:       # nom selon la source (signature / YARA / "Heuristique")
    @property
    def threat_severity(self) -> str:   # sévérité selon la source

@dataclass
class ScanReport:
    results: List[FileResult]
    duration_seconds: float
    @property total_scanned / threats_found / threats
```

**Progression** : `PROGRESS_EVERY = 75` — un message de log toutes les 75 fichiers analysés
pour éviter l'impression d'un scan bloqué sur les gros fichiers.

### 3.2 `scanner/walker.py` — File Walker

Énumération récursive par `os.scandir` (les métadonnées taille/type sont fournies par l'OS
gratuitement, sans appel système supplémentaire par fichier).

**Filtres appliqués, dans l'ordre (cheap → coûteux) :**
1. **Extension** — `path.suffix.lower() not in config.scanner.extensions` → ignoré
2. **Taille** — `st_size > max_file_size_mb * 1024 * 1024` → ignoré **avant** tout hachage
3. **Alias Windows** — fichiers de taille 0 avec attribut `FILE_ATTRIBUTE_REPARSE_POINT` (0x400)
   (alias WindowsApps illisibles, `Errno 22`) → ignorés
4. **Exclusions** — `exclude_paths` de la config (testé seulement si la liste est non vide)

**Optimisations OneDrive :**
- Pas de `Path.resolve()` par fichier (bloquant sur les reparse points « cloud ») : il n'est appelé
  que si `exclude_paths` est non vide.
- `_is_windows_alias` n'est testé que pour les fichiers de taille 0.

### 3.3 `scanner/hasher.py` — Hash Calculator (fallback Python)

```python
BLOCK_SIZE = 65536  # 64 Ko

class HashCalculator:
    @staticmethod
    def compute(path: Path) -> Optional[dict]:
        md5, sha256 = hashlib.md5(), hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(BLOCK_SIZE):
                md5.update(chunk); sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
        # None si PermissionError / OSError (fichier ignoré)
```

### 3.4 `core/aegis_engine.py` — Pont C++ ⇄ Python

Charge `aegis_cpp.pyd` depuis `cpp/bin/` et enregistre les DLL dépendantes via `os.add_dll_directory`
(runtime MinGW/MSYS2 : `libstdc++-6.dll`, `libssl-3-x64.dll`, …). Recherche dans :
1. `cpp/bin/`
2. `C:\msys64\mingw64\bin` (détecté par `Msys2Detector`)
3. `C:\Program Files\mingw64\bin` (legacy)

```python
class AegisHasher:
    @staticmethod
    def compute(path):       # C++ si _cpp chargé, sinon HashCalculator Python
class AegisBloomMatcher:
    def __init__(self, db):  # SignatureMatcher SQLite en fallback
    def _load_bloom(self):   # db.get_all_hashes() → _cpp.bloom_load(hashes)
    def check(self, hashes):
        # 1) _cpp.bloom_check(hash) en RAM  → si probablement présent :
        # 2) self.db.lookup(hash) en SQLite → confirmation sans faux positif
    def reload(self):        # recharger le filtre après un `update`
```

### 3.5 `detection/signature_matcher.py` — Signature Matcher (fallback)

```python
@dataclass
class MatchResult:
    is_threat: bool
    malware_name: Optional[str] = None
    severity: Optional[int] = None       # 1..4
    matched_hash: Optional[str] = None
    hash_type: Optional[str] = None      # 'md5' | 'sha256'

class SignatureMatcher:
    def check(self, hashes: dict) -> MatchResult:
        for hash_type, hash_value in hashes.items():
            result = self.db.lookup(hash_value)
            if result is not None:
                return MatchResult(is_threat=True, ...)
```

### 3.6 `detection/heuristic.py` — Heuristic Analyzer

Analyse **uniquement les fichiers PE** (`.exe`, `.dll`). Détails complets en section 9.

```python
ENTROPY_THRESHOLD = 7.0          # entropie « dense » (PE uniquement)
ENTROPY_SAMPLE_SIZE = 4 * 1024 * 1024   # échantillon de 4 Mo, 1 seule passe
SUSPICIOUS_SCORE_THRESHOLD = 1.0 # score minimal pour « suspect »
```

### 3.7 `detection/yara_scanner.py` — YARA

```python
THREAT_SEVERITIES = {"critical", "high"}  # seules ces sévérités = MENACE

class YaraScanner:
    def __init__(self, rules_dir):   # compile tous les *.yar en une fois
    def scan(self, path) -> YaraResult:
        # tente rules.match(str(path)) ; sur échec (codepage ANSI de l'API C de
        # YARA avec chemins accentués) → lit les octets et rules.match(data=...)
```

`YaraResult` : `is_threat`, `matched_rules` (liste), `severity`.

### 3.8 `db/signature_db.py` — Signature Database (SQLite)

```sql
CREATE TABLE IF NOT EXISTS signatures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_type     TEXT NOT NULL,          -- 'md5' | 'sha256'
    hash_value    TEXT NOT NULL UNIQUE,   -- stocké en minuscules
    malware_name  TEXT NOT NULL,
    severity      INTEGER DEFAULT 1       -- 1=low .. 4=critical
);
CREATE INDEX IF NOT EXISTS idx_hash_value ON signatures (hash_value);
```

**API :** `add_signature(...)` (False si doublon `IntegrityError`), `lookup(hash_value)`,
`count()`, `remove_signature(hash_value)`, `get_all_hashes()` (pour charger le Bloom).

### 3.9 `quarantine/manager.py` — Quarantine Manager

Déplace le fichier vers `quarantine/` et enregistre dans `quarantine/quarantine.db` :

```sql
CREATE TABLE quarantine (
    id               TEXT PRIMARY KEY,     -- uuid4
    original_path    TEXT NOT NULL,
    quarantine_path  TEXT NOT NULL,
    malware_name     TEXT,
    severity         INTEGER,
    date_quarantined TEXT NOT NULL
);
```

**API :** `quarantine(path, malware_name, severity)` → `quarantine_id | None`,
`restore(id)` (recrée le dossier parent), `delete(id)`, `list_quarantined()`.

### 3.10 `reporting/generator.py` — Report Generator

- **Console** : résumé (fichiers analysés, menaces, durée) + tableau `rich` (fichier / statut / menace / sévérité).
- **JSON** : `reports/scan_YYYYMMDD_HHMMSS.json` — résumé + résultats (chemin, menace, sévérité, hashes).
- **CSV** : `reports/scan_YYYYMMDD_HHMMSS.csv` — colonnes `fichier, est_menace, malware, severite, md5, sha256`.

### 3.11 `updater/updater.py` — Updater

- `import_from_file(json_path)` : lit le JSON AEGIS et insère les signatures (doublons ignorés).
- `import_from_url(url)` : téléchargement `httpx` (timeout 60 s, follow_redirects),
  vérification d'intégrité via `url + ".sha256"` (si disponible, `--no-verify` pour désactiver),
  détection du format :
  - JSON direct (`{...}` ou `[...]`)
  - CSV MalwareBazaar (lignes `#` / virgules) → conversion automatique via `_convert_malware_signature_list_csv_to_json`
  - fichier temporaire `data/tmp_update.json` puis import, et suppression.
- `status()` : nombre de signatures + chemin de la base.

### 3.12 `config/manager.py` — Config

Dataclasses typées (`ScannerConfig`, `DatabaseConfig`, `QuarantineConfig`, `LoggingConfig`)
chargées depuis `config.yaml` par `Config.from_yaml()`. Si le fichier est absent,
des valeurs par défaut sont utilisées.

### 3.13 `logger/logger.py` — Logger

`RichHandler` (couleurs, horodatage `HH:MM:SS`) sur console + `FileHandler` UTF-8 vers
`logs/aegis.log`. `setup_logger(config)` est idempotent (évite les handlers dupliqués).
Helpers : `log_section`, `log_blank`, `log_success`, `log_failure`, `log_warning_inline`.

### 3.14 `setup/checker.py` — DependencyChecker

Vérifie la version Python puis les dépendances obligatoires (adaptées par OS pour
`python-magic` / `python-magic-bin`) avec installation automatique (`aegis setup`),
et signale les dépendances optionnelles (`fastapi`, `uvicorn`).

### 3.15 `build/` — Chaînes de compilation

| Module | Rôle |
|--------|------|
| `detector.py` | `EnvironmentDetector` — détecte g++, cmake, OpenSSL, MinGW classique |
| `builder.py` | `CppBuilder` — configuration + build CMake, vérification du `.pyd` |
| `msys2_detector.py` | `Msys2Detector` — détecte `C:\msys64\mingw64\bin`, paquets pacman, générateur |
| `msys2_builder.py` | `Msys2CppBuilder` — build via MSYS2 (cmake/ninja de MSYS2, PATH injecté) |

---

## 4. Moteur C++ (aegis_cpp)

Source : `cpp/src/aegis_module.cpp` — module `pybind11` unique `aegis_cpp`.

### 4.1 Hashing (OpenSSL EVP)

- Lecture via `CreateFileW` (Unicode) : conversion UTF-8 → UTF-16 dans le module,
  donc **chemins accentués supportés**.
- `compute_hashes(filepath) -> {"md5": ..., "sha256": ...}` avec EVP (MD5 + SHA-256),
  blocs de 64 Ko.

### 4.2 Bloom Filter

| Paramètre | Valeur |
|-----------|--------|
| Taille | `BLOOM_SIZE = 9 600 000` bits (≈ 1,2 Mo… ~9,6 Mo pour 1 M de hashes) |
| Nb de fonctions de hachage | `NUM_HASHES = 7` |
| Hash | FNV-1a (seed par index, multiplicateur constant) |

- `bloom_init()`, `bloom_add(hash)`, `bloom_check(hash)` (False = absent **avec certitude**),
  `bloom_load(hashes)`, `bloom_bit_count()`.
- Le filtre ne contient **que** des hashes : la confirmation finale reste en SQLite
  (`AegisBloomMatcher.check`), ce qui élimine les faux positifs du Bloom.

### 4.3 Chargement Python

`core/aegis_engine.py` charge le `.pyd` (sys.path `cpp/bin`), ajoute les DLL au
`add_dll_directory` (runtime MSYS2), et expose `AegisHasher` / `AegisBloomMatcher`.
Si `_cpp is None` → fallback Python silencieux (message au démarrage).

---

## 5. Compilation C++ (MSYS2 / MinGW)

### 5.1 Chaîne MSYS2 (recommandée)

Avantages : chemins sans espaces (`C:\msys64\mingw64\bin`), outils cohérents, ninja fourni.

```bash
# Dans le terminal « MSYS2 MINGW64 » :
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl

# Dans cmd (PATH utilisateur), puis rouvrir le terminal :
setx PATH "C:\msys64\mingw64\bin;%PATH%"
```

Racines détectées : `C:/msys64`, `C:/msys2`, `C:/tools/msys64`
(surcharge possible via la variable d'environnement `AEGIS_MSYS2_ROOT`).
Environnements : `mingw64` > `ucrt64` > `clang64`. Générateur : `Ninja` si présent, sinon `MinGW Makefiles`.

### 5.2 Chaîne de secours (MinGW classique)

winlibs g++ + CMake + OpenSSL dans `C:\Program Files\...` — géré par `EnvironmentDetector`
(chemins courts 8.3 via `GetShortPathNameW` pour éviter les espaces dans le cache CMake).

### 5.3 Build

```bash
aegis build compile            # ou : aegis build compile --force
aegis build status             # état détaillé des outils et modules
python msys2_build.py compile  # variante script
```

Le `CMakeLists.txt` :
- exige `pybind11` (CONFIG) et Python ; OpenSSL via `-DOPENSSL_INCLUDE_DIR`,
  `-DOPENSSL_SSL_LIBRARY`, `-DOPENSSL_CRYPTO_LIBRARY` (détectés par le builder) ;
- copie le `.pyd` final dans `cpp/bin/` (POST_BUILD).

Le module `.pyd` dépend des DLL runtime MSYS2 (`libstdc++-6.dll`, `libssl-3-x64.dll`, …)
qui doivent rester accessibles : `C:\msys64\mingw64\bin` dans le PATH, sinon `cpp/bin/`
(copie locale générée).

---

## 6. Configuration

`config.yaml` — le seul fichier de configuration :

```yaml
scanner:
  extensions: [".exe", ".dll", ".js", ".pdf", ".com", ".png"]
  max_file_size_mb: 100
  exclude_paths: []               # ex: ["C:/Windows/System32"]

database:
  path: "./data/signatures.db"

quarantine:
  dir: "./quarantine"
  encrypt: false                  # réservé — chiffrement non implémenté

logging:
  level: "INFO"                   # DEBUG | INFO | WARNING | ERROR
  file: "./logs/aegis.log"
```

Champs par défaut si le fichier est absent : extensions `[".exe", ".dll"]`, taille 100 Mo,
base `./data/signatures.db`, quarantaine `./quarantine`, log `./logs/aegis.log`.

---

## 7. Base de données de signatures

### 7.1 Format JSON (import)

```json
{
  "version": "2026.05.23",
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

### 7.2 Format CSV MalwareBazaar (fetch URL)

`aegis update fetch <url>` convertit automatiquement le CSV MalwareBazaar
(colonnes `#first_seen,sha256_hash,md5_hash,...`) en signatures `sha256` + `md5`
(sévérité 4), nom du malware depuis la colonne signature.

### 7.3 Contenu initial du dépôt

`data/malwarebazaar_signatures.json` — 3208 signatures (dont EICAR),
importées automatiquement par `install.py` (étape 5). La base SQLite `data/signatures.db`
est **générée** et exclue de git.

---

## 8. Flux d'exécution détaillé

```
Utilisateur → aegis scan /chemin [--json] [--csv] [--quarantine]
    │
    ▼
ScannerEngine.scan(path)
    │
    ├── FileWalker.walk(path)
    │       os.scandir récursif
    │       ├── extension autorisée ?  sinon → ignoré
    │       ├── taille ≤ 100 Mo ?      sinon → ignoré
    │       ├── alias Windows ?        sinon → ignoré
    │       └── exclusion ?            sinon → ignoré
    │
    ├── Pour chaque fichier retenu :
    │     ├── AegisHasher.compute(file)
    │     │       C++ (OpenSSL)  OU  Python (hashlib)
    │     │       → {"md5": "...", "sha256": "..."}  OU None (illisible)
    │     │
    │     ├── AegisBloomMatcher.check(hashes)
    │     │       ├── Bloom C++ (probablement présent ?)
    │     │       └── SQLite lookup (confirmation)
    │     │       → MatchResult
    │     │
    │     ├── HeuristicAnalyzer.analyze(file)     # .exe/.dll uniquement
    │     │       → HeuristicResult(score, indicators)
    │     │
    │     ├── YaraScanner.scan(file)
    │     │       → YaraResult(matched_rules, severity)   # alerte si critical/high
    │     │
    │     └── FileResult(path, hashes, match, heuristic, yara)
    │
    ├── Si is_threat : log "MENACE : <threat_name> → <chemin>"
    ├── Progression log toutes les 75 fichiers
    │
    ├── Rapport console (rich)
    ├── Si --json : reports/scan_<ts>.json
    ├── Si --csv  : reports/scan_<ts>.csv
    └── Si --quarantine : QuarantineManager.quarantine(chaque menace)
```

---

## 9. Heuristique — seuils et indicateurs

Applicable **uniquement** à `.exe` / `.dll` (constante `PE_EXTENSIONS`). Un PDF, une image
ou un ZIP n'est jamais « suspect » par la seule entropie (faux positifs éliminés).

| Constante | Valeur | Sens |
|-----------|--------|------|
| `ENTROPY_THRESHOLD` | 7.0 | entropie « dense » |
| `ENTROPY_SAMPLE_SIZE` | 4 Mo | échantillon 1 seule passe |
| `SUSPICIOUS_SCORE_THRESHOLD` | 1.0 | score minimal pour « suspect » |
| `WEIGHT_ENTROPY` | 0.4 | entropie ≥ 7.0 |
| `WEIGHT_PACKED` | 0.5 | packing (sections UPX/ASPack/… ou point d'entrée dans la dernière section) |
| `WEIGHT_RWX_SECTION` | 0.5 | section exécutable + écriture + lecture |
| `WEIGHT_SUSPICIOUS_IMPORTS` | 0.6 | combinaison d'imports Windows |

Imports suspects (combinaisons) :

```python
SUSPICIOUS_IMPORTS = [
    {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"},
    {"CryptEncrypt", "InternetConnect"},
    {"RegSetValueEx", "ShellExecute", "DownloadFile"},
]
```

Un score ≥ 1.0 exige de **combiner plusieurs indicateurs** (ex. entropie + packing),
ce qui limite fortement les faux positifs sur des exécutables légitimes mais denses.

---

## 10. Règles YARA

`data/yara_rules/test_rules.yar` — compilées au démarrage du `YaraScanner` :

| Règle | Sévérité | Détection |
|-------|----------|-----------|
| `EICAR_Test_File` | `critical` | chaîne EICAR standard |
| `Packed_Executable_UPX` | `medium` | `MZ` @0 + taille > 1 Ko + sections `UPX0`/`UPX1` |
| `Suspicious_Script` | `medium` | 2 motifs parmi `eval(base64_decode)`, `eval(gzinflate)`, `fromCharCode` |

Seules les sévérités `critical` et `high` (`THREAT_SEVERITIES`) déclenchent une alerte ;
les règles `medium`/`low` sont loggées en info. Une règle trop large ne doit pas produire
de faux positifs en cascade.

---

## 11. Rapports

`--json` et `--csv` écrivent dans `reports/` (dossier créé à la volée) avec horodatage.

**JSON** :
```json
{
  "scan_date": "2026-08-08T...",
  "summary": { "total_scanned": 331, "threats_found": 1, "duration_seconds": 5.47 },
  "results": [
    { "path": "C:/.../eicar.com", "is_threat": true,
      "malware_name": "EICAR_Test_File", "severity": "critical",
      "hashes": { "md5": "...", "sha256": "..." } }
  ]
}
```

**CSV** : `fichier, est_menace, malware, severite, md5, sha256`

---

## 12. Tests et validation

### 12.1 Test EICAR (validation rapide)

```bash
aegis generate-test                      # crée Tests/Malwares_test/eicar.com
aegis scan Tests/Malwares_test/          # → MENACE : EICAR_Test_File
```

Windows Defender supprime EICAR à la création : mettre `Tests/Malwares_test/` en exclusion
temporaire (Windows Sécurité) pour tester.

### 12.2 Validation d'installation

`install.py` (étape 5/5) vérifie : base de signatures (nb d'entrées), hasher (hash de
`config.yaml`), CLI (`python aegis.py --help`).

### 12.3 Tests pas à pas (développement)

`Tests/Tests_par_etape/` — scripts `test_etap_N.py` / `.bash` validant les étapes de
développement (squelette, walker, hasher, DB, matcher, heuristique, quarantaine, CLI,
updater, build C++…). Fichiers d'exemples dans `Tests/Tests_par_etape/test_files/`
(document.pdf, programme.exe, script.js, suspect.exe, …).

### 12.4 Métriques observées

| Métrique | Valeur constatée |
|----------|------------------|
| Scan répertoire de cours (331 fichiers) | ≈ 5,5 s |
| Ignore d'un fichier > 100 Mo | ≈ 2 ms |
| Hasher C++ | ×4 vs Python |
| Bloom Matcher | ×4 vs SQLite direct |

---

## 13. Fichiers générés et .gitignore

Fichiers/dossiers créés à l'installation ou à l'usage, exclus du dépôt (`.gitignore`) :

| Élément | Généré par |
|---------|-----------|
| `__pycache__/`, `*.pyc` | interpréteur Python |
| `aegis_antivirus.egg-info/` | `pip install -e .` |
| `cpp/build/`, `cpp/old_build/`, `cpp/bin/*.pyd`, `cpp/bin/*.dll` | build C++ (CMake) |
| `cpp/build.bat`, `cpp/bin/hasher.dll`, `cpp/bin/bloom_matcher.dll` | ancien build (legacy) |
| `data/signatures.db` | `install.py` / updater |
| `data/old_sample_signatures.json`, `data/Imports signatures/` | workspace (inutilisé) |
| `data/tmp_updater.json`, `data/tmp_update.json` | updater (fichiers temporaires) |
| `logs/`, `cpp/logs/` | logger |
| `quarantine/` | quarantaine (fichiers + `quarantine.db`) |
| `reports/` | `aegis scan --json/--csv` |
| `.venv/`, `venv/`, `env/` | environnements virtuels |
| `Tests/Tests_par_etape/`, `Tests/Malwares_test/` | tests (non publiés) |

---

## 14. Feuille de route

- [x] **Hasher C++** — OpenSSL EVP, Unicode, bloc 64 Ko (×4 vs Python)
- [x] **Bloom Matcher C++** — FNV-1a ×7, 9,6 M bits, confirmation SQLite (×4 vs SQLite)
- [x] **Heuristique PE** — packing, RWX, imports, entropie (anti-faux-positifs)
- [x] **YARA** — règles par sévérité (`critical`/`high` = alerte)
- [x] **Updater** — import JSON local / URL, conversion CSV MalwareBazaar, vérification SHA-256
- [x] **Build MSYS2** — chaîne recommandée + secours MinGW + repli Python pur
- [ ] Walker C++ multi-thread (parcours parallèle)
- [ ] Multithreading du scan (pool de workers)
- [ ] Chiffrement réel de la quarantaine (`cryptography`/Fernet — champ `encrypt` prévu)
- [ ] API REST (dépendances optionnelles `fastapi`/`uvicorn` déclarées)

---

## 15. Références

- **YARA documentation** : https://yara.readthedocs.io
- **pefile documentation** : https://github.com/erocarrera/pefile
- **pybind11 documentation** : https://pybind11.readthedocs.io
- **OpenSSL EVP (hashing)** : https://docs.openssl.org/master/man3/EVP_DigestInit/
- **EICAR test file** : https://www.eicar.org/download-anti-malware-testfile/
- **MalwareBazaar (export de signatures)** : https://bazaar.abuse.ch
- **MSYS2** : https://www.msys2.org
- **Bloom filter (concept)** : https://en.wikipedia.org/wiki/Bloom_filter
- **Shannon entropy in malware** : https://practicalsecurityanalytics.com/file-entropy/

---

*Ce document est une référence vivante : mettez à jour les versions des dépendances, les
métriques et la feuille de route à chaque évolution du projet.*


