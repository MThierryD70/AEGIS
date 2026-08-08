<p align="center">
  <img src="logo.png" alt="AEGIS Antivirus" width="300">
</p>

<h1 align="center">🛡 AEGIS Antivirus</h1>

<p align="center">
  Antivirus à base de signatures avec moteur C++ haute performance.<br>
  Python + <code>pybind11</code> · Signatures · Heuristique PE · YARA
</p>

---

## ✨ Fonctionnalités

- **Détection par signatures** — MD5 / SHA-256 via Bloom Filter C++ en RAM, confirmées par la base SQLite
- **Analyse heuristique** — exécutables packés, sections RWX, imports suspects, entropie élevée (fichiers PE uniquement)
- **Règles YARA** — personnalisables dans `data/yara_rules/` (seules les sévérités `critical`/`high` déclenchent une alerte)
- **Moteur C++ `aegis_cpp`** (pybind11) avec **repli automatique en Python pur** si non compilé
- **Quarantaine** — liste, restauration et suppression des fichiers isolés
- **Rapports** — console (`rich`), JSON et CSV dans `reports/`
- **Mise à jour des signatures** — import depuis un fichier JSON local ou une URL (JSON et CSV MalwareBazaar)
- **Installation et build C++ automatisés** — chaîne MSYS2 recommandée, secours MinGW classique

---

## 📋 Prérequis

- **Python 3.10+** — [télécharger](https://www.python.org/downloads/)
- **MSYS2** *(optionnel — pour les performances C++)* — [télécharger](https://www.msys2.org)

---

## 🚀 Installation

```bash
git clone https://github.com/MThierryD70/AEGIS.git
cd AEGIS
python install.py
```

Le script `install.py` enchaîne automatiquement :

| Étape | Action |
|-------|--------|
| 1/5 | Vérification de la version Python (3.10+) |
| 2/5 | Installation de `rich` (bootstrap du logger) |
| 3/5 | Installation des dépendances Python puis du package (`pip install -e .`) |
| 4/5 | Compilation des modules C++ *(optionnel — repli Python pur si impossible)* |
| 5/5 | Import des signatures initiales et validation de l'installation |

### Alternative manuelle

```bash
pip install -e .            # installe les dépendances + la commande `aegis`
python install.py           # ou python aegis.py si l'éditable n'est pas fait
```

---

## ▶ Lancement

Après installation, deux façons de lancer AEGIS :

```bash
# Commande directe (recommandée — si Scripts/ est dans votre PATH)
aegis --help

# Alternatives universelles
python aegis.py scan <chemin>
aegis.bat scan <chemin>
```

---

## 🧩 Commandes disponibles

### Scan

```bash
aegis scan <chemin>                      # scan fichier ou répertoire
aegis scan <chemin> --json               # + rapport JSON dans reports/
aegis scan <chemin> --csv                # + rapport CSV dans reports/
aegis scan <chemin> --quarantine         # + mise en quarantaine auto des menaces
```

### Mise à jour des signatures

```bash
aegis update import signatures.json      # import depuis un fichier JSON local
aegis update fetch https://.../signatures.json   # import depuis une URL (JSON ou CSV MalwareBazaar)
aegis update fetch <url> --no-verify     # désactive la vérification d'intégrité SHA-256
aegis update status                      # nombre de signatures en base
```

### Quarantaine

```bash
aegis quarantine list                    # liste les fichiers isolés
aegis quarantine restore <id>            # restaure un fichier à son emplacement
aegis quarantine delete <id>             # suppression définitive
```

### Modules C++

```bash
aegis build compile                      # compile aegis_cpp (hasher + bloom filter)
aegis build compile --force              # force la recompilation
aegis build status                       # état de l'environnement et des modules
```

### Dépendances et test

```bash
aegis setup                              # vérifie et installe les dépendances manquantes
aegis setup --no-install                 # vérifie sans installer
aegis generate-test                      # génère Tests/Malwares_test/eicar.com
```

> L'outil d'aide `msys2_build.py` propose aussi : `python msys2_build.py status`, `compile [--force]` et `install` (instructions MSYS2).

---

## 🧪 Test de détection — fichier EICAR

AEGIS détecte le fichier de test standard EICAR, utilisé universellement pour valider les antivirus.

```bash
aegis generate-test
aegis scan Tests/Malwares_test/
```

**Résultat attendu :**

```
MENACE : EICAR_Test_File → C:\...\Tests\Malwares_test\eicar.com
```

> **Note Windows** : Windows Defender supprime automatiquement EICAR dès sa création — c'est son comportement normal.
> Pour tester AEGIS, ajoutez temporairement `Tests/Malwares_test/` en exclusion dans Windows Sécurité,
> lancez le scan, puis retirez l'exclusion.
>
> Le fichier EICAR n'est **pas** un vrai malware — c'est un standard de test inoffensif défini par l'organisation EICAR.

---

## ⚙ Configuration

Tout se règle dans `config.yaml` :

```yaml
scanner:
  extensions: [".exe", ".dll", ".js", ".pdf", ".com"]           # types analysés
  max_file_size_mb: 100                                         # fichiers plus gros ignorés
  exclude_paths: []                                             # chemins à exclure

database:
  path: "./data/signatures.db"

quarantine:
  dir: "./quarantine"
  encrypt: false

logging:
  level: "INFO"          # DEBUG / INFO / WARNING / ERROR
  file: "./logs/aegis.log"
```

> **Performance** : le walker rejette les fichiers hors extension ou trop volumineux **avant** tout hachage,
> et affiche une progression toutes les 75 fichiers pour que le scan reste lisible sur de gros répertoires.

---

## 📂 Structure du projet

```
AEGIS/
├── aegis/                  # Package principal
│   ├── cli.py              # Interface CLI (Click)
│   ├── logo.py             # Logo console (rich + pyfiglet)
│   ├── scanner/
│   │   ├── engine.py       # ScannerEngine — orchestration du scan
│   │   ├── walker.py       # FileWalker — énumération os.scandir
│   │   └── hasher.py       # HashCalculator Python (fallback)
│   ├── detection/
│   │   ├── signature_matcher.py  # SignatureMatcher (SQLite)
│   │   ├── heuristic.py          # HeuristicAnalyzer (fichiers PE)
│   │   └── yara_scanner.py       # YaraScanner
│   ├── core/
│   │   └── aegis_engine.py       # AegisHasher / AegisBloomMatcher (C++ ⇄ Python)
│   ├── db/signature_db.py        # SignatureDB (SQLite)
│   ├── quarantine/manager.py     # QuarantineManager
│   ├── reporting/generator.py    # ReportGenerator (console / JSON / CSV)
│   ├── updater/updater.py        # Updater (import JSON local / URL)
│   ├── build/                    # builder.py, detector.py, msys2_builder.py, msys2_detector.py
│   ├── config/manager.py         # Config (YAML)
│   ├── logger/logger.py          # Logger rich + fichier
│   └── setup/checker.py          # DependencyChecker
├── cpp/
│   ├── src/aegis_module.cpp      # Module pybind11 (hasher + bloom filter)
│   ├── bin/                      # .pyd + DLL runtime (générés)
│   ├── build/ old_build/         # artefacts CMake (générés)
│   └── CMakeLists.txt
├── data/
│   ├── malwarebazaar_signatures.json  # signatures initiales (≈3200)
│   ├── yara_rules/test_rules.yar      # règles YARA
│   └── signatures.db                  # base SQLite (générée)
├── Tests/
│   ├── Malwares_test/eicar.com        # fichier de test EICAR
│   └── Tests_par_etape/               # validation pas à pas (dev)
├── config.yaml                 # configuration
├── install.py                  # script d'installation
├── msys2_build.py              # build C++ via MSYS2
├── aegis.py / aegis.bat        # points d'entrée
├── pyproject.toml              # métadonnées + dépendances
└── logo.png                    # logo du projet
```

> Les dossiers `__pycache__/`, `aegis_antivirus.egg-info/`, `cpp/build/`, `cpp/old_build/`,
> `cpp/bin/`, `logs/`, `quarantine/`, `reports/`, `data/signatures.db` et les fichiers temporaires
> (`data/tmp_*.json`) sont **générés** et exclus via `.gitignore` : ils se recréent automatiquement.

---

## 🔍 Détection — trois couches

| Couche | Méthode | Rôle |
|--------|---------|------|
| **Signatures** | Hash MD5 / SHA-256 | Lookup Bloom Filter C++ en RAM, puis confirmation SQLite |
| **Heuristique** | Analyse PE | Packing (UPX…), sections RWX, imports suspects, entropie (`.exe`/`.dll` uniquement) |
| **YARA** | Règles de contenu | `data/yara_rules/test_rules.yar` — alerte seulement si sévérité `critical`/`high` |

Un fichier est une **menace** dès qu'une des trois couches le signale ; le nom et la sévérité
de la menace (source signature, YARA ou heuristique) sont reportés dans le log et le rapport.

---

## ⚡ Moteur C++ et performances

Le module `aegis_cpp.pyd` (pybind11) couvre les deux points chauds du scan :

| Fonction | C++ (`aegis_cpp`) | Repli Python |
|----------|-------------------|--------------|
| Hachage MD5 + SHA-256 | OpenSSL EVP, lecture Unicode (`CreateFileW` → accents supportés) | `scanner/hasher.py` |
| Lookup de signatures | Bloom Filter en RAM (9,6 Mo, 7 hachages FNV-1a) puis SQLite | SQLite direct |

- Le chargement est **transparent** : si le `.pyd` est absent, tout bascule en Python pur.
- Compilation : chaîne **MSYS2** recommandée (chemins sans espaces, générateur Ninja),
  secours **MinGW classique** — voir `aegis build status`.

---

# ⚠ Base de signatures — action requise

La base fournie dans ce dépôt est **volontairement légère** (< 3500 signatures) pour des
raisons de taille de dépôt GitHub.

**Un antivirus efficace nécessite des millions de signatures.**
Pour enrichir la base, importez des signatures depuis des sources publiques de threat intelligence :

### Sources recommandées

| Source | Format | Lien |
|--------|--------|------|
| MalwareBazaar | JSON / CSV | https://bazaar.abuse.ch/export/ |
| VirusShare | MD5 hashsets | https://virusshare.com |
| OpenIOC | Indicateurs | https://github.com/fireeye/iocs |

### Procédure d'import

```bash
# 1 — Téléchargez un export depuis MalwareBazaar (JSON ou CSV)
# 2 — Importez dans la base (le format CSV MalwareBazaar est converti automatiquement)

aegis update fetch https://bazaar.abuse.ch/export/md5/signatures.json
aegis update import signatures.json

# Vérifiez le nombre de signatures chargées
aegis update status
```

> **Note** : plus la base est volumineuse, plus le Bloom Filter C++ fait gagner de performance
> sur les lookups. Avec 1 million de signatures, le filtre n'occupe que ~9,6 Mo en RAM.

### Format JSON attendu

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

---

## 🤝 Contribuer

Les retours et pull requests sont les bienvenus.
Ouvrez une issue pour signaler un bug ou proposer une amélioration.

## 📘 Documentation technique

Pour les détails d'architecture, de chaque module, du moteur C++ et du build :
→ [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md)
