# AEGIS Antivirus

Antivirus à base de signatures avec moteur C++ haute performance,
développé en Python avec extensions C++ via pybind11.

## Prérequis

- **Python 3.10+** — [télécharger](https://www.python.org/downloads/)
- **g++ et CMake** *(optionnel — pour les performances C++)* — [télécharger](https://github.com/brechtsanders/winlibs_mingw)
- **OpenSSL** *(optionnel — requis avec g++)* — [télécharger](https://slproweb.com/products/Win32OpenSSL.html)

## Installation

```bash
git clone https://github.com/<ton-compte>/aegis.git
cd aegis
python install.py
```

C'est tout. Le script installe les dépendances, compile les modules
C++ si l'environnement le permet, et valide l'installation.

## Commandes disponibles

```bash
# Scanner un fichier ou répertoire
antivirus scan <chemin>
antivirus scan <chemin> --json       # rapport JSON
antivirus scan <chemin> --quarantine # mise en quarantaine auto

# Mettre à jour les signatures
antivirus update import signatures.json
antivirus update status

# Gérer la quarantaine
antivirus quarantine list
antivirus quarantine restore <id>
antivirus quarantine delete <id>

# Compiler les modules C++
antivirus build compile
antivirus build compile --force
antivirus build status

# Vérifier les dépendances Python
antivirus setup
```

## Architecture

```
AEGIS/
├── antivirus/          # Package principal
│   ├── scanner/        # FileWalker, Hasher, Engine
│   ├── detection/      # SignatureMatcher, Heuristic, YARA
│   ├── db/             # SignatureDB (SQLite)
│   ├── quarantine/     # QuarantineManager
│   ├── reporting/      # ReportGenerator (JSON/CSV/Console)
│   ├── updater/        # Updater (import signatures)
│   ├── build/          # Detector, Builder (modules C++)
│   ├── core/           # AegisEngine (C++/Python unifié)
│   └── cli.py          # Interface CLI (Click)
├── cpp/                # Code source C++
│   ├── src/
│   │   └── aegis_module.cpp
│   ├── bin/            # Modules compilés (.pyd + DLL)
│   └── CMakeLists.txt
├── data/               # Base de signatures (SQLite)
├── quarantine/         # Fichiers isolés
├── logs/               # Journaux
├── config.yaml         # Configuration
├── install.py          # Script d'installation
├── TECHNICAL_DOCS.md   # Documentation technique
└── main.py             # Point d'entrée
```

## Performances

| Module | Python pur | C++ (pybind11) | Gain |
|--------|-----------|----------------|------|
| Hasher (SHA-256) | référence | ×4.0 | Sur scan réel |
| Bloom Matcher | référence | ×407 | Sur lookups sains |

## Détection

- **Signatures** — MD5 + SHA-256 contre base SQLite
- **YARA** — règles personnalisables dans `data/yara_rules/`
- **Heuristique** — entropie de Shannon + imports PE suspects

## Contribuer

Les retours et pull requests sont les bienvenus.
Ouvrez une issue pour signaler un bug ou proposer une amélioration.


## Documentation technique

Pour les détails d'architecture, modules, métriques et feuille de route :
→ [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md)
