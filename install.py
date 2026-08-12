"""
AEGIS Antivirus - Script d'installation universel
Usage : python install.py
"""
import sys
import subprocess
import importlib
from pathlib import Path


def print_header():
    print("""
╔══════════════════════════════════════════════════════╗
║           AEGIS Antivirus - Installation             ║
║      Antivirus à base de signatures Python/C++       ║
╚══════════════════════════════════════════════════════╝
""")

def check_python_version() -> bool:
    major, minor = sys.version_info[:2]
    print(f"[1/5] Vérification Python... {major}.{minor}", end=" ")
    if major < 3 or (major == 3 and minor < 10):
        print("✗")
        print(f"      Python 3.10+ requis, vous avez {major}.{minor}")
        print("      Téléchargez : https://www.python.org/downloads/")
        return False
    print("✓")
    return True

def install_rich() -> bool:
    print("[2/5] Vérification de rich...", end=" ")
    try:
        importlib.import_module("rich")
        print("✓ déjà installé")
        return True
    except ImportError:
        print("installation...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "rich>=13.7.0"],
                capture_output=True,
                check=True
            )
            print("      ✓ rich installé")
            return True
        except subprocess.CalledProcessError:
            print("      X Échec installation rich")
            return False

def install_dependencies() -> bool:
    print("[3/5] Installation des dépendances Python...")
    import subprocess, sys

    # Dépendances critiques installées d'abord
    critical = [
        "click>=8.1.7",
        "rich>=13.7.0",
        "pyyaml>=6.0.1",
        "pyfiglet>=1.0.2",
        "httpx>=0.25.2",
        "cryptography>=41.0.7",
        "pybind11>=3.0.0",
        "pefile>=2023.2.7",
    ]

    # python-magic selon l'OS
    import platform
    if platform.system() == "Windows":
        critical.append("python-magic-bin>=0.4.14")
    else:
        critical.append("python-magic>=0.4.27")

    # yara-python - optionnel car peut échouer sans compilateur
    optional = ["yara-python>=4.3.0"]

    all_ok = True
    for pkg in critical:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"      ✓ {pkg.split('>=')[0]}")
        else:
            print(f"      ✗ {pkg.split('>=')[0]} — échec")
            all_ok = False

    for pkg in optional:
        name = pkg.split(">=")[0]
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"      ✓ {name}")
        else:
            print(f"      ⚠ {name} — échec de l'installation (optionnel, ignoré)")
            _explain_optional_failure(name, result.stderr)

    # Installe le projet lui-même en mode editable
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", ".",
         "--no-deps"],  # --no-deps car déjà installées ci-dessus
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"      ✗ Installation du projet échouée")
        all_ok = False

    return all_ok

def _explain_optional_failure(name: str, stderr: str) -> None:
    """Explique pourquoi un package optionnel n'a pas pu être installé et
    quoi faire pour y remédier (ex. compilateur manquant pour yara-python)."""
    if name != "yara-python":
        print("        Voir le détail de l'erreur affiché par pip ci-dessus.")
        return

    print("")
    print("        « yara-python » doit être compilé sur place et un composant")
    print("        externe est manquant sur cette machine :")

    if "Microsoft Visual C++ 14.0" in stderr or "C++ Build Tools" in stderr:
        print("")
        print("          → Windows : il manque le compilateur C/C++ de Microsoft.")
        print("            Installez « Microsoft C++ Build Tools » :")
        print("              https://visualstudio.microsoft.com/visual-cpp-build-tools/")
        print("            (cochez la charge de travail « Développement Desktop en C++ »)")
    else:
        print("")
        print("          → Linux : il manque le SDK YARA.")
        print("            Installez-le :  sudo apt install libyara-dev")

    print("")
    print("          Puis relancez :  python install.py")
    print("          (ou directement :  python -m pip install yara-python)")
    print("")
    print("        Sans yara-python, la détection par règles YARA est désactivée,")
    print("        mais le reste d'AEGIS fonctionne normalement.")


def build_cpp_modules() -> bool:
    print("[4/5] Compilation des modules C++...")
    try:
        # Import différé — dépendances déjà installées à ce stade
        from aegis.config.manager import Config
        from aegis.logger.logger import setup_logger
        from aegis.build.msys2_detector import Msys2Detector
        from aegis.build.msys2_builder import Msys2CppBuilder
        from aegis.build.builder import CppBuilder

        # Setup logger minimal pour le builder
        config = Config.from_yaml("config.yaml")
        setup_logger(config)

        # MSYS2 préféré (chemins sans espaces) — secours classique
        msys2 = Msys2Detector()
        if msys2.is_available():
            builder = Msys2CppBuilder()
        else:
            builder = CppBuilder()

        success = builder.build(force_rebuild=False)

        if success:
            print("      ✓ Modules C++ compilés — performances maximales")
            return True
        else:
            print("      ⚠ Modules C++ non disponibles")
            print("        AEGIS fonctionnera en mode Python pur")
            print("        Pour activer C++ plus tard :")
            if msys2.is_available():
                print("        1. Réinstallez les paquets dans « MSYS2 MINGW64 » :")
                print(f"           {msys2.pacman_command()}")
                print("        2. Lancez : aegis build compile")
            else:
                print("        1. Installez MSYS2 (https://www.msys2.org)")
                print("        2. Dans « MSYS2 MINGW64 » :")
                print(f"           {msys2.pacman_command()}")
                print(f"        3. Dans cmd : {msys2.path_command()}")
                print("        4. Lancez : aegis build compile")
            return False

    except Exception as e:
        print(f"      ⚠ Compilation ignorée : {e}")
        return False


def run_validation() -> bool:
    print("[5/5] Validation de l'installation...")
    try:
        from aegis.config.manager import Config
        from aegis.logger.logger import setup_logger
        from aegis.db.signature_db import SignatureDB
        from aegis.scanner.hasher import HashCalculator
        from pathlib import Path as P

        config = Config.from_yaml("config.yaml")
        setup_logger(config)

        # Vérifie la base de données
        db = SignatureDB(config.database.path)
        count = db.count()
        print(f"      ✓ Base de signatures : {count} entrée(s)")

        # Vérifie le hasher
        test_file = P("config.yaml")
        hashes = HashCalculator.compute(test_file)
        if hashes and hashes.get("sha256"):
            print(f"      ✓ Hasher opérationnel")
        else:
            print(f"      X Hasher défaillant")
            return False

        # Vérifie la CLI
        result = subprocess.run(
            [sys.executable, "aegis.py", "--help"],
            capture_output=True,
            text=True
        )
 

        if result.returncode == 0:
            print(f"      ✓ CLI opérationnelle")
        else:
            print(f"      ✗ CLI défaillante")
            return False

        return True

    except Exception as e:
        print(f"      ✗ Erreur validation : {e}")
        return False


def print_summary(steps: dict):
    print("""
╔══════════════════════════════════════════════════════╗
║                  Résumé installation                 ║
╠══════════════════════════════════════════════════════╣""")

    labels = {
        "python":  "Python 3.10+",
        "rich":    "Bibliothèque rich",
        "deps":    "Dépendances Python",
        "cpp":     "Modules C++ (optionnel)",
        "valid":   "Validation finale",
    }

    all_critical_ok = all([
        steps["python"],
        steps["rich"],
        steps["deps"],
        steps["valid"],
    ])

    for key, label in labels.items():
        status = "✓" if steps[key] else ("⚠" if key == "cpp" else "✗")
        print(f"║  {status} {label:<45}║")

    print("╠══════════════════════════════════════════════════════╣")

    if all_critical_ok:
        print("║  ✓ AEGIS est prêt à l'emploi !                       ║")
        print("║                                                      ║")
        print("║  Commandes disponibles :                             ║")
        print("║    aegis scan <chemin>                               ║")
        print("║    aegis update import <fichier.json>                ║")
        print("║    aegis quarantine list                             ║")
        print("║    aegis build compile                               ║")
        print("║    aegis --help                                      ║")
        print("║                                                      ║")
        print("║  Alternative : python aegis.py <commande>            ║")

    else:
        print("║  ✗ Installation incomplète — voir erreurs ci-dessus  ║")

    print("╚══════════════════════════════════════════════════════╝")


def import_initial_signatures() -> bool:
    print("[+] Import des signatures initiales...")
    sample = Path("data/malwarebazaar_signatures.json")
    if not sample.exists():
        print("      ⚠ Aucun fichier de signatures trouvé")
        return True  # non bloquant

    try:
        from aegis.config.manager import Config
        from aegis.logger.logger import setup_logger
        from aegis.updater.updater import Updater

        config = Config.from_yaml("config.yaml")
        setup_logger(config)
        updater = Updater(config)
        result = updater.import_from_file(str(sample))
        print(f"      ✓ {result['added']} signature(s) importée(s)")
        return True
    except Exception as e:
        print(f"      ⚠ Import ignoré : {e}")
        return True  # non bloquant


def main():
    print_header()

    steps = {
        "python": False,
        "rich":   False,
        "deps":   False,
        "cpp":    False,
        "valid":  False,
    }

    # Étape 1 - Python
    steps["python"] = check_python_version()
    if not steps["python"]:
        print_summary(steps)
        sys.exit(1)

    # Étape 2 - rich (bootstrap)
    steps["rich"] = install_rich()
    if not steps["rich"]:
        print_summary(steps)
        sys.exit(1)

    # Étape 3 - dépendances
    steps["deps"] = install_dependencies()
    if not steps["deps"]:
        print_summary(steps)
        sys.exit(1)

    # Étape 4 - modules C++ (optionnel — pas de sys.exit si échec)
    steps["cpp"] = build_cpp_modules()

    # Étape 5 - Import des signatures initales
    import_initial_signatures()

    # Étape 6 - validation
    steps["valid"] = run_validation()

    print_summary(steps)
    sys.exit(0 if steps["valid"] else 1)


if __name__ == "__main__":
    import subprocess
    main()