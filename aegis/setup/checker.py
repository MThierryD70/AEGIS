import sys
import importlib
import subprocess
from dataclasses import dataclass, field
from typing import List
from aegis.logger.logger import get_logger, log_section, log_blank



# Dépendances obligatoires : (nom_import, nom_pip, version_min)
REQUIRED = [
    ("yaml",            "pyyaml",           "6.0.1"),
    ("click",           "click",            "8.1.7"),
    ("rich",            "rich",             "13.7.0"),
    ("pyfiglet",    "pyfiglet",          "1.0.2"),
    ("pefile",          "pefile",           "2023.2.7"),
    ("httpx",           "httpx",            "0.25.2"),
    ("cryptography",    "cryptography",     "41.0.7"),
    ("pybind11",        "pybind11",         "3.0.0"),
    ("yara",            "yara-python",      "4.3.0"),
]

# Dépendances optionnelles

OPTIONAL = [
    ("fastapi",   "fastapi",   "0.104.1"),
    ("uvicorn",   "uvicorn",   "0.24.0"),
]

@dataclass
class CheckResult:
    package: str
    pip_name: str
    installed: bool
    version: str = ""
    error: str = ""

@dataclass
class SetupReport:
    results: List[CheckResult] = field(default_factory=list)
    installed_count: int = 0
    failed: List[str] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return len(self.failed) == 0

class DependencyChecker:
    def __init__(self):
        self.logger = get_logger()

    def check_python_version(self) -> bool:
        major, minor = sys.version_info[:2]
        if major < 3 or (major == 3 and minor < 10):
            self.logger.error(
                f"Python {major}.{minor} détecté - "
                f"Python 3.10+ requis"
            )
            return False
        self.logger.info(f"Python {major}.{minor} - OK")
        return True

    def _check_package(self, import_name: str, pip_name: str) -> CheckResult:
        try:
            mod = importlib.import_module(import_name)
            version = getattr(mod, "__version__", "inconnue")
            return CheckResult(
                package=import_name,
                pip_name=pip_name,
                installed=True,
                version=version
            )
        except ImportError:
            return CheckResult(
                package=import_name,
                pip_name=pip_name,
                installed=False
            )

    def _install_package(self, pip_name: str) -> bool:
        self.logger.info(f"Installation de {pip_name} ...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name],
                capture_output=True
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Erreur installation {pip_name} : {e}")
            return False

    def check_and_install (
            self,
            packages: list,
            auto_install: bool = True
    ) -> SetupReport:
        report = SetupReport()

        for import_name, pip_name, version_min in packages:
            result = self._check_package(import_name, pip_name)

            if not result.installed:
                if auto_install:
                    success = self._install_package(pip_name)
                    if success:
                        # Vérifier après installation
                        result = self._check_package(import_name, pip_name)
                        result.installed = True
                        report.installed_count +=1
                        self.logger.info(f" OK, {pip_name} installé")
                    else:
                        result.error = "Echec installation"
                        report.failed.append(pip_name)
                        self.logger.error(f"X {pip_name} - echec")
                else:
                    report.failed.append(pip_name)
            else:
                self.logger.info(
                    f" OK {import_name} ({result.version}) - déjà présent"
                )
            report.results.append(result)
        return report
    

    def run_full_check(self, auto_install: bool = True) -> bool:
        log_section("Vérification des dépendances Python")
    
        if not self.check_python_version():
            log_blank()
            return False
    
        self.logger.info("Dépendances obligatoires :")
        report = self.check_and_install(REQUIRED, auto_install)
    
        self.logger.info("Dépendances optionnelles :")
        self.check_and_install(OPTIONAL, auto_install=False)
    
        log_blank()  # ← placé AVANT les return
    
        if report.all_ok:
            self.logger.info(
                f"Toutes les dépendances sont satisfaites "
                f"({report.installed_count} installée(s))"
            )
        else:
            self.logger.error(
                f"Dépendances manquantes : {', '.join(report.failed)}"
            )
    
        log_blank()
        return report.all_ok  # ← un seul return à la fin


    '''def run_full_check(self, auto_install: bool = True) -> bool:
        log_section("Vérification des dépendances Python")

        if not self.check_python_version():
            return False

        self.logger.info("Dépendances obligatoires : ")
        report = self.check_and_install(REQUIRED, auto_install)

        self.logger.info("Dépendances optionelles: ")
        self.check_and_install(OPTIONAL, auto_install=False)

        if report.all_ok:
            self.logger.info(
                f"Toutes les dépendances sont satisfaites "
                f"({report.installed_count} installée (s))"
            )
            return True
        else:
            self.logger.error(
                f"Dépendances manquantes : {', '.join(report.failed)}"
            )
            return False

        log_blank()
        return report.all_ok'''
        




















