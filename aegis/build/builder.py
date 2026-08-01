import subprocess
import shutil
import sys
from pathlib import Path
from aegis.build.detector import EnvironmentDetector, EnvReport
from aegis.logger.logger import get_logger


class CppBuilder:
    def __init__(self):
        self.logger = get_logger()
        self.cpp_dir   = Path(__file__).parent.parent.parent / "cpp"
        self.build_dir = self.cpp_dir / "build"
        self.bin_dir   = self.cpp_dir / "bin"
        self.detector  = EnvironmentDetector()

    def build(self, force_rebuild: bool = False) -> bool:
        self.logger.info("=== Construction des modules C++ ===")

        # Étape 1 — détection environnement
        report = self.detector.detect()
        self.logger.info(report.summary())

        if not report.can_build:
            self.logger.warning(
                "Environnement C++ incomplet - "
                "AEGIS fonctionnera en mode Python pur"
            )
            self._print_missing_tools(report)
            return False

        # Étape 2 — vérifie si déjà compilé
        if not force_rebuild and self._pyd_exists():
            self.logger.info(
                "Module C++ déjà compilé — "
                "utilisez --force pour recompiler"
            )
            return True

        # Étape 3 — prépare le dossier build

        # Force rebuild — supprime seulement le cache CMake
        # pas tout le dossier (évite PermissionError Windows)
        '''if force_rebuild:
            cache = self.build_dir / "CMakeCache.txt"
            if cache.exists():
                cache.unlink()
                self.logger.info("Cache CMake nettoyé")
        
            # Supprime le .pyd existant dans bin/
            for pyd in self.bin_dir.glob("aegis_cpp*.pyd"):
                try:
                    pyd.unlink()
                    self.logger.info(f"Ancien module supprimé : {pyd.name}")
                except PermissionError:
                    self.logger.warning(f"Impossible de supprimer {pyd.name} — ignoré")'''

        if force_rebuild:
            cache = self.build_dir / "CMakeCache.txt"
            if cache.exists():
                cache.unlink()
                self.logger.info("Cache CMake nettoyé")
        
            # Supprime les .pyd dans cpp/bin/ ET cpp/build/
            for search_dir in [self.bin_dir, self.build_dir]:
                if not search_dir.exists():
                    continue
                for pyd in search_dir.glob("aegis_cpp*.pyd"):
                    try:
                        pyd.unlink()
                        self.logger.info(f"Ancien module supprimé : {pyd.name}")
                    except PermissionError:
                        self.logger.warning(
                            f"Impossible de supprimer {pyd.name} — ignoré"
                        )




        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info("Configuration CMake...")
        if not self._cmake_configure(report):
            return False

        self.logger.info("Compilation en cours...")
        if not self._cmake_build():
            return False

        if self._pyd_exists():
            self.logger.info("✓ Module C++ compilé avec succès")
            self._verify_module()
            return True
        else:
            self.logger.error("✗ Fichier .pyd introuvable après compilation")
            return False


        '''if force_rebuild and self.build_dir.exists():
            self.logger.info("Nettoyage du dossier build...")
            shutil.rmtree(str(self.build_dir))
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)

        # Étape 4 — configuration CMake
        self.logger.info("Configuration CMake...")
        if not self._cmake_configure(report):
            return False

        # Étape 5 — compilation
        self.logger.info("Compilation en cours...")
        if not self._cmake_build():
            return False

        # Étape 6 — vérification
        if self._pyd_exists():
            self.logger.info("OK Module C++ compilé avec succès")
            self._verify_module()
            return True
        else:
            self.logger.error("X Fichier .pyd introuvable après compilation")
            return False'''









   
    '''def _pyd_exists(self) -> bool:
        if not self.bin_dir.exists():
            return False
        return any(self.bin_dir.glob("aegis_cpp*.pyd"))'''

    def _pyd_exists(self) -> bool:
        # Vérifie dans cpp/bin/ (emplacement final)
        if self.bin_dir.exists():
            if any(self.bin_dir.glob("aegis_cpp*.pyd")):
                return True

        # Vérifie aussi dans cpp/build/ (emplacement CMake)
        if self.build_dir.exists():
            if any(self.build_dir.glob("aegis_cpp*.pyd")):
                return True

        return False
    




    def _cmake_configure(self, report: EnvReport) -> bool:
        try:
            import pybind11
            pybind11_dir = pybind11.get_cmake_dir()
        except ImportError:
            self.logger.error("pybind11 non installé — pip install pybind11")
            return False

        cmake_args = self.detector.generate_cmake_args(report)
        cmd = [
            "cmake", "..",
            f"-Dpybind11_DIR={pybind11_dir}",
        ] + cmake_args

        self.logger.info(f"Commande : {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            cwd=str(self.build_dir),
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            self.logger.error(f"Erreur CMake :\n{result.stderr}")
            return False

        return True

    def _cmake_build(self) -> bool:
        result = subprocess.run(
            ["cmake", "--build", ".", "--config", "Release"],
            cwd=str(self.build_dir),
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            self.logger.error(f"Erreur compilation :\n{result.stderr}")
            return False

        return True

    def _verify_module(self):
        try:
            sys.path.insert(0, str(self.bin_dir))
            import importlib
            spec = importlib.util.find_spec("aegis_cpp")
            if spec:
                self.logger.info(f"Module vérifié : {spec.origin}")
            else:
                self.logger.warning("Module compilé mais non importable")
        except Exception as e:
            self.logger.warning(f"Vérification module : {e}")

    def _print_missing_tools(self, report: EnvReport):
        missing = [t for t in report.tools if not t.found]
        if missing:
            self.logger.warning("Outils manquants :")
            for tool in missing:
                self.logger.warning(f"  ✗ {tool.name} — {tool.note}")

        if not report.openssl_include or not report.openssl_lib:
            self.logger.warning(
                "  ✗ OpenSSL — installez OpenSSL et ajoutez-le au PATH"
            )

        self.logger.info(
            "\nPour installer les outils manquants :\n"
            "  g++/CMake : https://github.com/brechtsanders/winlibs_mingw\n"
            "  OpenSSL   : https://slproweb.com/products/Win32OpenSSL.html\n"
            "  Puis relancez : antivirus build"
        )

    def rebuild(self) -> bool:
        return self.build(force_rebuild=True)








