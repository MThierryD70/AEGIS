"""
Build des modules C++ AEGIS en utilisant la chaîne d'outils MSYS2.
Hérite de CppBuilder (même flux build/_pyd_exists) mais :
  - détecte les outils exclusivement dans C:\\msys64\\mingw64\\bin ;
  - exécute le cmake fourni par MSYS2 (générateur Ninja) ;
  - injecte le bin MSYS2 dans le PATH du sous-processus.
"""
import subprocess

from aegis.build.builder import CppBuilder
from aegis.build.msys2_detector import Msys2Detector
from aegis.logger.logger import get_logger


class Msys2CppBuilder(CppBuilder):
    """Builder C++ branché sur l'environnement MSYS2."""
    def __init__(self):
        super().__init__()
        self.detector = Msys2Detector()
    def _cmake_executable(self) -> str:
        if self.detector.bin_dir and (
            self.detector.bin_dir / "cmake.exe"
        ).exists():
            return str(self.detector.bin_dir / "cmake.exe")
        return "cmake"
    def _cmake_configure(self, report) -> bool:
        try:
            import pybind11
            pybind11_dir = pybind11.get_cmake_dir()
        except ImportError:
            self.logger.error("pybind11 non installé - pip install pybind11")
            return False
        cmake_args = self.detector.generate_cmake_args(report)
        self.logger.info(f"Générateur CMake : {self.detector.generator}")
        import sys
        cmd = [
            self._cmake_executable(), "..",
            f"-Dpybind11_DIR={pybind11_dir}",
            f"-DPython_EXECUTABLE={sys.executable}",
        ] + cmake_args
        self.logger.info(f"Commande : {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=str(self.build_dir),
            capture_output=True,
            text=True,
            env=self.detector.build_env()
        )
        if result.returncode != 0:
            self.logger.error(f"Erreur CMake :\n{result.stderr}")
            return False
        return True
    def _cmake_build(self) -> bool:
        result = subprocess.run(
            [self._cmake_executable(), "--build", ".", "--config", "Release"],
            cwd=str(self.build_dir),
            capture_output=True,
            text=True,
            env=self.detector.build_env()
        )

        if result.returncode != 0:
            self.logger.error(f"Erreur compilation :\n{result.stderr}")
            return False
        return True

