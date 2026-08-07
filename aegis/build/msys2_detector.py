"""
Détection de l'environnement C++ basé sur MSYS2.

MSYS2 fournit une chaîne d'outils cohérente et précompilée sans espaces
dans les chemins (C:\\msys64\\mingw64\\bin), ce qui évite les problèmes
de gcc/ld rencontrés avec un préfixe contenant des espaces
(C:\\Program Files\\...).

Installation (dans le terminal « MSYS2 MINGW64 ») :
    pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake \
                        mingw-w64-x86_64-openssl

Le paquet mingw-w64-x86_64-cmake tire ninja en dépendance, donc le
générateur CMake « Ninja » est disponible d'office.
"""
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional

from aegis.build.detector import EnvReport, ToolInfo


# Paquets MSYS2 à installer (environnement MINGW64)
MSYS2_PACKAGES = (
    "mingw-w64-x86_64-gcc "
    "mingw-w64-x86_64-cmake "
    "mingw-w64-x86_64-openssl"
)

# Racines MSYS2 candidates (peut être surchargé via AEGIS_MSYS2_ROOT)
MSYS2_ROOTS = [
    Path("C:/msys64"),
    Path("C:/msys2"),
    Path("C:/tools/msys64"),
]

# Environnements MSYS2 possibles, par ordre de préférence
MINGW_ENVS = ["mingw64", "ucrt64", "clang64"]

# Import libs OpenSSL par ordre de préférence pour ld de MinGW
OPENSSL_LIB_NAMES = ["libssl.dll.a", "libssl.a", "libssl.lib"]


class Msys2Detector:
    """Détecte et décrit la chaîne d'outils C++ fournie par MSYS2."""

    def __init__(self, root: Optional[Path] = None):
        self.root = root if root else self._find_msys2_root()
        self.bin_dir = self._find_mingw_bin()
        self.prefix = self.bin_dir.parent if self.bin_dir else None
        self.lib_dir = self.prefix / "lib" if self.prefix else None
        self.include_dir = self.prefix / "include" if self.prefix else None
        self.pacman = (
            self.root / "usr" / "bin" / "pacman.exe" if self.root else None
        )
        self.generator = self._detect_generator()

    # ── Résolution des chemins ──────────────────────────

    def _find_msys2_root(self) -> Optional[Path]:
        env_root = os.environ.get("AEGIS_MSYS2_ROOT")
        candidates = ([Path(env_root)] if env_root else []) + MSYS2_ROOTS
        for root in candidates:
            if (root / "usr" / "bin" / "pacman.exe").exists() or (
                root / "mingw64" / "bin" / "g++.exe"
            ).exists():
                return root
        return None

    def _find_mingw_bin(self) -> Optional[Path]:
        if self.root is None:
            return None
        for env in MINGW_ENVS:
            cand = self.root / env / "bin"
            if (cand / "g++.exe").exists():
                return cand
        return None

    def _detect_generator(self) -> Optional[str]:
        if self.bin_dir is None:
            return None
        if (self.bin_dir / "ninja.exe").exists():
            return "Ninja"
        if (self.bin_dir / "mingw32-make.exe").exists():
            return "MinGW Makefiles"
        return None

    # ── API publique ────────────────────────────────────

    def is_available(self) -> bool:
        """MSYS2 est-il installé avec un environnement MinGW détecté ?"""
        return self.root is not None and self.bin_dir is not None

    def detect(self) -> EnvReport:
        """Produit un EnvReport au même format que le détecteur classique."""
        report = EnvReport()

        if not self.is_available():
            report.tools.append(ToolInfo(
                name="MSYS2", found=False,
                note="introuvable - voir : python msys2_build.py install"
            ))
            return report

        report.tools.append(self._tool_from(self.bin_dir / "g++.exe", "g++"))
        report.tools.append(self._tool_from(self.bin_dir / "gcc.exe", "gcc"))
        report.tools.append(self._tool_from(self.bin_dir / "cmake.exe", "cmake"))
        report.tools.append(self._tool_from(self.bin_dir / "ninja.exe", "ninja"))
        report.tools.append(
            self._tool_from(self.bin_dir / "mingw32-make.exe", "mingw32-make")
        )
        report.tools.append(ToolInfo(
            name="python", found=True, path=sys.executable,
            version=self._get_version(sys.executable)
        ))

        report.mingw_bin = str(self.bin_dir)
        report.openssl_include = self._find_openssl_include()
        report.openssl_lib = self._find_openssl_lib()

        gpp_ok = any(t.name == "g++" and t.found for t in report.tools)
        cmake_ok = any(t.name == "cmake" and t.found for t in report.tools)
        openssl_ok = bool(report.openssl_include and report.openssl_lib)

        report.can_build = (
            gpp_ok and cmake_ok and openssl_ok
            and self.generator is not None
        )
        return report

    def generate_cmake_args(self, report: EnvReport) -> list:
        """Arguments CMake : chemins MSYS2 (aucun espace), générateur
        Ninja si disponible."""
        args = []
        if self.generator:
            args += ["-G", self.generator]
        args.append("-DCMAKE_BUILD_TYPE=Release")

        if report.openssl_include:
            args.append(
                f"-DOPENSSL_INCLUDE_DIR="
                f"{Path(report.openssl_include).as_posix()}"
            )

        if report.openssl_lib:
            lib_dir = Path(report.openssl_lib)
            for name in OPENSSL_LIB_NAMES:
                if (lib_dir / name).exists():
                    args.append(
                        f"-DOPENSSL_SSL_LIBRARY="
                        f"{(lib_dir / name).as_posix()}"
                    )
                    args.append(
                        f"-DOPENSSL_CRYPTO_LIBRARY="
                        f"{(lib_dir / name.replace('ssl', 'crypto')).as_posix()}"
                    )
                    break

        if self.bin_dir:
            for var, exe in [
                ("CMAKE_C_COMPILER", "gcc.exe"),
                ("CMAKE_CXX_COMPILER", "g++.exe"),
            ]:
                p = self.bin_dir / exe
                if p.exists():
                    args.append(f"-D{var}={p.as_posix()}")
            if self.generator == "MinGW Makefiles":
                make = self.bin_dir / "mingw32-make.exe"
                if make.exists():
                    args.append(f"-DCMAKE_MAKE_PROGRAM={make.as_posix()}")

        return args

    def build_env(self) -> dict:
        """Environnement subprocess avec C:\\msys64\\mingw64\\bin en tête
        de PATH (nécessaire pour gcc/ld/ninja et les DLL à l'exécution)."""
        env = dict(os.environ)
        if self.bin_dir:
            env["PATH"] = str(self.bin_dir) + os.pathsep + env.get("PATH", "")
        return env

    # ── Helpers ─────────────────────────────────────────

    def _tool_from(self, exe: Path, name: str) -> ToolInfo:
        if exe.exists():
            return ToolInfo(
                name=name, found=True, path=str(exe),
                version=self._get_version(exe)
            )
        return ToolInfo(
            name=name, found=False,
            note=f"absent de {self.bin_dir}"
        )

    def _get_version(self, exe) -> str:
        try:
            result = subprocess.run(
                [str(exe), "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.split("\n")[0].strip()[:50]
        except Exception:
            return "version inconnue"

    def _find_openssl_include(self) -> str:
        if self.include_dir and (
            self.include_dir / "openssl" / "sha.h"
        ).exists():
            return str(self.include_dir)
        return ""

    def _find_openssl_lib(self) -> str:
        if self.lib_dir is None:
            return ""
        for name in OPENSSL_LIB_NAMES:
            if (self.lib_dir / name).exists():
                return str(self.lib_dir)
        return ""

    # ── Instructions d'installation ─────────────────────

    @staticmethod
    def pacman_command() -> str:
        return f"pacman -S --needed {MSYS2_PACKAGES}"

    @staticmethod
    def path_command() -> str:
        return r'setx PATH "C:\msys64\mingw64\bin;%PATH%"'

    def install_help(self) -> str:
        return "\n".join([
            "1. Installez MSYS2 : https://www.msys2.org",
            "2. Ouvrez le terminal « MSYS2 MINGW64 » et exécutez :",
            f"     {self.pacman_command()}",
            "   (ninja est installé automatiquement avec cmake)",
            "3. Ajoutez le bin MinGW au PATH utilisateur (cmd) :",
            f"     {self.path_command()}",
            "   puis rouvrez un terminal.",
            "",
            "Rappel : C:\\msys64\\mingw64\\bin doit rester dans le PATH,"
            " c'est aussi lui qui fournit les DLL",
            "         (libssl-3-x64.dll, libstdc++-6.dll, ...) requises"
            " au chargement du module .pyd.",
        ])
