import os
import sys
import shutil
import subprocess
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List


@dataclass
class ToolInfo:
    name: str
    found: bool
    path: str = ""
    version: str = ""
    note: str = ""


@dataclass
class EnvReport:
    tools: List[ToolInfo] = field(default_factory=list)
    openssl_include: str = ""
    openssl_lib: str = ""
    mingw_bin: str = ""
    can_build: bool = False

    def summary(self) -> str:
        lines = ["\n=== Environnement C++ ==="]
        for tool in self.tools:
            status = "OK" if tool.found else "X"
            detail = f"{tool.path} ({tool.version})" if tool.found else tool.note
            lines.append(f"  {status} {tool.name:12} {detail}")
        lines.append(f"\n  OpenSSL include : {self.openssl_include or 'non trouvé'}")
        lines.append(f"  OpenSSL lib     : {self.openssl_lib or 'non trouvé'}")
        lines.append(f"  MinGW bin       : {self.mingw_bin or 'non trouvé'}")
        lines.append(
            f"\n  Compilation C++ : "
            f"{'possible' if self.can_build else 'impossible'}"
        )
        return "\n".join(lines)


class EnvironmentDetector:

    # Emplacements standards OpenSSL sur Windows
    OPENSSL_SEARCH_PATHS_WIN = [
        "C:/Program Files/OpenSSL-Win64",
        "C:/Program Files/OpenSSL",
        "C:/OpenSSL-Win64",
        "C:/OpenSSL",
        "C:/Program Files/mingw64",
    ]

    # Emplacements standards MinGW sur Windows
    MINGW_SEARCH_PATHS_WIN = [
        r"C:\Program Files\mingw64\bin",
        r"C:\mingw64\bin",
        r"C:\MinGW/bin",
        r"C:\msys64\mingw64\bin",
    ]

    def detect(self) -> EnvReport:
        report = EnvReport()
        report.tools.append(self._check_tool("g++",   ["g++", "c++"]))
        report.tools.append(self._check_tool("cmake", ["cmake"]))
        report.tools.append(self._check_tool("python", [sys.executable]))

        report.openssl_include = self._find_openssl_include()
        report.openssl_lib     = self._find_openssl_lib()
        report.mingw_bin       = self._find_mingw_bin()

        gpp_ok    = any(t.name == "g++"   and t.found for t in report.tools)
        cmake_ok  = any(t.name == "cmake" and t.found for t in report.tools)
        openssl_ok = bool(report.openssl_include and report.openssl_lib)

        report.can_build = gpp_ok and cmake_ok and openssl_ok
        return report

    def _check_tool(self, name: str, commands: list) -> ToolInfo:
        for cmd in commands:
            path = shutil.which(cmd)
            if path:
                version = self._get_version(cmd)
                return ToolInfo(
                    name=name, found=True,
                    path=path, version=version
                )
        return ToolInfo(
            name=name, found=False,
            note=f"introuvable dans PATH"
        )

    def _get_version(self, cmd: str) -> str:
        try:
            result = subprocess.run(
                [cmd, "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.split("\n")[0].strip()[:50]
        except Exception:
            return "version inconnue"

    def _find_openssl_include(self) -> str:
        # Cherche dans PATH d'abord
        for base in self._get_search_paths():
            candidate = Path(base) / "include" / "openssl" / "sha.h"
            if candidate.exists():
                return str(Path(base) / "include")

        # Cherche dans les emplacements standards Windows
        if platform.system() == "Windows":
            bases = [
                b for b in self.OPENSSL_SEARCH_PATHS_WIN
                if Path(b).exists()
            ]
            # Priorise les chemins sans espaces
            bases.sort(key=lambda b: " " in b)
            for base in bases:
                candidate = Path(base) / "include" / "openssl" / "sha.h"
                if candidate.exists():
                    return str(Path(base) / "include")
        return ""

    def _find_openssl_lib(self) -> str:
        if platform.system() == "Windows":
            bases = [
                b for b in self.OPENSSL_SEARCH_PATHS_WIN
                if Path(b).exists()
            ]
            # Priorise les chemins sans espaces
            bases.sort(key=lambda b: " " in b)

            # Import libs MinGW en priorité : ld de MinGW ne gère pas
            # toujours les .lib compilés pour MSVC
            for base in bases:
                for subpath in ["lib", "lib64",
                                "lib/VC/x64/MD", "lib/VC/x64/MT"]:
                    for libname in ["libssl.dll.a", "libssl.a"]:
                        candidate = Path(base) / subpath / libname
                        if candidate.exists():
                            return str(Path(base) / subpath)

            # Dernier recours : import libs MSVC (.lib)
            for base in bases:
                for subpath in ["lib/VC/x64/MD", "lib/VC/x64/MT",
                                "lib", "lib64"]:
                    candidate = Path(base) / subpath / "libssl.lib"
                    if candidate.exists():
                        return str(Path(base) / subpath)
        else:
            # Linux / Mac
            for path in ["/usr/lib", "/usr/local/lib",
                         "/opt/homebrew/lib"]:
                if Path(path).glob("libssl*"):
                    return path
        return ""

    def _find_mingw_bin(self) -> str:
        if platform.system() != "Windows":
            return ""

        # Priorise les chemins sans espaces : gcc/MinGW gère mal un
        # préfixe d'installation contenant des espaces
        existing = [
            p for p in self.MINGW_SEARCH_PATHS_WIN if Path(p).exists()
        ]
        existing.sort(key=lambda p: " " in p)
        if existing:
            return existing[0]

        # Cherche g++ dans PATH et remonte vers bin/
        gpp = shutil.which("g++")
        if gpp:
            return str(Path(gpp).parent)
        return ""

    def _get_search_paths(self) -> list:
        paths = []
        gpp = shutil.which("g++")
        if gpp:
            # Remonte de bin/g++ vers la racine
            paths.append(str(Path(gpp).parent.parent))
        return paths

    '''def generate_cmake_args(self, report: EnvReport) -> list:
        """Génère les arguments CMake adaptés à l'environnement détecté."""
        args = ["-G", "MinGW Makefiles", "-DCMAKE_BUILD_TYPE=Release"]
        #args = ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release"]

        if report.openssl_include:
            args += [f"-DOPENSSL_INCLUDE_DIR={report.openssl_include}"]

        if report.openssl_lib:
            # Cherche les fichiers .lib ou .a
            lib_path = Path(report.openssl_lib)
            for name in ["libssl.lib", "libssl.a"]:
                if (lib_path / name).exists():
                    ssl_lib  = str(lib_path / name)
                    crypto_name = name.replace("ssl", "crypto")
                    crypto_lib  = str(lib_path / crypto_name)
                    args += [
                        f"-DOPENSSL_SSL_LIBRARY={ssl_lib}",
                        f"-DOPENSSL_CRYPTO_LIBRARY={crypto_lib}",
                    ]
                    break

        return args'''
    
    def _to_short_path(self, path: str) -> str:
        """Convertit un chemin Windows en version courte (8.3) sans espaces."""
        import platform
        if platform.system() != "Windows" or " " not in path:
            return path
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(260)
            result = ctypes.windll.kernel32.GetShortPathNameW(path, buf, 260)
            # Ne renvoie le résultat que s'il est réellement sans espace
            # (les noms courts 8.3 peuvent être désactivés sur le volume)
            if result and " " not in buf.value:
                return buf.value
        except Exception:
            pass
        return path  # fallback si la conversion échoue
    

    def generate_cmake_args(self, report: EnvReport) -> list:
        """
        Génère les arguments CMake adaptés à l'environnement.
        Essaie MinGW Makefiles en premier, Ninja en fallback.
        """
        import platform

        # Choix du générateur selon l'OS
        if platform.system() == "Windows":
            generator = self._find_best_generator()
        else:
            generator = "Unix Makefiles"

        args = ["-G", generator, "-DCMAKE_BUILD_TYPE=Release"]

        if report.openssl_include:
            include_path = self._to_short_path(report.openssl_include)
            args += [f"-DOPENSSL_INCLUDE_DIR={include_path}"]

        if report.openssl_lib:
            lib_path = Path(self._to_short_path(report.openssl_lib))
            # Import libs MinGW (.dll.a / .a) en priorité, puis .lib MSVC
            for name in ["libssl.dll.a", "libssl.a", "libssl.lib"]:
                if (lib_path / name).exists():
                    ssl_lib    = str(lib_path / name).replace("\\", "/")
                    crypto_lib = str(lib_path / name.replace("ssl", "crypto")).replace("\\", "/")
                    args += [
                        f"-DOPENSSL_SSL_LIBRARY={ssl_lib}",
                        f"-DOPENSSL_CRYPTO_LIBRARY={crypto_lib}",
                    ]
                    break

        # Compilateurs et make : chemins courts pour éviter les espaces.
        # Empêche CMake d'enregistrer des chemins longs avec espaces
        # dans le CMakeCache (C:/Program Files/mingw64/...).
        if platform.system() == "Windows" and report.mingw_bin:
            mingw_bin = self._to_short_path(report.mingw_bin)
            gcc = Path(mingw_bin) / "gcc.exe"
            gpp = Path(mingw_bin) / "g++.exe"
            if gcc.exists():
                args.append(f"-DCMAKE_C_COMPILER={str(gcc).replace('\\', '/')}")
            if gpp.exists():
                args.append(f"-DCMAKE_CXX_COMPILER={str(gpp).replace('\\', '/')}")
            if generator == "MinGW Makefiles":
                make = Path(mingw_bin) / "mingw32-make.exe"
                if make.exists():
                    args.append(
                        f"-DCMAKE_MAKE_PROGRAM={str(make).replace('\\', '/')}"
                    )

        return args

        
    def _find_best_generator(self) -> str:
        """
        Détecte le meilleur générateur CMake disponible sur Windows.
        Priorité : MinGW Makefiles > Ninja > NMake Makefiles
        """
        import subprocess
        import shutil
    
        # Vérifie si mingw32-make est disponible
        mingw_make = shutil.which("mingw32-make")
        if mingw_make:
            # Vérifie que mingw32-make fonctionne réellement
            try:
                result = subprocess.run(
                    ["mingw32-make", "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return "MinGW Makefiles"
            except Exception:
                pass
    
        # Fallback Ninja
        ninja = shutil.which("ninja")
        if ninja:
            return "Ninja"
    
        # Dernier recours
        return "MinGW Makefiles"

    









