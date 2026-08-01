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
            for base in self.OPENSSL_SEARCH_PATHS_WIN:
                candidate = Path(base) / "include" / "openssl" / "sha.h"
                if candidate.exists():
                    return str(Path(base) / "include")
        return ""

    def _find_openssl_lib(self) -> str:
        if platform.system() == "Windows":
            # Cherche libssl.lib ou libssl.a
            for base in self.OPENSSL_SEARCH_PATHS_WIN:
                for subpath in [
                    "lib/VC/x64/MD",
                    "lib/VC/x64/MT",
                    "lib",
                    "lib64",
                ]:
                    for libname in ["libssl.lib", "libssl.a"]:
                        candidate = Path(base) / subpath / libname
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
        for path in self.MINGW_SEARCH_PATHS_WIN:
            if Path(path).exists():
                return path
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

    def generate_cmake_args(self, report: EnvReport) -> list:
        """Génère les arguments CMake adaptés à l'environnement détecté."""
        args = ["-G", "MinGW Makefiles", "-DCMAKE_BUILD_TYPE=Release"]

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

        return args









