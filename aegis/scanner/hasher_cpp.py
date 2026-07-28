import os
import ctypes
from pathlib import Path
from aegis.logger.logger import get_logger

# Chemin vers la DLL compilée
_DLL_PATH = Path(__file__).parent.parent.parent / "cpp" / "bin" / "hasher.dll"

# Dossiers où chercher les DLL dépendantes (OpenSSL, MinGW runtime)
_DLL_SEARCH_PATHS = [
    r"C:\Program Files\mingw64\bin",
]


def _load_library():
    if not _DLL_PATH.exists():
        return None
    try:
        # Enregistre les dossiers de recherche avant de charger la DLL
        for dll_dir in _DLL_SEARCH_PATHS:
            if os.path.isdir(dll_dir):
                os.add_dll_directory(dll_dir)

        lib = ctypes.CDLL(str(_DLL_PATH))

        lib.compute_md5.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.compute_md5.restype = ctypes.c_int

        lib.compute_sha256.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.compute_sha256.restype = ctypes.c_int

        get_logger().info("HashCalculator C++ chargé avec succès")
        return lib

    except Exception as e:
        get_logger().warning(f"Impossible de charger hasher.dll : {e}")
        return None

_lib = _load_library()



class HashCalculatorCpp:
    @staticmethod
    def compute(path: Path) -> dict | None:
        logger = get_logger()

        if _lib is None:
            logger.warning("DLL non disponible, fallback Python")
            from aegis.scanner.hasher import HashCalculator
            return HashCalculator.compute(path)

        filepath = str(path).encode("utf-8")

        # Buffer de sortie : 64 caractères pour SHA-256 + null terminator
        md5_output    = ctypes.create_string_buffer(33)
        sha256_output = ctypes.create_string_buffer(65)

        md5_ok    = _lib.compute_md5(filepath, md5_output)
        sha256_ok = _lib.compute_sha256(filepath, sha256_output)

        if not md5_ok or not sha256_ok:
            logger.warning(f"Erreur de lecture C++ pour : {path}")
            return None

        return {
            "md5":    md5_output.value.decode("utf-8"),
            "sha256": sha256_output.value.decode("utf-8")
        }