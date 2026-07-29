import os
import ctypes
from pathlib import Path
from aegis.db.signature_db import SignatureDB
from aegis.detection.signature_matcher import SignatureMatcher, MatchResult
from aegis.logger.logger import get_logger


_DLL_PATH = Path(__file__).parent.parent.parent / "cpp" / "bin" / "bloom_matcher.dll"
_DLL_SEARCH_PATHS = [r"C:\Program Files\mingw64\bin"]

def _load_library():
    if not _DLL_PATH.exists():
        return None
    try:
        for dll_dir in _DLL_SEARCH_PATHS:
            if os.path.isdir(dll_dir):
                os.add_dll_directory(dll_dir)

        lib = ctypes.CDLL(str(_DLL_PATH))

        lib.bloom_init.argtypes = []
        lib.bloom_init.restype = None

        lib.bloom_add.argtypes = [ctypes.c_char_p]
        lib.bloom_add.restype = None

        lib.bloom_check.argtypes = [ctypes.c_char_p]
        lib.bloom_check.restype = ctypes.c_int

        lib.bloom_count_set_bits.argtypes = []
        lib.bloom_count_set_bits.restype = ctypes.c_int

        return lib
    except Exception as e:
        get_logger().warning(f"Impossible de charger bloom_matcher.dll : {e}")
        return None

_lib = _load_library()

class BloomMatcher:
    def __init__(self, db: SignatureDB):
        self.db = db
        self.logger = get_logger()
        self._fallback = SignatureMatcher(db)
        self._use_cpp = _lib is not None
        self._loaded = False

        if self._use_cpp:
            self._load_bloom()
        else:
            self.logger.warning("Bloom Filter C++ non disponible, fallback Python")

    def _load_bloom(self):
        _lib.bloom_init()
        hashes = self.db.get_all_hashes()
        for h in hashes:
            _lib.bloom_add(h.encode("utf-8"))
        self._loaded = True
        bits = _lib.bloom_count_set_bits()
        self.logger.info(
            f"Bloom Filter chargé: {len(hashes)} signature (s), "
            f"{bits} bits actifs"
        )



    def check(self, hashes: dict) -> MatchResult:
        if not self._use_cpp or not self._loaded:
            return self._fallback.check(hashes)

        for hash_type, hash_value in hashes.items():
            # Etape 1: Bloom Filter en RAM (nanosecondes)
            maybe_present = _lib.bloom_check(hash_value.encode("utf-8"))

            if maybe_present:
                # Etape 2: confirmation SQLite (seulement si nécessaire)
                result = self.db.lookup(hash_value)
                if result is not None:
                    self.logger.warning(
                        f"Signature trouvée : {result['malware_name']} "
                        f"({hash_type}: {hash_value[:16]}...)"
                    )
                    return MatchResult(
                        is_threat=True,
                        malware_name=result["malware_name"],
                        severity=result["severity"],
                        matched_hash=hash_value,
                        hash_type=hash_type
                    )
        return MatchResult(is_threat=False)
        













